#ifndef OPENSSL_NO_QUIC

#include "quic/buffer.h"
#include "quic/crypto.h"
#include "quic/endpoint.h"
#include "quic/quic.h"
#include "quic/qlog.h"
#include "quic/session.h"
#include "quic/stream.h"
#include "crypto/crypto_util.h"
#include "aliased_struct-inl.h"
#include "allocated_buffer-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_mem-inl.h"
#include "node_sockaddr-inl.h"
#include "req_wrap-inl.h"
#include "v8.h"

#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/evp.h>

namespace node {

using v8::Context;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::PropertyAttribute;
using v8::Value;

namespace quic {

namespace {
ngtcp2_crypto_aead CryptoAeadAes128GCM() {
  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_init(&aead, const_cast<EVP_CIPHER *>(EVP_aes_128_gcm()));
  return aead;
}

ngtcp2_crypto_md CryptoMDSha256() {
  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));
  return md;
}

// The reserved version is a mechanism QUIC endpoints
// can use to ensure correct handling of version
// negotiation. It is defined by the QUIC spec in
// https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-6.3
// Specifically, any version that follows the pattern
// 0x?a?a?a?a may be used to force version negotiation.
inline uint32_t GenerateReservedVersion(
    const SocketAddress& addr,
    uint32_t version) {
  socklen_t addrlen = addr.length();
  uint32_t h = 0x811C9DC5u;
  const uint8_t* p = addr.raw();
  const uint8_t* ep = p + addrlen;
  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }
  version = htonl(version);
  p =  reinterpret_cast<const uint8_t*>(&version);
  ep = p + sizeof(version);
  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }
  h &= 0xf0f0f0f0u;
  h |= 0x0a0a0a0au;
  return h;
}

bool IsShortHeader(uint32_t version, const uint8_t* pscid, size_t pscidlen) {
  return version == NGTCP2_PROTO_VER_MAX &&
         pscid == nullptr &&
         pscidlen == 0;
}
}  // namespace

Local<FunctionTemplate> SendWrap::GetConstructorTemplate(
    Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  CHECK_NOT_NULL(state);
  Local<FunctionTemplate> tmpl = state->send_wrap_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->Inherit(UdpSendWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        SendWrap::kInternalFieldCount);
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicSendWrap"));
    state->set_send_wrap_constructor_template(env, tmpl);
  }
  return tmpl;
}

SendWrap* SendWrap::Create(Environment* env, size_t length) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return nullptr;
  }

  return new SendWrap(env, obj, length);
}

SendWrap::SendWrap(
    Environment* env,
    v8::Local<v8::Object> object,
    size_t length)
    : UdpSendWrap(env, object, AsyncWrap::PROVIDER_QUICSENDWRAP),
      length_(length) {}

void SendWrap::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("session", session_);
  tracker->TrackField("packet", packet_);
}

Local<FunctionTemplate> Endpoint::GetConstructorTemplate(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  CHECK_NOT_NULL(state);
  Local<FunctionTemplate> tmpl = state->endpoint_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicEndpoint"));
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Endpoint::kInternalFieldCount);
    state->set_endpoint_constructor_template(env, tmpl);
  }
  return tmpl;
}

void Endpoint::Initialize(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_endpoint_constructor_template(env, GetConstructorTemplate(env));
}

BaseObjectPtr<Endpoint> Endpoint::Create(
    Environment* env,
    Local<Object> udp_wrap,
    const Config& config) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(env);
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Endpoint>();

  return MakeBaseObject<Endpoint>(env, obj, udp_wrap, config);
}

Endpoint::Endpoint(
    Environment* env,
    Local<Object> object,
    Local<Object> udp_wrap,
    const Config& config)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUICENDPOINT),
      EndpointStatsBase(env, object),
      config_(config),
      state_(env),
      block_list_(SocketAddressBlockListWrap::New(env)),
      token_aead_(CryptoAeadAes128GCM()),
      token_md_(CryptoMDSha256()),
      addrLRU_(config.address_lru_size) {
  MakeWeak();

  Debug(this, "New QUIC endpoint created");

  udp_ = static_cast<UDPWrapBase*>(
      udp_wrap->GetAlignedPointerFromInternalField(
          UDPWrapBase::kUDPWrapBaseField));
  CHECK_NOT_NULL(udp_);
  udp_->set_listener(this);
  udp_strong_ptr_.reset(udp_->GetAsyncWrap());

  if (config_.disable_stateless_reset)
    state_->stateless_reset_disabled = 1;

  crypto::EntropySource(
      reinterpret_cast<unsigned char*>(token_secret_),
      kTokenSecretLen);

  object->DefineOwnProperty(
      env->context(),
      env->block_list_string(),
      block_list_->object(),
      PropertyAttribute::ReadOnly).Check();

  object->DefineOwnProperty(
      env->context(),
      env->state_string(),
      state_.GetArrayBuffer(),
      PropertyAttribute::ReadOnly).Check();
}

Endpoint::~Endpoint() {
  udp_->set_listener(nullptr);
  CHECK_EQ(sessions_.size(), 0);
  Debug(this, "Destroying");
  DebugStats();
}

void Endpoint::OnEndpointDone() {
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  MakeCallback(env()->ondone_string(), 0, nullptr);
}

void Endpoint::OnError(ssize_t status) {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  Local<Value> arg = Number::New(env()->isolate(), static_cast<double>(status));
  MakeCallback(state->endpoint_error_callback(env()), 1, &arg);
}

void Endpoint::OnSessionReady(BaseObjectPtr<Session> session) {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  Local<Value> arg = session->object();
  Context::Scope context_scope(env()->context());
  MakeCallback(state->session_ready_callback(env()), 1, &arg);
}

void Endpoint::OnServerBusy() {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  Context::Scope context_scope(env()->context());
  MakeCallback(state->endpoint_busy_callback(env()), 0, nullptr);
}

void Endpoint::OnReceive(
    ssize_t nread,
    AllocatedBuffer buf,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    unsigned int flags) {
  Debug(this, "Receiving %d bytes from the UDP socket", nread);

  // When diagnostic packet loss is enabled, the packet will be randomly
  // dropped based on the rx_loss_ probability.
  if (UNLIKELY(is_diagnostic_packet_loss(config_.rx_loss))) {
    Debug(this, "Simulating received packet loss");
    return;
  }

  if (UNLIKELY(block_list_->Apply(remote_addr))) {
    Debug(this, "Ignoring blocked remote address: %s", remote_addr);
    IncrementStat(&EndpointStats::packets_ignored);
    return;
  }

  IncrementStat(&EndpointStats::bytes_received, nread);

  const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.data());

  uint32_t pversion;
  const uint8_t* pdcid;
  size_t pdcidlen;
  const uint8_t* pscid;
  size_t pscidlen;

  // This is our first check to see if the received data can be
  // processed as a QUIC packet. If this fails, then the QUIC packet
  // header is invalid and cannot be processed; all we can do is ignore
  // it. It's questionable whether we should even increment the
  // packets_ignored statistic here but for now we do. If it succeeds,
  // we have a valid QUIC header but there's still no guarantee that
  // the packet can be successfully processed.
  if (ngtcp2_pkt_decode_version_cid(
        &pversion,
        &pdcid,
        &pdcidlen,
        &pscid,
        &pscidlen,
        data,
        nread,
        NGTCP2_MAX_CIDLEN) < 0) {
    IncrementStat(&EndpointStats::packets_ignored);
    return;
  }

  // QUIC currently requires CID lengths of max NGTCP2_MAX_CIDLEN. The
  // ngtcp2 API allows non-standard lengths, and we may want to allow
  // non-standard lengths later. But for now, we're going to ignore any
  // packet with a non-standard CID length.
  if (pdcidlen > NGTCP2_MAX_CIDLEN || pscidlen > NGTCP2_MAX_CIDLEN) {
    IncrementStat(&EndpointStats::packets_ignored);
    return;
  }

  CID dcid(pdcid, pdcidlen);
  CID scid(pscid, pscidlen);

  Debug(this, "Received a QUIC packet for dcid %s", dcid);

  BaseObjectPtr<Session> session = FindSession(dcid);

  // If a session is not found, there are four possible reasons:
  // 1. The session has not been created yet
  // 2. The session existed once but we've lost the local state for it
  // 3. The packet is a stateless reset sent by the peer
  // 4. This is a malicious or malformed packet.
  if (!session) {
    Debug(this, "There is no existing session for dcid %s", dcid);
    bool is_short_header = IsShortHeader(pversion, pscid, pscidlen);

    // Handle possible reception of a stateless reset token...
    // If it is a stateless reset, the packet will be handled with
    // no additional action necessary here. We want to return immediately
    // without committing any further resources.
    if (is_short_header &&
        MaybeStatelessReset(
            dcid,
            scid,
            nread,
            data,
            local_addr,
            remote_addr,
            flags)) {
      Debug(this, "Handled stateless reset");
      return;
    }

    // AcceptInitialPacket will first validate that the packet can be
    // accepted, then create a new server session instance if able
    // to do so. If a new instance cannot be created (for any reason),
    // the session BaseObjectPtr will be empty on return.
    session = AcceptInitialPacket(
        pversion,
        dcid,
        scid,
        nread,
        data,
        local_addr,
        remote_addr,
        flags);

    // There are many reasons why a server session could not be
    // created. The most common will be invalid packets or incorrect
    // QUIC version. In any of these cases, however, to prevent a
    // potential attacker from causing us to consume resources,
    // we're just going to ignore the packet. It is possible that
    // the AcceptInitialPacket sent a version negotiation packet,
    // or a CONNECTION_CLOSE packet.
    if (!session) {
      Debug(this, "Unable to create a new server session");
      // If the packet contained a short header, we might need to send
      // a stateless reset. The stateless reset contains a token derived
      // from the received destination connection ID.
      //
      // Stateless resets are generated programmatically using HKDF with
      // the sender provided dcid and a locally provided secret as input.
      // It is entirely possible that a malicious peer could send multiple
      // stateless reset eliciting packets with the specific intent of using
      // the returned stateless reset to guess the stateless reset token
      // secret used by the server. Once guessed, the malicious peer could use
      // that secret as a DOS vector against other peers. We currently
      // implement some mitigations for this by limiting the number
      // of stateless resets that can be sent to a specific remote
      // address but there are other possible mitigations, such as
      // including the remote address as input in the generation of
      // the stateless token.
      if (is_short_header &&
          SendStatelessReset(dcid, local_addr, remote_addr, nread)) {
        Debug(this, "Sent stateless reset");
        IncrementStat(&EndpointStats::stateless_reset_count);
        return;
      }
      IncrementStat(&EndpointStats::packets_ignored);
      return;
    }
  }

  CHECK(session);

  // If the packet could not successfully processed for any reason (possibly
  // due to being malformed or malicious in some way) we mark it ignored.
  if (session->is_destroyed() ||
      !session->Receive(nread, data, local_addr, remote_addr, flags)) {
    IncrementStat(&EndpointStats::packets_ignored);
    return;
  }

  IncrementStat(&EndpointStats::packets_received);
}

void Endpoint::OnSendDone(UdpSendWrap* wrap, int status) {
  DecrementPendingCallbacks();
  std::unique_ptr<SendWrap> req(static_cast<SendWrap*>(wrap));
  Packet* packet = req->packet();

  if (status == 0) {
    Debug(this, "Sent %" PRIu64 " bytes (label: %s)",
          packet->length(),
          packet->diagnostic_label());
    IncrementStat(&EndpointStats::bytes_sent, packet->length());
    IncrementStat(&EndpointStats::packets_sent);
  } else {
    Debug(this, "Failed to send %" PRIu64 " bytes (status: %d, label: %s)",
          packet->length(),
          status,
          packet->diagnostic_label());
  }

  if (is_done_waiting_for_callbacks())
    OnEndpointDone();
}

uv_buf_t Endpoint::OnAlloc(size_t suggested_size) {
  return AllocatedBuffer::AllocateManaged(env(), suggested_size).release();
}

void Endpoint::OnRecv(
    ssize_t nread,
    const uv_buf_t& buf_,
    const sockaddr* addr,
    unsigned int flags) {
  AllocatedBuffer buf(env(), buf_);

  if (nread == 0)
    return;

  if (nread < 0)
    return OnError(nread);

  OnReceive(
      nread,
      std::move(buf),
      local_address(),
      SocketAddress(addr),
      flags);
}

UdpSendWrap* Endpoint::CreateSendWrap(size_t msg_size) {
  HandleScope handle_scope(env()->isolate());
  last_created_send_wrap_ = SendWrap::Create(env(), msg_size);
  return last_created_send_wrap_;
}

uint32_t Endpoint::GetFlowLabel(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    const CID& cid) {
  return GenerateFlowLabel(
      local_address,
      remote_address,
      cid,
      token_secret_,
      NGTCP2_STATELESS_RESET_TOKENLEN);
}

void Endpoint::OnAfterBind() {
  Debug(this, "Endpoint is bound to %s", local_address());
  RecordTimestamp(&EndpointStats::bound_at);
}

int Endpoint::Send(uv_buf_t* buf, size_t len, const sockaddr* addr) {
  int ret = static_cast<int>(udp_->Send(buf, len, addr));
  if (ret == 0)
    IncrementPendingCallbacks();
  return ret;
}

BaseObjectPtr<Session> Endpoint::AcceptInitialPacket(
    uint32_t version,
    const CID& dcid,
    const CID& scid,
    ssize_t nread,
    const uint8_t* data,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    unsigned int flags) {
  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  ngtcp2_pkt_hd hd;
  CID ocid;

  // If the QuicSocket is not listening, the paket will be ignored.
  if (!state_->listening) {
    Debug(this, "Endpoint is not listening");
    return BaseObjectPtr<Session>();
  }

  switch (ngtcp2_accept(&hd, data, static_cast<size_t>(nread))) {
    case 1:
      // Send Version Negotiation
      SendVersionNegotiation(version, dcid, scid, local_addr, remote_addr);
      // Fall through
    case -1:
      // Either a version negotiation packet was sent or the packet is
      // an invalid initial packet. Either way, there's nothing more we
      // can do here.
      return BaseObjectPtr<Session>();
  }

  // If the server is busy, of the number of connections total for this
  // server, and this remote addr, new connections will be shut down
  // immediately.
  if (UNLIKELY(state_->busy == 1) ||
      sessions_.size() >= config_.max_connections_total ||
      current_socket_address_count(remote_addr) >=
          config_.max_connections_per_host) {
    Debug(this, "QuicSocket is busy or connection count exceeded");
    IncrementStat(&EndpointStats::server_busy_count);
    ImmediateConnectionClose(
      version,
      CID(hd.scid),
      CID(hd.dcid),
      local_addr,
      remote_addr,
      NGTCP2_CONNECTION_REFUSED);
    return BaseObjectPtr<Session>();
  }

  Session::Config config(this);

  // QUIC has address validation built in to the handshake but allows for
  // an additional explicit validation request using RETRY frames. If we
  // are using explicit validation, we check for the existence of a valid
  // retry token in the packet. If one does not exist, we send a retry with
  // a new token. If it does exist, and if it's valid, we grab the original
  // cid and continue.
  if (!is_validated_address(remote_addr)) {
    switch (hd.type) {
      case NGTCP2_PKT_INITIAL:
        if (config_.validate_address || hd.token.len > 0) {
          Debug(this, "Performing explicit address validation");
          if (hd.token.len == 0) {
            Debug(this, "No retry token was detected. Generating one");
            SendRetry(version, dcid, scid, local_addr, remote_addr);
            return BaseObjectPtr<Session>();
          }
          if (InvalidRetryToken(
                  hd.token,
                  remote_addr,
                  &ocid,
                  token_secret_,
                  config_.retry_token_expiration,
                  token_aead_,
                  token_md_)) {
            Debug(this, "Invalid retry token was detected. Failing");
            ImmediateConnectionClose(
                version,
                CID(hd.scid),
                CID(hd.dcid),
                local_addr,
                remote_addr);
            return BaseObjectPtr<Session>();
          }
          set_validated_address(remote_addr);
          config.token = hd.token;
        }
        break;
      case NGTCP2_PKT_0RTT:
        SendRetry(version, dcid, scid, local_addr, remote_addr);
        return {};
    }
  }

  if (ocid && this->config().qlog)
    config.EnableQLog(ocid);

  BaseObjectPtr<Session> session =
      Session::CreateServer(
          this,
          local_addr,
          remote_addr,
          config,
          scid,
          dcid,
          ocid,
          version);
  CHECK(session);

  OnSessionReady(session);

  // It's possible that the session was destroyed while processing
  // the ready callback. If it was, then we need to send an early
  // CONNECTION_CLOSE.
  if (session->is_destroyed()) {
    ImmediateConnectionClose(
        version,
        CID(hd.scid),
        CID(hd.dcid),
        local_addr,
        remote_addr,
        NGTCP2_CONNECTION_REFUSED);
  } else {
    session->set_wrapped();
  }

  return session;
}

bool Endpoint::MaybeStatelessReset(
    const CID& dcid,
    const CID& scid,
    ssize_t nread,
    const uint8_t* data,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    unsigned int flags) {
  if (UNLIKELY(state_->stateless_reset_disabled || nread < 16))
    return false;
  StatelessResetToken possible_token(
      data + nread - NGTCP2_STATELESS_RESET_TOKENLEN);
  Debug(this, "Possible stateless reset token: %s", possible_token);
  auto it = token_map_.find(possible_token);
  if (it == token_map_.end())
    return false;
  Debug(this, "Received a stateless reset token %s", possible_token);
  return it->second->Receive(nread, data, local_addr, remote_addr, flags);
}

void Endpoint::ImmediateConnectionClose(
    uint32_t version,
    const CID& scid,
    const CID& dcid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    int64_t reason) {
  Debug(this, "Sending stateless connection close to %s", scid);
  std::unique_ptr<Packet> packet =
      std::make_unique<Packet>("immediate connection close");

  ssize_t nwrite = ngtcp2_crypto_write_connection_close(
      packet->data(),
      packet->length(),
      version,
      scid.cid(),
      dcid.cid(),
      reason);
  if (nwrite > 0) {
    packet->set_length(nwrite);
    SendPacket(local_addr, remote_addr, std::move(packet));
  }
}

void Endpoint::SendVersionNegotiation(
      uint32_t version,
      const CID& dcid,
      const CID& scid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr) {
  uint32_t sv[2];
  sv[0] = GenerateReservedVersion(remote_addr, version);
  sv[1] = NGTCP2_PROTO_VER_MAX;

  uint8_t unused_random;
  crypto::EntropySource(&unused_random, 1);

  size_t pktlen = dcid.length() + scid.length() + (sizeof(sv)) + 7;

  std::unique_ptr<Packet> packet =
      std::make_unique<Packet>(pktlen, "version negotiation");
  ssize_t nwrite = ngtcp2_pkt_write_version_negotiation(
      packet->data(),
      NGTCP2_MAX_PKTLEN_IPV6,
      unused_random,
      dcid.data(),
      dcid.length(),
      scid.data(),
      scid.length(),
      sv,
      arraysize(sv));
  if (nwrite > 0) {
    packet->set_length(nwrite);
    SendPacket(local_addr, remote_addr, std::move(packet));
  }
}

bool Endpoint::SendStatelessReset(
    const CID& cid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    size_t source_len) {
  if (UNLIKELY(state_->stateless_reset_disabled))
    return false;
  constexpr static size_t kRandlen = NGTCP2_MIN_STATELESS_RESET_RANDLEN * 5;
  constexpr static size_t kMinStatelessResetLen = 41;
  uint8_t random[kRandlen];

  // Per the QUIC spec, we need to protect against sending too
  // many stateless reset tokens to an endpoint to prevent
  // endless looping.
  if (current_stateless_reset_count(remote_addr) >=
          config_.max_stateless_resets) {
    return false;
  }
  // Per the QUIC spec, a stateless reset token must be strictly
  // smaller than the packet that triggered it. This is one of the
  // mechanisms to prevent infinite looping exchange of stateless
  // tokens with the peer.
  // An endpoint should never send a stateless reset token smaller than
  // 41 bytes per the QUIC spec. The reason is that packets less than
  // 41 bytes may allow an observer to determine that it's a stateless
  // reset.
  size_t pktlen = source_len - 1;
  if (pktlen < kMinStatelessResetLen)
    return false;

  StatelessResetToken token(config_.reset_token_secret, cid);
  crypto::EntropySource(random, kRandlen);

  std::unique_ptr<Packet> packet =
      std::make_unique<Packet>(pktlen, "stateless reset");
  ssize_t nwrite =
      ngtcp2_pkt_write_stateless_reset(
        packet->data(),
        NGTCP2_MAX_PKTLEN_IPV4,
        const_cast<uint8_t*>(token.data()),
        random,
        kRandlen);
  if (nwrite >= static_cast<ssize_t>(kMinStatelessResetLen)) {
    packet->set_length(nwrite);
    IncrementStatelessResetCounter(remote_addr);
    return SendPacket(local_addr, remote_addr, std::move(packet)) == 0;
  }
  return false;
}

bool Endpoint::SendRetry(
    uint32_t version,
    const CID& dcid,
    const CID& scid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr) {
  auto info = addrLRU_.Upsert(remote_addr);
  if (++(info->retry_count) > config_.retry_limit)
    return true;
  std::unique_ptr<Packet> packet =
      GenerateRetryPacket(
          version,
          token_secret_,
          dcid,
          scid,
          local_addr,
          remote_addr,
          token_aead_,
          token_md_);
  return packet ?
      SendPacket(local_addr, remote_addr, std::move(packet)) == 0 : false;
}

int Endpoint::SendPacket(
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<Session> session) {
  if (packet->length() == 0)
    return 0;

  Debug(this, "Sending %" PRIu64 " bytes to %s from %s (label: %s)",
        packet->length(),
        remote_addr,
        local_addr,
        packet->diagnostic_label());

  if (UNLIKELY(is_diagnostic_packet_loss(config_.tx_loss))) {
    Debug(this, "Simulating transmitted packet loss");
    return 0;
  }

  last_created_send_wrap_ = nullptr;
  uv_buf_t buf = packet->buf();

  int err = Send(&buf, 1, remote_addr.data());

  if (err != 0) {
    if (err > 0) {
      Debug(this, "Sent %" PRIu64 " bytes (label: %s)",
            packet->length(),
            packet->diagnostic_label());
      IncrementStat(&EndpointStats::bytes_sent, packet->length());
      IncrementStat(&EndpointStats::packets_sent);
    } else {
      Debug(this, "Failed to send %" PRIu64 " bytes (status: %d, label: %s)",
            packet->length(),
            err,
            packet->diagnostic_label());
    }
    return err;
  }

  CHECK_NOT_NULL(last_created_send_wrap_);
  last_created_send_wrap_->set_packet(std::move(packet));
  last_created_send_wrap_->set_session(session);
  return 0;
}

void Endpoint::AddSession(const CID& cid, BaseObjectPtr<Session> session) {
  sessions_[cid] = session;
  IncrementSocketAddressCounter(session->remote_address());
  IncrementStat(
      session->is_server() ?
          &EndpointStats::server_sessions :
          &EndpointStats::client_sessions);
}

void Endpoint::RemoveSession(const CID& cid, const SocketAddress& addr) {
  DecrementSocketAddressCounter(addr);
  sessions_.erase(cid);
}

void Endpoint::ReceiveStart() {
  udp_->RecvStart();
}

void Endpoint::ReceiveStop() {
  udp_->RecvStop();
}

void Endpoint::Listen(const Session::Options& options) {
  CHECK_NE(state_->listening, 1);
  CHECK(options.context);
  Debug(this, "Starting to listen");
  server_options_ = options;
  state_->listening = 1;
  RecordTimestamp(&EndpointStats::listen_at);
  ReceiveStart();
}

void Endpoint::DisassociateStatelessResetToken(
    const StatelessResetToken& token) {
  Debug(this, "Removing stateless reset token %s", token);
  token_map_.erase(token);
}

void Endpoint::AssociateStatelessResetToken(
    const StatelessResetToken& token,
    BaseObjectPtr<Session> session) {
  Debug(this, "Associating stateless reset token %s", token);
  token_map_[token] = session;
}

void Endpoint::DisassociateCID(const CID& cid) {
  if (cid) {
    Debug(this, "Removing association for cid %s", cid);
    dcid_to_scid_.erase(cid);
  }
}

void Endpoint::AssociateCID(const CID& cid, const CID& scid) {
  if (cid && scid) {
    Debug(this, "Associating cid %s with %s", cid, scid);
    dcid_to_scid_[cid] = scid;
  }
}

SocketAddress Endpoint::local_address() const {
  return udp_->GetSockName();
}

void Endpoint::WaitForPendingCallbacks() {
  if (!is_done_waiting_for_callbacks()) {
    OnEndpointDone();
    return;
  }
  state_->waiting_for_callbacks = 1;
}

BaseObjectPtr<Session> Endpoint::FindSession(const CID& cid) {
  BaseObjectPtr<Session> session;
  auto session_it = sessions_.find(cid);
  if (session_it == std::end(sessions_)) {
    auto scid_it = dcid_to_scid_.find(cid);
    if (scid_it != std::end(dcid_to_scid_)) {
      session_it = sessions_.find(scid_it->second);
      CHECK_NE(session_it, std::end(sessions_));
      session = session_it->second;
    }
  } else {
    session = session_it->second;
  }
  return session;
}

void Endpoint::set_validated_address(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->validated = true;
}

bool Endpoint::is_validated_address(const SocketAddress& addr) const {
  auto info = addrLRU_.Peek(addr);
  return info != nullptr ? info->validated : false;
}

bool Endpoint::is_diagnostic_packet_loss(double prob) const {
  if (LIKELY(prob == 0.0)) return false;
  unsigned char c = 255;
  crypto::EntropySource(&c, 1);
  return (static_cast<double>(c) / 255) < prob;
}

void Endpoint::IncrementStatelessResetCounter(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->reset_count++;
}

void Endpoint::IncrementSocketAddressCounter(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->active_connections++;
}

void Endpoint::DecrementSocketAddressCounter(const SocketAddress& addr) {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  if (counts != nullptr && counts->active_connections > 0)
    counts->active_connections--;
}

size_t Endpoint::current_socket_address_count(const SocketAddress& addr) const {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  return counts != nullptr ? counts->active_connections : 0;
}

size_t Endpoint::current_stateless_reset_count(
    const SocketAddress& addr) const {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  return counts != nullptr ? counts->reset_count : 0;
}

void Endpoint::IncrementPendingCallbacks() { state_->pending_callbacks++; }

void Endpoint::DecrementPendingCallbacks() { state_->pending_callbacks--; }

bool Endpoint::is_done_waiting_for_callbacks() const {
  return state_->waiting_for_callbacks && !state_->pending_callbacks;
}

bool Endpoint::SocketAddressInfoTraits::CheckExpired(
    const SocketAddress& address,
    const Type& type) {
  return (uv_hrtime() - type.timestamp) > 1e10;  // 10 seconds.
}

void Endpoint::SocketAddressInfoTraits::Touch(
    const SocketAddress& address,
    Type* type) {
  type->timestamp = uv_hrtime();
}

void EndpointStatsTraits::ToString(
    const Endpoint& ptr,
    AddStatsField add_field) {
#define V(_n, name, label) add_field(label, ptr.GetStat(&EndpointStats::name));
  ENDPOINT_STATS(V)
#undef V
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
