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
#include "udp_wrap.h"
#include "v8.h"

#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/evp.h>

namespace node {

using v8::BackingStore;
using v8::BigInt;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Int32;
using v8::Just;
using v8::Local;
using v8::Maybe;
using v8::Nothing;
using v8::Number;
using v8::Object;
using v8::PropertyAttribute;
using v8::String;
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
    tmpl = env->NewFunctionTemplate(IllegalConstructor);
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicEndpoint"));
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Endpoint::kInternalFieldCount);
    env->SetProtoMethod(
        tmpl,
        "startListen",
        StartListen);
    env->SetProtoMethod(
        tmpl,
        "startWaitingForPendingCallbacks",
        StartWaitForPendingCallbacks);
    state->set_endpoint_constructor_template(env, tmpl);
  }
  return tmpl;
}

void Endpoint::Initialize(Environment* env, Local<Object> target) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_endpoint_constructor_template(env, GetConstructorTemplate(env));

  env->SetMethod(target, "createEndpoint", CreateEndpoint);

  ConfigObject::Initialize(env, target);

#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATS_ENDPOINT_##name);
  ENDPOINT_STATS(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATS_ENDPOINT_COUNT);
#undef V
#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATE_ENDPOINT_##name);
  ENDPOINT_STATE(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATE_ENDPOINT_COUNT);
#undef V
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

void Endpoint::CreateEndpoint(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  CHECK(ConfigObject::HasInstance(env, args[0]));
  CHECK(args[1]->IsObject());  // UDPWrap object
  ConfigObject* config;
  ASSIGN_OR_RETURN_UNWRAP(&config, args[0]);

  BaseObjectPtr<Endpoint> endpoint = Create(
      env,
      args[1].As<Object>(),
      config->config());
  if (endpoint)
    args.GetReturnValue().Set(endpoint->object());
}

void Endpoint::StartListen(const FunctionCallbackInfo<Value>& args) {
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  CHECK(OptionsObject::HasInstance(env, args[0]));
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args[0].As<Object>());
  endpoint->Listen(options->options());
}

void Endpoint::StartWaitForPendingCallbacks(
    const FunctionCallbackInfo<Value>& args) {}

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

bool ConfigObject::HasInstance(Environment* env, Local<Value> value) {
  return GetConstructorTemplate(env)->HasInstance(value);
}

Local<FunctionTemplate> ConfigObject::GetConstructorTemplate(
    Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  Local<FunctionTemplate> tmpl =
      state->endpoint_config_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = env->NewFunctionTemplate(New);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        ConfigObject::kInternalFieldCount);
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "ConfigObject"));
    env->SetProtoMethod(
        tmpl,
        "generateResetTokenSecret",
        GenerateResetTokenSecret);
    env->SetProtoMethod(
        tmpl,
        "setResetTokenSecret",
        SetResetTokenSecret);
    state->set_endpoint_config_constructor_template(env, tmpl);
  }
  return tmpl;
}

void ConfigObject::Initialize(Environment* env, Local<Object> target) {
  env->SetConstructorFunction(
      target,
      "ConfigObject",
      GetConstructorTemplate(env));
}

Maybe<bool> ConfigObject::SetOption(
    Local<Object> object,
    Local<String> name,
    uint64_t Endpoint::Config::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return Nothing<bool>();

  if (value->IsUndefined())
    return Just(false);

  CHECK_IMPLIES(!value->IsBigInt(), value->IsNumber());

  uint64_t val = 0;
  if (value->IsBigInt()) {
    bool lossless = true;
    val = value.As<BigInt>()->Uint64Value(&lossless);
    if (!lossless) {
      Utf8Value label(env()->isolate(), name);
      THROW_ERR_OUT_OF_RANGE(
          env(),
          (std::string("options.") + *label + " is out of range").c_str());
      return Nothing<bool>();
    }
  } else {
    val = static_cast<int64_t>(value.As<Number>()->Value());
  }
  config_.get()->*member = val;
  return Just(true);
}

Maybe<bool> ConfigObject::SetOption(
    Local<Object> object,
    Local<String> name,
    double Endpoint::Config::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return Nothing<bool>();

  if (value->IsUndefined())
    return Just(false);

  CHECK(value->IsNumber());
  double val = static_cast<int64_t>(value.As<Number>()->Value());
  config_.get()->*member = val;
  return Just(true);
}

Maybe<bool> ConfigObject::SetOption(
    Local<Object> object,
    Local<String> name,
    ngtcp2_cc_algo Endpoint::Config::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return Nothing<bool>();

  if (value->IsUndefined())
    return Just(false);

  ngtcp2_cc_algo val = static_cast<ngtcp2_cc_algo>(value.As<Int32>()->Value());
  switch (val) {
    case NGTCP2_CC_ALGO_CUBIC:
      // Fall through
    case NGTCP2_CC_ALGO_RENO:
      config_.get()->*member = val;
      break;
    default:
      UNREACHABLE();
  }

  return Just(true);
}

Maybe<bool> ConfigObject::SetOption(
    Local<Object> object,
    Local<String> name,
    bool Endpoint::Config::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return Nothing<bool>();
  if (value->IsUndefined())
    return Just(false);
  CHECK(value->IsBoolean());
  config_.get()->*member = value->IsTrue();
  return Just(true);
}

void ConfigObject::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);

  ConfigObject* config = new ConfigObject(env, args.This());
  config->data()->GenerateResetTokenSecret();

  if (args[0]->IsObject()) {
    BindingState* state = env->GetBindingData<BindingState>(env->context());
    Local<Object> object = args[0].As<Object>();
    if (config->SetOption(
            object,
            state->retry_token_expiration_string(env),
            &Endpoint::Config::retry_token_expiration).IsNothing() ||
        config->SetOption(
            object,
            state->max_window_override_string(env),
            &Endpoint::Config::max_window_override).IsNothing() ||
        config->SetOption(
            object,
            state->max_stream_window_override_string(env),
            &Endpoint::Config::max_stream_window_override).IsNothing() ||
        config->SetOption(
            object,
            state->max_connections_per_host_string(env),
            &Endpoint::Config::max_connections_per_host).IsNothing() ||
        config->SetOption(
            object,
            state->max_connections_total_string(env),
            &Endpoint::Config::max_connections_total).IsNothing() ||
        config->SetOption(
            object,
            state->max_stateless_resets_string(env),
            &Endpoint::Config::max_stateless_resets).IsNothing() ||
        config->SetOption(
            object,
            state->address_lru_size_string(env),
            &Endpoint::Config::address_lru_size).IsNothing() ||
        config->SetOption(
            object,
            state->retry_limit_string(env),
            &Endpoint::Config::retry_limit).IsNothing() ||
        config->SetOption(
            object,
            state->max_payload_size_string(env),
            &Endpoint::Config::max_payload_size).IsNothing() ||
        config->SetOption(
            object,
            state->unacknowledged_packet_threshold_string(env),
            &Endpoint::Config::unacknowledged_packet_threshold).IsNothing() ||
        config->SetOption(
            object,
            state->qlog_string(env),
            &Endpoint::Config::qlog).IsNothing() ||
        config->SetOption(
            object,
            state->validate_address_string(env),
            &Endpoint::Config::validate_address).IsNothing() ||
        config->SetOption(
            object,
            state->disable_stateless_reset_string(env),
            &Endpoint::Config::disable_stateless_reset).IsNothing() ||
        config->SetOption(
            object,
            state->rx_packet_loss_string(env),
            &Endpoint::Config::rx_loss).IsNothing() ||
        config->SetOption(
            object,
            state->tx_packet_loss_string(env),
            &Endpoint::Config::tx_loss).IsNothing() ||
        config->SetOption(
            object,
            state->cc_algorithm_string(env),
            &Endpoint::Config::cc_algorithm).IsNothing()) {
      // The if block intentionally does nothing. The code is structured
      // like this to shortcircuit if any of the SetOptions() returns Nothing.
    }
  }
}

void ConfigObject::GenerateResetTokenSecret(
    const FunctionCallbackInfo<Value>& args) {
  ConfigObject* config;
  ASSIGN_OR_RETURN_UNWRAP(&config, args.Holder());
  config->data()->GenerateResetTokenSecret();
}

void ConfigObject::SetResetTokenSecret(
    const FunctionCallbackInfo<Value>& args) {
  ConfigObject* config;
  ASSIGN_OR_RETURN_UNWRAP(&config, args.Holder());

  crypto::ArrayBufferOrViewContents<uint8_t> secret(args[0]);
  CHECK_EQ(secret.size(), sizeof(config->data()->reset_token_secret));
  memcpy(config->data()->reset_token_secret, secret.data(), secret.size());
}

ConfigObject::ConfigObject(
    Environment* env,
    Local<Object> object,
    std::shared_ptr<Endpoint::Config> config)
    : BaseObject(env, object),
      config_(config) {
  MakeWeak();
}

void ConfigObject::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("config", config_);
}

ConfigObject::TransferData::TransferData(
    std::shared_ptr<Endpoint::Config> config)
    : config_(std::move(config)) {}

std::unique_ptr<worker::TransferData>
ConfigObject::CloneForMessaging() const {
  return std::make_unique<ConfigObject::TransferData>(config_);
}

void ConfigObject::TransferData::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("config", config_);
}

BaseObjectPtr<BaseObject> ConfigObject::TransferData::Deserialize(
    Environment* env,
    v8::Local<v8::Context> context,
    std::unique_ptr<worker::TransferData> self) {
  Local<Object> obj;
  if (!ConfigObject::GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(context).ToLocal(&obj)) {
    return BaseObjectPtr<BaseObject>();
  }

  return MakeDetachedBaseObject<ConfigObject>(env, obj, std::move(config_));
}

// -------------

Local<FunctionTemplate> InnerEndpoint::SendWrap::GetConstructorTemplate(
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

InnerEndpoint::SendWrap* InnerEndpoint::SendWrap::Create(
    Environment* env,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<InnerSession> session) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return nullptr;
  }

  return new SendWrap(env, obj, std::move(packet), std::move(session));
}

InnerEndpoint::SendWrap::SendWrap(
    Environment* env,
    v8::Local<v8::Object> object,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<InnerSession> session)
    : UdpSendWrap(env, object, AsyncWrap::PROVIDER_QUICSENDWRAP),
      packet_(std::move(packet)),
      session_(std::move(session)) {}

void InnerEndpoint::SendWrap::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("packet", packet_);
  tracker->TrackField("session", session_);
}

InnerEndpoint::InnerEndpoint(
    Environment* env,
    v8::Local<v8::Object> object,
    const Config& config)
    : HandleWrap(env,
                 object,
                 reinterpret_cast<uv_handle_t*>(&handle_),
                 AsyncWrap::PROVIDER_QUICENDPOINT),
      StatsBase(env, object),
      config_(config),
      token_aead_(CryptoAeadAes128GCM()),
      token_md_(CryptoMDSha256()),
      addrLRU_(config.address_lru_size) {
  MakeWeak();

  CHECK_EQ(uv_udp_init(env->event_loop(), &handle_), 0);

  CHECK_EQ(uv_async_init(env->event_loop(), &outbound_signal_, OnOutbound), 0);
  uv_unref(reinterpret_cast<uv_handle_t*>(&outbound_signal_));

  Debug(this, "New QUIC endpoint created");

  crypto::EntropySource(
      reinterpret_cast<unsigned char*>(token_secret_),
      kTokenSecretLen);
};

void InnerEndpoint::MemoryInfo(MemoryTracker* tracker) const {
  // TODO(@jasnell): Implement
}

bool InnerEndpoint::AcceptInitialPacket(
    uint32_t version,
    const CID& dcid,
    const CID& scid,
    std::shared_ptr<v8::BackingStore> store,
    size_t nread,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    unsigned int flags) {

  ngtcp2_pkt_hd hd;
  CID ocid;

  InitialPacketListener* listener = NextListener();
  if (listener == nullptr) {
    Debug(this, "Endpoint is not listening");
    return false;
  }

  uint8_t* data = static_cast<uint8_t*>(store->Data());
  switch (ngtcp2_accept(&hd, data, nread)) {
    case 1:
      // Send Version Negotiation
      SendVersionNegotiation(version, dcid, scid, local_addr, remote_addr);
      // Fall through
    case -1:
      // Either a version negotiation packet was sent or the packet is
      // an invalid initial packet. Either way, there's nothing more we
      // can do here and we will consider this an ignored packet.
      return false;
  }

  // If the server is busy, of the number of connections total for this
  // server, and this remote addr, new connections will be shut down
  // immediately.
  if (UNLIKELY(busy_) ||
      sessions_.size() >= config_.max_connections_total ||
      current_socket_address_count(remote_addr) >=
          config_.max_connections_per_host) {
    Debug(this, "Endpoint is busy or connection count exceeded");
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

  InnerSession::Config config(this, dcid, scid, version);

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

  listener->Accept(config, std::move(store), nread, local_addr, remote_addr);

  return true;
}

void InnerEndpoint::AddSession(
    const CID& cid,
    BaseObjectPtr<InnerSession> session) {
  Mutex::ScopedLock lock(session_mutex_);
  sessions_[cid] = session;
  IncrementSocketAddressCounter(session->remote_address());
  IncrementStat(
      session->is_server() ?
          &EndpointStats::server_sessions :
          &EndpointStats::client_sessions);
}

void InnerEndpoint::RemoveSession(const CID& cid, const SocketAddress& addr) {
  Mutex::ScopedLock lock(session_mutex_);
  sessions_.erase(cid);
  DecrementSocketAddressCounter(addr);
}

void InnerEndpoint::AddInitialPacketListener(
    InitialPacketListener* listener) {
  Mutex::ScopedLock lock(listener_mutex_);
  listeners_.emplace_back(listener);
}

void InnerEndpoint::ImmediateConnectionClose(
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

void InnerEndpoint::RemoveInitialPacketListener(
    InitialPacketListener* listener) {
  Mutex::ScopedLock lock(listener_mutex_);
  auto it = std::find(listeners_.begin(), listeners_.end(), listener);
  if (it != listeners_.end())
    listeners_.erase(it);
}

InnerEndpoint::InitialPacketListener* InnerEndpoint::NextListener() {
  Mutex::ScopedLock lock(listener_mutex_);
  if (listeners_.empty()) return nullptr;
  InitialPacketListener* listener = listeners_.front();
  listeners_.pop_front();
  listeners_.push_back(listener);
  return listener;
}

InnerSession* InnerEndpoint::FindSession(const CID& cid) {
  Mutex::ScopedLock lock(session_mutex_);
  auto session_it = sessions_.find(cid);
  if (session_it == std::end(sessions_)) {
    auto scid_it = dcid_to_scid_.find(cid);
    if (scid_it != std::end(dcid_to_scid_)) {
      session_it = sessions_.find(scid_it->second);
      CHECK_NE(session_it, std::end(sessions_));
      return session_it->second.get();
    }
  }
  return session_it->second.get();
}

void InnerEndpoint::DisassociateStatelessResetToken(
    const StatelessResetToken& token) {
  Debug(this, "Removing stateless reset token %s", token);
  Mutex::ScopedLock lock(session_mutex_);
  token_map_.erase(token);
}

void InnerEndpoint::AssociateStatelessResetToken(
    const StatelessResetToken& token,
    BaseObjectPtr<InnerSession> session) {
  Debug(this, "Associating stateless reset token %s", token);
  Mutex::ScopedLock lock(session_mutex_);
  token_map_[token] = session;
}

void InnerEndpoint::DisassociateCID(const CID& cid) {
  if (cid) {
    Debug(this, "Removing association for cid %s", cid);
    Mutex::ScopedLock lock(session_mutex_);
    dcid_to_scid_.erase(cid);
  }
}

void InnerEndpoint::AssociateCID(const CID& cid, const CID& scid) {
  if (cid && scid) {
    Debug(this, "Associating cid %s with %s", cid, scid);
    Mutex::ScopedLock lock(session_mutex_);
    dcid_to_scid_[cid] = scid;
  }
}

bool InnerEndpoint::MaybeStatelessReset(
    const CID& dcid,
    const CID& scid,
    std::shared_ptr<BackingStore> store,
    size_t nread,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    unsigned int flags) {
  if (UNLIKELY(config_.disable_stateless_reset) ||
      nread < NGTCP2_STATELESS_RESET_TOKENLEN) {
    return false;
  }
  uint8_t* ptr = static_cast<uint8_t*>(store->Data());
  ptr += nread;
  ptr -= NGTCP2_STATELESS_RESET_TOKENLEN;
  StatelessResetToken possible_token(ptr);
  Debug(this, "Possible stateless reset token: %s", possible_token);
  Mutex::ScopedLock lock(session_mutex_);
  auto it = token_map_.find(possible_token);
  if (it == token_map_.end())
    return false;
  Debug(this, "Received a stateless reset token %s", possible_token);
  return it->second->Receive(std::move(store), local_addr, remote_addr, flags);
}

void InnerEndpoint::OnAlloc(
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf) {
  InnerEndpoint* endpoint =
      ContainerOf(
        &InnerEndpoint::handle_,
        reinterpret_cast<uv_udp_t*>(handle));
  *buf = endpoint->OnAlloc(suggested_size);
}

uv_buf_t InnerEndpoint::OnAlloc(size_t suggested_size) {
  return AllocatedBuffer::AllocateManaged(env(), suggested_size).release();
}

void InnerEndpoint::OnOutbound(uv_async_t* handle) {
  InnerEndpoint* endpoint =
      ContainerOf(&InnerEndpoint::outbound_signal_, handle);
  endpoint->ProcessOutbound();
}

void InnerEndpoint::OnReceive(
    uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const sockaddr* addr,
    unsigned int flags) {
  InnerEndpoint* endpoint =
      ContainerOf(&InnerEndpoint::handle_, handle);
  if (nread < 0) {
    endpoint->ProcessReceiveFailure(static_cast<int>(nread));
    return;
  }

  endpoint->OnReceive(
      static_cast<size_t>(nread),
      *buf,
      SocketAddress(addr),
      flags);
}

void InnerEndpoint::OnReceive(
    size_t nread,
    const uv_buf_t& buf,
    const SocketAddress& remote_address,
    unsigned int flags) {
  AllocatedBuffer buffer(env(), buf);

  Debug(this, "Receiving %llu bytes from the UDP socket", nread);

  // When diagnostic packet loss is enabled, the packet will be randomly
  // dropped based on the rx_loss probability.
  if (UNLIKELY(is_diagnostic_packet_loss(config_.rx_loss))) {
    Debug(this, "Simulating received packet loss");
    return;
  }

  // if (UNLIKELY(block_list_->Apply(remote_addr))) {
  //   Debug(this, "Ignoring blocked remote address: %s", remote_addr);
  //   IncrementStat(&EndpointStats::packets_ignored);
  //   return;
  // }

  IncrementStat(&EndpointStats::bytes_received, nread);

  // If the bytes read is less than the allocated buffer size,
  // we need to compact it back down
  std::shared_ptr<BackingStore> store = buffer.ReleaseBackingStore();

  if (!store) {
    ProcessReceiveFailure(UV_ENOMEM);
    return;
  }

  const uint8_t* data = reinterpret_cast<const uint8_t*>(store->Data());

  CHECK_LE(nread, store->ByteLength());

  uint32_t pversion;
  const uint8_t* pdcid;
  size_t pdcidlen;
  const uint8_t* pscid;
  size_t pscidlen;

  // This is our first check to see if the received data can be
  // processed as a QUIC packet. If this fails, then the QUIC packet
  // header is invalid and cannot be processed; all we can do is ignore
  // it. It is questionable whether we should even increment the
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

  InnerSession* session = FindSession(dcid);

  // If a session is not found, there are four possible reasons:
  // 1. The session has not been created yet
  // 2. The session existed once but we've lost the local state for it
  // 3. The packet is a stateless reset sent by the peer
  // 4. This is a malicious or malformed packet.
  if (session == nullptr) {
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
            store,
            nread,
            local_address(),
            remote_address,
            flags)) {
      Debug(this, "Handled stateless reset");
      IncrementStat(&EndpointStats::packets_received);
      return;
    }

    if (AcceptInitialPacket(
          pversion,
          dcid,
          scid,
          store,
          nread,
          local_address(),
          remote_address,
          flags)) {
      Debug(this, "Handled initial packet");
      IncrementStat(&EndpointStats::packets_received);
    }

    // There are many reasons why a server session could not be
    // created. The most common will be invalid packets or incorrect
    // QUIC version. In any of these cases, however, to prevent a
    // potential attacker from causing us to consume resources,
    // we're just going to ignore the packet. It is possible that
    // the AcceptInitialPacket sent a version negotiation packet,
    // or a CONNECTION_CLOSE packet.
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
        SendStatelessReset(dcid, local_address(), remote_address, nread)) {
      Debug(this, "Sent stateless reset");
      IncrementStat(&EndpointStats::stateless_reset_count);
      return;
    }
    IncrementStat(&EndpointStats::packets_ignored);
    return;
  }

  // If the packet could not successfully processed for any reason (possibly
  // due to being malformed or malicious in some way) we mark it ignored.
  if (session->is_destroyed() ||
      !session->Receive(
          std::move(store),
          nread,
          local_address(),
          remote_address,
          flags)) {
    IncrementStat(&EndpointStats::packets_ignored);
    return;
  }

  IncrementStat(&EndpointStats::packets_received);
}

void InnerEndpoint::ProcessOutbound() {
  QueuedPacket::Queue queue;
  {
    Mutex::ScopedLock lock(outbound_mutex_);
    outbound_.swap(queue);
  }

  int err = 0;
  while (!queue.empty()) {
    auto& packet = queue.front();
    queue.pop_front();

    err = ProcessPacket(
      packet.local_address,
      packet.remote_address,
      std::move(packet.packet),
      std::move(packet.session));

    if (err) break;
  }

  // If there was a fatal error sending, the Endpoint
  // will be destroyed along with all associated sessions.
  // Go ahead and cancel the remaining pending sends.
  if (err) {
    while (!queue.empty()) {
      auto& packet = queue.front();
      queue.pop_front();
      packet.session->SendPacketDone(UV_ECANCELED);
    }
    ProcessSendFailure(err);
  }
}

int InnerEndpoint::ProcessPacket(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<InnerSession> session) {
  uv_buf_t buf = packet->buf();
  const sockaddr* remote_addr = remote_address.data();

  AsyncHooks::DefaultTriggerAsyncIdScope trigger_scope(this);
  SendWrap* req = SendWrap::Create(env(), std::move(packet), session);
  if (req == nullptr) {
    if (session)
      session->SendPacketDone(UV_ENOSYS);
    return UV_ENOSYS;
  }

  IncrementPendingOutbound();
  int err = req->Dispatch(
      uv_udp_send,
      &handle_,
      &buf, 1,
      remote_addr,
      uv_udp_send_cb{[](uv_udp_send_t* req, int status) {
        std::unique_ptr<SendWrap> ptr(
          static_cast<SendWrap*>(UdpSendWrap::from_req(req)));
        InnerEndpoint* endpoint =
            ContainerOf(&InnerEndpoint::handle_, req->handle);
        if (ptr->session())
          ptr->session()->SendPacketDone(status);
        endpoint->DecrementPendingOutbound();
      }});

  if (err) {
    std::unique_ptr<SendWrap> free_me(req);
    session->SendPacketDone(err);
  }

  return err;
}

void InnerEndpoint::ProcessSendFailure(int status) {
  // TODO(@jasnell): Likely a signal of a larger failure.
  // Tear down the Endpoint...
}

void InnerEndpoint::Ref() {
  uv_ref(reinterpret_cast<uv_handle_t*>(&handle_));
}

bool InnerEndpoint::SendPacket(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    std::unique_ptr<Packet> packet,
    InnerSession* session) {
  if (IsHandleClosing()) return false;
  {
    Mutex::ScopedLock lock(outbound_mutex_);
    outbound_.emplace_back(QueuedPacket{
      local_address,
      remote_address,
      std::move(packet),
      BaseObjectPtr<InnerSession>(session)
    });
  }
  uv_async_send(&outbound_signal_);
}

bool InnerEndpoint::SendRetry(
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

bool InnerEndpoint::SendStatelessReset(
    const CID& cid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    size_t source_len) {
  if (UNLIKELY(config_.disable_stateless_reset))
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

void InnerEndpoint::SendVersionNegotiation(
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

int InnerEndpoint::StartReceiving() {
  if (IsHandleClosing()) return UV_EBADF;
  int err = uv_udp_recv_start(&handle_, OnAlloc, OnReceive);
  if (err == UV_EALREADY)
    err = 0;
  return err;
}

int InnerEndpoint::StopReceiving() {
  if (IsHandleClosing()) return UV_EBADF;
  return uv_udp_recv_stop(&handle_);
}

void InnerEndpoint::Unref() {
  uv_unref(reinterpret_cast<uv_handle_t*>(&handle_));
}

bool InnerEndpoint::is_diagnostic_packet_loss(double prob) const {
  if (LIKELY(prob == 0.0)) return false;
  unsigned char c = 255;
  crypto::EntropySource(&c, 1);
  return (static_cast<double>(c) / 255) < prob;
}

void InnerEndpoint::set_validated_address(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->validated = true;
}

bool InnerEndpoint::is_validated_address(const SocketAddress& addr) const {
  auto info = addrLRU_.Peek(addr);
  return info != nullptr ? info->validated : false;
}

void InnerEndpoint::IncrementStatelessResetCounter(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->reset_count++;
}

void InnerEndpoint::IncrementSocketAddressCounter(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->active_connections++;
}

void InnerEndpoint::DecrementSocketAddressCounter(const SocketAddress& addr) {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  if (counts != nullptr && counts->active_connections > 0)
    counts->active_connections--;
}

size_t InnerEndpoint::current_socket_address_count(
    const SocketAddress& addr) const {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  return counts != nullptr ? counts->active_connections : 0;
}

size_t InnerEndpoint::current_stateless_reset_count(
    const SocketAddress& addr) const {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  return counts != nullptr ? counts->reset_count : 0;
}

SocketAddress InnerEndpoint::local_address() const {
  return SocketAddress::FromSockName(handle_);
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
