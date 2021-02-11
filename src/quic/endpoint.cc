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
using v8::Integer;
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
    env->SetProtoMethod(
        tmpl,
        "setLocalAddress",
        SetLocalAddress);
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

  // Set as default
  SocketAddress::New("localhost", 0, &config->data()->local_address);

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

void ConfigObject::SetLocalAddress(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  ConfigObject* config;
  ASSIGN_OR_RETURN_UNWRAP(&config, args.Holder());

  CHECK(args[0]->IsInt32());  // Family
  CHECK(args[1]->IsString());  // Address
  CHECK(args[2]->IsInt32());  // Port

  int32_t family = args[0].As<Int32>()->Value();
  Utf8Value address(env->isolate(), args[1]);
  int32_t port = args[2].As<Int32>()->Value();

  args.GetReturnValue().Set(
      SocketAddress::New(
          family,
          *address,
          port,
          &config->data()->local_address));
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

Local<FunctionTemplate> Endpoint::SendWrap::GetConstructorTemplate(
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

BaseObjectPtr<Endpoint::SendWrap> Endpoint::SendWrap::Create(
    Environment* env,
    const SocketAddress& destination,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<EndpointWrap> endpoint) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return BaseObjectPtr<SendWrap>();
  }

  return MakeDetachedBaseObject<SendWrap>(
      env,
      obj,
      destination,
      std::move(packet),
      std::move(endpoint));
}

Endpoint::SendWrap::SendWrap(
    Environment* env,
    v8::Local<v8::Object> object,
    const SocketAddress& destination,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<EndpointWrap> endpoint)
    : UdpSendWrap(env, object, AsyncWrap::PROVIDER_QUICSENDWRAP),
      destination_(destination),
      packet_(std::move(packet)),
      endpoint_(std::move(endpoint)),
      self_ptr_(this) {
  MakeWeak();
}

void Endpoint::SendWrap::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("destination", destination_);
  tracker->TrackField("packet", packet_);
  if (endpoint_)
    tracker->TrackField("endpoint", endpoint_);
}

void Endpoint::SendWrap::Done(int status) {
  if (endpoint_)
    endpoint_->OnSendDone(status);
  strong_ptr_.reset();
  self_ptr_.reset();
  endpoint_.reset();
}

Endpoint::Endpoint(
    Environment* env,
    const Config& config)
    : EndpointStatsBase(env),
      env_(env),
      udp_(env, this),
      config_(config),
      outbound_signal_(env, [this]() { this->ProcessOutbound(); }),
      token_aead_(CryptoAeadAes128GCM()),
      token_md_(CryptoMDSha256()),
      addrLRU_(config.address_lru_size) {
  outbound_signal_.Unref();
  crypto::EntropySource(
      reinterpret_cast<unsigned char*>(token_secret_),
      kTokenSecretLen);
  env->AddCleanupHook(OnCleanup, this);
};

Endpoint::~Endpoint() {
  // There should be no more sessions and all queues
  // and lists should be empty.
  CHECK(sessions_.empty());
  CHECK(outbound_.empty());
  CHECK(listeners_.empty());
  outbound_signal_.Close();
}

void Endpoint::OnCleanup(void* data) {
  Endpoint* endpoint = static_cast<Endpoint*>(data);
  endpoint->Close();
}

void Endpoint::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("udp", udp_);
  tracker->TrackField("outbound", outbound_);
  tracker->TrackField("addrLRU", addrLRU_);
}

void Endpoint::ProcessReceiveFailure(int status) {
  Close(CloseListener::Context::RECEIVE_FAILURE, status);
}

void Endpoint::AddCloseListener(CloseListener* listener) {
  close_listeners_.insert(listener);
}

void Endpoint::RemoveCloseListener(CloseListener* listener) {
  close_listeners_.erase(listener);
}

void Endpoint::Close(CloseListener::Context context, int status) {
  Lock lock(this);
  env()->RemoveCleanupHook(OnCleanup, this);
  udp_.Close();
  for (const auto listener : close_listeners_) {
    listener->EndpointClosed(context, status);
  }
}

bool Endpoint::AcceptInitialPacket(
    uint32_t version,
    const CID& dcid,
    const CID& scid,
    std::shared_ptr<v8::BackingStore> store,
    size_t nread,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr) {

  ngtcp2_pkt_hd hd;
  CID ocid;

  if (listeners_.empty()) return false;

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
    // Endpoint is busy or the connection count is exceeded
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

  Session::Config config(this, dcid, scid, version);

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
          // Perform explicit address validation
          if (hd.token.len == 0) {
            // No retry token was detected. Generate one.
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
            // Invalid retry token was detected. Close the connection.
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

  if (ocid && config_.qlog)
    config.EnableQLog(ocid);

  // Iterate through the available listeners, if any. If a listener
  // accepts the packet, that listener will be moved to the end of
  // the list so that another listener has the option of picking
  // up the next one.
  {
    Lock lock(this);
    for (auto it = listeners_.begin(); it != listeners_.end(); it++) {
      InitialPacketListener* listener = *it;
      if (listener->Accept(config, store, nread, local_addr, remote_addr)) {
        listeners_.erase(it);
        listeners_.emplace_back(listener);
        return true;
      }
    }
  }

  return false;
}

void Endpoint::AssociateCID(const CID& cid, PacketListener* listener) {
  sessions_[cid] = listener;
}

void Endpoint::DisassociateCID(const CID& cid) {
  sessions_.erase(cid);
}

void Endpoint::AddInitialPacketListener(InitialPacketListener* listener) {
  listeners_.emplace_back(listener);
}

void Endpoint::ImmediateConnectionClose(
    uint32_t version,
    const CID& scid,
    const CID& dcid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    int64_t reason) {
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
    SendPacket(remote_addr, std::move(packet));
  }
}

void Endpoint::RemoveInitialPacketListener(
    InitialPacketListener* listener) {
  auto it = std::find(listeners_.begin(), listeners_.end(), listener);
  if (it != listeners_.end())
    listeners_.erase(it);
}

Endpoint::PacketListener* Endpoint::FindSession(const CID& cid) {
  auto session_it = sessions_.find(cid);
  if (session_it != std::end(sessions_))
    return session_it->second;
  return nullptr;
}

void Endpoint::DisassociateStatelessResetToken(
    const StatelessResetToken& token) {
  token_map_.erase(token);
}

void Endpoint::AssociateStatelessResetToken(
    const StatelessResetToken& token,
    PacketListener* listener) {
  token_map_[token] = listener;
}

int Endpoint::MaybeBind() {
  if (bound_) return 0;
  bound_ = true;

  return udp_.Bind(
      config_.local_address,
      config_.local_address.family() == AF_INET6 && config_.ipv6_only
          ? UV_UDP_IPV6ONLY : 0);
}

bool Endpoint::MaybeStatelessReset(
    const CID& dcid,
    const CID& scid,
    std::shared_ptr<BackingStore> store,
    size_t nread,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr) {
  if (UNLIKELY(config_.disable_stateless_reset) ||
      nread < NGTCP2_STATELESS_RESET_TOKENLEN) {
    return false;
  }
  uint8_t* ptr = static_cast<uint8_t*>(store->Data());
  ptr += nread;
  ptr -= NGTCP2_STATELESS_RESET_TOKENLEN;
  StatelessResetToken possible_token(ptr);
  Lock lock(this);
  auto it = token_map_.find(possible_token);
  if (it == token_map_.end())
    return false;
  return it->second->Receive(
      dcid,
      scid,
      std::move(store),
      nread,
      local_addr,
      remote_addr,
      PacketListener::Flags::STATELESS_RESET);
}

uv_buf_t Endpoint::OnAlloc(size_t suggested_size) {
  return AllocatedBuffer::AllocateManaged(env(), suggested_size).release();
}

void Endpoint::OnReceive(
    size_t nread,
    const uv_buf_t& buf,
    const SocketAddress& remote_address) {
  AllocatedBuffer buffer(env(), buf);

  // When diagnostic packet loss is enabled, the packet will be randomly
  // dropped based on the rx_loss probability.
  if (UNLIKELY(is_diagnostic_packet_loss(config_.rx_loss)))
    return;

  // if (UNLIKELY(block_list_->Apply(remote_addr))) {
  //   Debug(this, "Ignoring blocked remote address: %s", remote_addr);
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
  // it. If it succeeds, we have a valid QUIC header but there is still
  // no guarantee that the packet can be successfully processed.
  if (ngtcp2_pkt_decode_version_cid(
        &pversion,
        &pdcid,
        &pdcidlen,
        &pscid,
        &pscidlen,
        data,
        nread,
        NGTCP2_MAX_CIDLEN) < 0) {
    return;  // Ignore the packet!
  }

  // QUIC currently requires CID lengths of max NGTCP2_MAX_CIDLEN. The
  // ngtcp2 API allows non-standard lengths, and we may want to allow
  // non-standard lengths later. But for now, we're going to ignore any
  // packet with a non-standard CID length.
  if (pdcidlen > NGTCP2_MAX_CIDLEN || pscidlen > NGTCP2_MAX_CIDLEN)
    return;  // Ignore the packet!

  CID dcid(pdcid, pdcidlen);
  CID scid(pscid, pscidlen);

  PacketListener* listener = nullptr;
  {
    Lock lock(this);
    listener = FindSession(dcid);
  }

  // If a session is not found, there are four possible reasons:
  // 1. The session has not been created yet
  // 2. The session existed once but we've lost the local state for it
  // 3. The packet is a stateless reset sent by the peer
  // 4. This is a malicious or malformed packet.
  if (listener == nullptr) {
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
            remote_address)) {
      return;  // Ignore the packet!
    }

    if (AcceptInitialPacket(
          pversion,
          dcid,
          scid,
          store,
          nread,
          local_address(),
          remote_address)) {
      return IncrementStat(&EndpointStats::packets_received);
    }

    // There are many reasons why a server session could not be
    // created. The most common will be invalid packets or incorrect
    // QUIC version. In any of these cases, however, to prevent a
    // potential attacker from causing us to consume resources,
    // we're just going to ignore the packet. It is possible that
    // the AcceptInitialPacket sent a version negotiation packet,
    // or a CONNECTION_CLOSE packet.

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
      return IncrementStat(&EndpointStats::stateless_reset_count);
    }
    return;  // Ignore the packet!
  }

  if (listener->Receive(
          dcid,
          scid,
          std::move(store),
          nread,
          local_address(),
          remote_address)) {
    IncrementStat(&EndpointStats::packets_received);
  }
}

void Endpoint::ProcessOutbound() {
  SendWrap::Queue queue;
  {
    Lock lock(this);
    outbound_.swap(queue);
  }

  int err = 0;
  while (!queue.empty()) {
    auto& packet = queue.front();
    queue.pop_front();
    err = udp_.SendPacket(packet);
    if (err) {
      packet->Done(err);
      break;
    }
  }

  // If there was a fatal error sending, the Endpoint
  // will be destroyed along with all associated sessions.
  // Go ahead and cancel the remaining pending sends.
  if (err) {
    while (!queue.empty()) {
      auto& packet = queue.front();
      queue.pop_front();
      packet->Done(UV_ECANCELED);
    }
    ProcessSendFailure(err);
  }
}

void Endpoint::ProcessSendFailure(int status) {
  Close(CloseListener::Context::SEND_FAILURE, status);
}

void Endpoint::Ref() {
  udp_.Ref();
}

bool Endpoint::SendPacket(
    const SocketAddress& remote_address,
    std::unique_ptr<Packet> packet) {
  BaseObjectPtr<SendWrap> wrap(
      SendWrap::Create(
          env(),
          remote_address,
          std::move(packet)));
  if (!wrap) return false;
  SendPacket(std::move(wrap));
  return true;
}

void Endpoint::SendPacket(BaseObjectPtr<SendWrap> packet) {
  {
    Lock lock(this);
    outbound_.emplace_back(std::move(packet));
    IncrementStat(&EndpointStats::bytes_sent, packet->packet()->length());
    IncrementStat(&EndpointStats::packets_sent);
  }
  outbound_signal_.Send();
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
  if (!packet) return false;
  return SendPacket(remote_addr, std::move(packet));
}

bool Endpoint::SendStatelessReset(
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
    return SendPacket(remote_addr, std::move(packet));
  }
  return false;
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
    SendPacket(remote_addr, std::move(packet));
  }
}

int Endpoint::StartReceiving() {
  if (receiving_) return UV_EALREADY;
  receiving_ = true;
  int err = MaybeBind();
  if (err) return err;
  return udp_.StartReceiving();
}

int Endpoint::StopReceiving() {
  receiving_ = false;
  return udp_.StopReceiving();
}

void Endpoint::Unref() {
  udp_.Unref();
}

bool Endpoint::is_diagnostic_packet_loss(double prob) const {
  if (LIKELY(prob == 0.0)) return false;
  unsigned char c = 255;
  crypto::EntropySource(&c, 1);
  return (static_cast<double>(c) / 255) < prob;
}

void Endpoint::set_validated_address(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->validated = true;
}

bool Endpoint::is_validated_address(const SocketAddress& addr) const {
  auto info = addrLRU_.Peek(addr);
  return info != nullptr ? info->validated : false;
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

size_t Endpoint::current_socket_address_count(
    const SocketAddress& addr) const {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  return counts != nullptr ? counts->active_connections : 0;
}

size_t Endpoint::current_stateless_reset_count(
    const SocketAddress& addr) const {
  SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(addr);
  return counts != nullptr ? counts->reset_count : 0;
}

SocketAddress Endpoint::local_address() const {
  return udp_.local_address();
}

Local<FunctionTemplate> Endpoint::UDP::GetConstructorTemplate(
    Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  Local<FunctionTemplate> tmpl = state->udp_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->Inherit(HandleWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        HandleWrap::kInternalFieldCount);
    tmpl->SetClassName(
        FIXED_ONE_BYTE_STRING(env->isolate(), "Session::UDP"));
    state->set_udp_constructor_template(env, tmpl);
  }
  return tmpl;
}

BaseObjectPtr<Endpoint::UDP> Endpoint::UDP::Create(
    Environment* env,
    Endpoint* endpoint) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return BaseObjectPtr<Endpoint::UDP>();
  }

  return MakeDetachedBaseObject<Endpoint::UDP>(env, obj, endpoint);
}

Endpoint::UDP::UDP(
    Environment* env,
    Local<Object> obj,
    Endpoint* endpoint)
    : HandleWrap(
          env,
          obj,
          reinterpret_cast<uv_handle_t*>(&handle_),
          AsyncWrap::PROVIDER_QUICENDPOINT),
      endpoint_(endpoint) {
  CHECK_EQ(uv_udp_init(env->event_loop(), &handle_), 0);
  handle_.data = this;
}

SocketAddress Endpoint::UDP::local_address() const {
  return SocketAddress::FromSockName(handle_);
}

int Endpoint::UDP::Bind(const SocketAddress& address, int flags) {
  return uv_udp_bind(&handle_, address.data(), flags);
}

void Endpoint::UDP::Close() {
  if (is_closing()) return;
  env()->CloseHandle(reinterpret_cast<uv_handle_t*>(&handle_), ClosedCb);
}

void Endpoint::UDP::ClosedCb(uv_handle_t* handle) {
  std::unique_ptr<UDP> ptr(
      ContainerOf(&Endpoint::UDP::handle_,
                  reinterpret_cast<uv_udp_t*>(handle)));
}

void Endpoint::UDP::Ref() {
  uv_ref(reinterpret_cast<uv_handle_t*>(&handle_));
}

void Endpoint::UDP::Unref() {
  uv_unref(reinterpret_cast<uv_handle_t*>(&handle_));
}

int Endpoint::UDP::StartReceiving() {
  if (IsHandleClosing()) return UV_EBADF;
  int err = uv_udp_recv_start(&handle_, OnAlloc, OnReceive);
  if (err == UV_EALREADY)
    err = 0;
  return err;
}

int Endpoint::UDP::StopReceiving() {
  if (IsHandleClosing()) return UV_EBADF;
  return uv_udp_recv_stop(&handle_);
}

int Endpoint::UDP::SendPacket(BaseObjectPtr<SendWrap> req) {
  CHECK(req);
  // Attach a strong pointer to the UDP instance to
  // ensure that it is not freed until all of the
  // dispatched SendWraps are freed.
  req->Attach(BaseObjectPtr<BaseObject>(this));
  uv_buf_t buf = req->packet()->buf();
  const sockaddr* dest = req->destination().data();
  return req->Dispatch(
      uv_udp_send,
      &handle_,
      &buf, 1,
      dest,
      uv_udp_send_cb{[](uv_udp_send_t* req, int status) {
        std::unique_ptr<SendWrap> ptr(
          static_cast<SendWrap*>(UdpSendWrap::from_req(req)));
        ptr->Done(status);
      }});
}

void Endpoint::UDP::OnAlloc(
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf) {
  UDP* udp =
      ContainerOf(
        &Endpoint::UDP::handle_,
        reinterpret_cast<uv_udp_t*>(handle));
  *buf = udp->endpoint_->OnAlloc(suggested_size);
}

void Endpoint::UDP::OnReceive(
    uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const sockaddr* addr,
    unsigned int flags) {
  UDP* udp = ContainerOf(&Endpoint::UDP::handle_, handle);
  if (nread < 0) {
    udp->endpoint_->ProcessReceiveFailure(static_cast<int>(nread));
    return;
  }

  if (UNLIKELY(flags & UV_UDP_PARTIAL)) {
    udp->endpoint_->ProcessReceiveFailure(UV_ENOBUFS);
    return;
  }

  udp->endpoint_->OnReceive(
      static_cast<size_t>(nread),
      *buf,
      SocketAddress(addr));
}

Endpoint::UDPHandle::UDPHandle(
    Environment* env,
    Endpoint* endpoint)
    : env_(env),
      udp_(Endpoint::UDP::Create(env, endpoint)) {
  CHECK(udp_);
  env->AddCleanupHook(CleanupHook, this);
}

void Endpoint::UDPHandle::Close() {
  if (udp_) {
    env_->RemoveCleanupHook(CleanupHook, this);
    udp_->Close();
  }
  udp_.reset();
}

void Endpoint::UDPHandle::MemoryInfo(MemoryTracker* tracker) const {
  if (udp_)
    tracker->TrackField("udp", udp_);
}

void Endpoint::UDPHandle::CleanupHook(void* data) {
  static_cast<UDPHandle*>(data)->Close();
}

bool EndpointWrap::HasInstance(Environment* env, Local<Value> value) {
  return GetConstructorTemplate(env)->HasInstance(value);
}

Local<FunctionTemplate> EndpointWrap::GetConstructorTemplate(
    Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  Local<FunctionTemplate> tmpl = state->endpoint_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = env->NewFunctionTemplate(IllegalConstructor);
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "Endpoint"));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        EndpointWrap::kInternalFieldCount);
    env->SetProtoMethod(
        tmpl,
        "listen",
        StartListen);
    env->SetProtoMethod(
        tmpl,
        "waitingForPendingCallbacks",
        StartWaitForPendingCallbacks);
    state->set_endpoint_constructor_template(env, tmpl);
  }
  return tmpl;
}

void EndpointWrap::Initialize(Environment* env, Local<Object> target) {
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

void EndpointWrap::CreateEndpoint(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  CHECK(ConfigObject::HasInstance(env, args[0]));
  ConfigObject* config;
  ASSIGN_OR_RETURN_UNWRAP(&config, args[0]);

  BaseObjectPtr<EndpointWrap> endpoint = Create(env, config->config());
  if (endpoint)
    args.GetReturnValue().Set(endpoint->object());
}

void EndpointWrap::StartListen(const FunctionCallbackInfo<Value>& args) {
  EndpointWrap* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  CHECK(OptionsObject::HasInstance(env, args[0]));
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args[0].As<Object>());
  endpoint->Listen(options->options());
}

void EndpointWrap::StartWaitForPendingCallbacks(
    const FunctionCallbackInfo<Value>& args) {
  EndpointWrap* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  endpoint->WaitForPendingCallbacks();
}

BaseObjectPtr<EndpointWrap> EndpointWrap::Create(
    Environment* env,
    const Endpoint::Config& config) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return BaseObjectPtr<EndpointWrap>();
  }

  return MakeBaseObject<EndpointWrap>(env, obj, config);
}

BaseObjectPtr<EndpointWrap> EndpointWrap::Create(
    Environment* env,
    std::shared_ptr<Endpoint> endpoint) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return BaseObjectPtr<EndpointWrap>();
  }

  return MakeBaseObject<EndpointWrap>(env, obj, std::move(endpoint));
}

EndpointWrap::EndpointWrap(
    Environment* env,
    Local<Object> object,
    const Endpoint::Config& config)
    : EndpointWrap(
          env,
          object,
          std::make_shared<Endpoint>(env, config)) {}

EndpointWrap::EndpointWrap(
    Environment* env,
    v8::Local<v8::Object> object,
    std::shared_ptr<Endpoint> inner)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUICENDPOINT),
      state_(env),
      inner_(std::move(inner)),
      close_signal_(env, [this]() { Close(); }),
      inbound_signal_(env, [this]() { ProcessInbound(); }),
      initial_signal_(env, [this]() { ProcessInitial(); }) {
  MakeWeak();

  Debug(this, "New QUIC endpoint created");

  close_signal_.Unref();
  inbound_signal_.Unref();
  initial_signal_.Unref();

  Endpoint::Lock lock(inner_);
  inner_->AddCloseListener(this);

  // TODO(@jasnell): Re-enable
  // object->DefineOwnProperty(
  //     env->context(),
  //     env->block_list_string(),
  //     block_list_->object(),
  //     PropertyAttribute::ReadOnly).Check();

  object->DefineOwnProperty(
      env->context(),
      env->state_string(),
      state_.GetArrayBuffer(),
      PropertyAttribute::ReadOnly).Check();

  object->DefineOwnProperty(
      env->context(),
      env->stats_string(),
      inner_->ToBigUint64Array(env),
      PropertyAttribute::ReadOnly).Check();
}

EndpointWrap::~EndpointWrap() {
  CHECK(sessions_.empty());
  Debug(this, "Destroying");
  if (inner_) {
    Endpoint::Lock lock(inner_);
    inner_->RemoveCloseListener(this);
    inner_->RemoveInitialPacketListener(this);
    inner_->DebugStats(this);
  }

  close_signal_.Close();
  inbound_signal_.Close();
  initial_signal_.Close();
}

void EndpointWrap::EndpointClosed(
    Endpoint::CloseListener::Context context,
    int status) {
  close_context_ = context;
  close_status_ = status;
  // TODO(@jasnell): Need to capture the statistics...
  close_signal_.Send();
}

// The underlying endpoint has been closed. Clean everything up and notify.
// No further packets will be sent at this point. This can happen abruptly
// so we have to make sure we cycle out through the JavaScript side to free
// up everything there.
void EndpointWrap::Close() {
  HandleScope scope(env()->isolate());
  v8::Context::Scope context_scope(env()->context());
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  // If the Environment is being torn down, then there's nothing more we can do.
  if (state == nullptr || !env()->can_call_into_js())
    return;
  Local<Value> argv[] = {
    Integer::NewFromUnsigned(
        env()->isolate(),
        static_cast<uint32_t>(close_context_)),
    Integer::New(env()->isolate(), close_status_)
  };
  BaseObjectPtr<EndpointWrap> ptr(this);
  MakeCallback(state->endpoint_close_callback(env()), arraysize(argv), argv);
}

void EndpointWrap::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("endpoint", inner_);
  tracker->TrackField("sessions", sessions_);
}

void EndpointWrap::AddSession(const CID& cid, BaseObjectPtr<Session> session) {
  sessions_[cid] = session;
  Endpoint::Lock lock(inner_);
  inner_->AssociateCID(cid, this);
  inner_->IncrementSocketAddressCounter(session->remote_address());
  inner_->IncrementStat(
      session->is_server()
          ? &EndpointStats::server_sessions
          : &EndpointStats::client_sessions);
}

void EndpointWrap::AssociateCID(const CID& cid, const CID& scid) {
  if (cid && scid) {
    Debug(this, "Associating cid %s with %s", cid, scid);
    dcid_to_scid_[cid] = scid;
    Endpoint::Lock lock(inner_);
    inner_->AssociateCID(cid, this);
  }
}

void EndpointWrap::AssociateStatelessResetToken(
    const StatelessResetToken& token,
    BaseObjectPtr<Session> session) {
  Debug(this, "Associating stateless reset token %s", token);
  token_map_[token] = session;
  Endpoint::Lock lock(inner_);
  inner_->AssociateStatelessResetToken(token, this);
}

void EndpointWrap::DisassociateCID(const CID& cid) {
  if (cid) {
    Debug(this, "Removing association for cid %s", cid);
    dcid_to_scid_.erase(cid);
    Endpoint::Lock lock(inner_);
    inner_->DisassociateCID(cid);
  }
}

void EndpointWrap::DisassociateStatelessResetToken(
    const StatelessResetToken& token) {
  Debug(this, "Removing stateless reset token %s", token);
  Endpoint::Lock lock(inner_);
  inner_->DisassociateStatelessResetToken(token);
}

BaseObjectPtr<Session> EndpointWrap::FindSession(const CID& cid) {
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

uint32_t EndpointWrap::GetFlowLabel(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    const CID& cid) {
  return inner_->GetFlowLabel(local_address, remote_address, cid);
}

void EndpointWrap::ImmediateConnectionClose(
    uint32_t version,
    const CID& scid,
    const CID& dcid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    int64_t reason) {
  Debug(this, "Sending stateless connection close to %s", scid);
  inner_->ImmediateConnectionClose(
      version,
      scid,
      dcid,
      local_addr,
      remote_addr,
      reason);
}

void EndpointWrap::Listen(const Session::Options& options) {
  if (state_->listening == 1) return;
  CHECK(options.context);
  Debug(this, "Starting to listen");
  server_options_ = options;
  state_->listening = 1;
  Endpoint::Lock lock(inner_);
  inner_->AddInitialPacketListener(this);
}

void EndpointWrap::OnEndpointDone() {
  HandleScope scope(env()->isolate());
  v8::Context::Scope context_scope(env()->context());
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  MakeCallback(state->endpoint_done_callback(env()), 0, nullptr);
}

void EndpointWrap::OnError() {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  v8::Context::Scope context_scope(env()->context());
  MakeCallback(state->endpoint_error_callback(env()), 0, nullptr);
}

void EndpointWrap::OnNewSession(const BaseObjectPtr<Session>& session) {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  Local<Value> arg = session->object();
  v8::Context::Scope context_scope(env()->context());
  MakeCallback(state->session_new_callback(env()), 1, &arg);
}

void EndpointWrap::OnSendDone(int status) {
  DecrementPendingCallbacks();
  if (is_done_waiting_for_callbacks())
    OnEndpointDone();
}

bool EndpointWrap::Accept(
    const Session::Config& config,
    std::shared_ptr<v8::BackingStore> store,
    size_t nread,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr) {

  {
    Mutex::ScopedLock lock(inbound_mutex_);
    initial_.emplace_back(InitialPacket {
      config,
      std::move(store),
      nread,
      local_addr,
      remote_addr
    });
  }
  initial_signal_.Send();
  return true;
}

void EndpointWrap::ProcessInitial() {
  InitialPacket::Queue queue;
  {
    Mutex::ScopedLock lock(inbound_mutex_);
    initial_.swap(queue);
  }

  while (!queue.empty()) {
    InitialPacket packet = queue.front();
    queue.pop_front();

    BaseObjectPtr<Session> session =
        Session::CreateServer(
            this,
            packet.local_address,
            packet.remote_address,
            packet.config,
            server_options_);

    if (!session)
      return ProcessInitialFailure();

    session->Receive(
        packet.nread,
        std::move(packet.store),
        packet.local_address,
        packet.remote_address);
  }
}

void EndpointWrap::ProcessInitialFailure() {
  // TODO(@jasnell): Generate an error to report
  OnError();
}

bool EndpointWrap::Receive(
    const CID& dcid,
    const CID& scid,
    std::shared_ptr<v8::BackingStore> store,
    size_t nread,
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    Endpoint::PacketListener::Flags flags) {
  {
    Mutex::ScopedLock lock(inbound_mutex_);
    inbound_.emplace_back(InboundPacket{
      dcid,
      scid,
      std::move(store),
      nread,
      local_address,
      remote_address,
      flags
    });
  }
  inbound_signal_.Send();
  return true;
}

void EndpointWrap::ProcessInbound() {
  InboundPacket::Queue queue;
  {
    Mutex::ScopedLock lock(inbound_mutex_);
    inbound_.swap(queue);
  }

  while (!queue.empty()) {
    InboundPacket packet = queue.front();
    queue.pop_front();

    inner_->IncrementStat(&EndpointStats::bytes_received, packet.nread);
    BaseObjectPtr<Session> session = FindSession(packet.dcid);
    if (session && !session->is_destroyed()) {
      session->Receive(
        packet.nread,
        std::move(packet.store),
        packet.local_address,
        packet.remote_address);
    }
  }
}

void EndpointWrap::RemoveSession(const CID& cid, const SocketAddress& addr) {
  sessions_.erase(cid);
  Endpoint::Lock lock(inner_);
  inner_->DisassociateCID(cid);
  inner_->DecrementSocketAddressCounter(addr);
}

void EndpointWrap::SendPacket(
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    std::unique_ptr<Packet> packet,
    BaseObjectPtr<Session> session) {
  if (UNLIKELY(packet->length() == 0))
    return;

  Debug(this, "Sending %" PRIu64 " bytes to %s from %s (label: %s)",
        packet->length(),
        remote_addr,
        local_addr,
        packet->diagnostic_label());

  BaseObjectPtr<Endpoint::SendWrap> wrap =
      Endpoint::SendWrap::Create(
          env(),
          remote_addr,
          std::move(packet),
          BaseObjectPtr<EndpointWrap>(this));
  if (!wrap) {
    // TODO(@jasnell): Process error
    return;
  }

  IncrementPendingCallbacks();
  inner_->SendPacket(std::move(wrap));
}

bool EndpointWrap::SendRetry(
    uint32_t version,
    const CID& dcid,
    const CID& scid,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr) {
  return inner_->SendRetry(version, dcid, scid, local_addr, remote_addr);
}

void EndpointWrap::WaitForPendingCallbacks() {
  if (!is_done_waiting_for_callbacks()) {
    OnEndpointDone();
    return;
  }
  state_->waiting_for_callbacks = 1;
}

std::unique_ptr<worker::TransferData> EndpointWrap::CloneForMessaging() const {
  return std::make_unique<TransferData>(inner_);
}

BaseObjectPtr<BaseObject> EndpointWrap::TransferData::Deserialize(
    Environment* env,
    v8::Local<v8::Context> context,
    std::unique_ptr<worker::TransferData> self) {
  return EndpointWrap::Create(env, std::move(inner_));
}

void EndpointWrap::TransferData::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("inner", inner_);
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
