#include "bindingdata-inl.h"
#include "cid-inl.h"
#include "cryptocontext-inl.h"
#include "defs.h"
#include "endpoint.h"
#include "session-inl.h"
#include "sessionticket.h"
#include "statelessresettoken-inl.h"
#include "util-inl.h"
#include "util.h"
#include <aliased_struct-inl.h>
#include <async_wrap-inl.h>
#include <memory_tracker-inl.h>
#include <node_sockaddr-inl.h>
#include <req_wrap-inl.h>
#include <uv.h>
#include <v8.h>
#include <optional>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

namespace node {

using v8::BackingStore;
using v8::BigInt;
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
using v8::Uint32;
using v8::Value;

namespace quic {

// ======================================================================================
// Endpoint::Options and OptionsObject

namespace {
class OptionsObject final : public BaseObject {
  public:
  HAS_INSTANCE()
  GET_CONSTRUCTOR_TEMPLATE()
  static void Initialize(Environment* env, Local<Object> target);
  static void RegisterExternalReferences(ExternalReferenceRegistry* registry);

  OptionsObject(Environment* env, Local<Object> object);

  operator const Endpoint::Options&() const;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(OptionsObject)
  SET_SELF_SIZE(OptionsObject)

  private:
  static void New(const FunctionCallbackInfo<Value>& args);
  static void GenerateResetTokenSecret(
      const FunctionCallbackInfo<Value>& args);
  static void SetResetTokenSecret(
      const FunctionCallbackInfo<Value>& args);
  static void GenerateTokenSecret(
      const FunctionCallbackInfo<Value>& args);
  static void SetTokenSecret(
      const FunctionCallbackInfo<Value>& args);

  template <typename T>
  bool SetOption(const Local<Object>& object,
                  const Local<String>& name,
                  T Endpoint::Options::*member);

  Endpoint::Options options_;
};

OptionsObject::operator const Endpoint::Options& () const { return options_; }

Local<FunctionTemplate> OptionsObject::GetConstructorTemplate(
    Environment* env) {
  auto& state = BindingData::Get(env);
  auto tmpl = state.endpoint_config_constructor_template();
  if (tmpl.IsEmpty()) {
    auto isolate = env->isolate();
    tmpl = NewFunctionTemplate(isolate, New);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(kInternalFieldCount);
    tmpl->SetClassName(state.endpoint_options_string());
    SetProtoMethod(
        isolate, tmpl, "generateResetTokenSecret", GenerateResetTokenSecret);
    SetProtoMethod(isolate, tmpl, "setResetTokenSecret", SetResetTokenSecret);
    SetProtoMethod(
        isolate, tmpl, "generateTokenSecret", GenerateTokenSecret);
    SetProtoMethod(isolate, tmpl, "setTokenSecret", SetTokenSecret);
    state.set_endpoint_config_constructor_template(tmpl);
  }
  return tmpl;
}

void OptionsObject::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  registry->Register(New);
  registry->Register(GenerateResetTokenSecret);
  registry->Register(SetResetTokenSecret);
  registry->Register(GenerateTokenSecret);
  registry->Register(SetTokenSecret);
}

void OptionsObject::Initialize(Environment* env,
                                         Local<Object> target) {
  SetConstructorFunction(env->context(),
                         target,
                         "EndpointOptions",
                         GetConstructorTemplate(env),
                         SetConstructorFunctionFlag::NONE);
}

template <>
bool OptionsObject::SetOption<uint64_t>(
    const Local<Object>& object,
    const Local<String>& name,
    uint64_t Endpoint::Options::*member) {
  Local<Value> value;
  if (UNLIKELY(!object->Get(env()->context(), name).ToLocal(&value)))
    return false;

  if (!value->IsUndefined()) {
    CHECK_IMPLIES(!value->IsBigInt(), value->IsNumber());

    uint64_t val = 0;
    if (value->IsBigInt()) {
      bool lossless = true;
      val = value.As<BigInt>()->Uint64Value(&lossless);
      if (!lossless) {
        Utf8Value label(env()->isolate(), name);
        THROW_ERR_OUT_OF_RANGE(
            env(),
            (std::string("options.") + (*label) + " is out of range").c_str());
        return false;
      }
    } else {
      val = static_cast<int64_t>(value.As<Number>()->Value());
    }
    options_.*member = val;
  }
  return true;
}

template <>
bool OptionsObject::SetOption<uint32_t>(
    const Local<Object>& object,
    const Local<String>& name,
    uint32_t Endpoint::Options::*member) {
  Local<Value> value;
  if (UNLIKELY(!object->Get(env()->context(), name).ToLocal(&value)))
    return false;

  if (!value->IsUndefined()) {

    CHECK(value->IsUint32());

    uint32_t val = value.As<Uint32>()->Value();
    options_.*member = val;
  }
  return true;
}

template <>
bool OptionsObject::SetOption<uint8_t>(
    const Local<Object>& object,
    const Local<String>& name,
    uint8_t Endpoint::Options::*member) {
  Local<Value> value;
  if (UNLIKELY(!object->Get(env()->context(), name).ToLocal(&value)))
    return false;

  if (!value->IsUndefined()) {
    CHECK(value->IsUint32());

    uint32_t val = value.As<Uint32>()->Value();
    if (val > 255) return false;
    options_.*member = static_cast<uint8_t>(val);
  }
  return true;
}

template <>
bool OptionsObject::SetOption<double>(
    const Local<Object>& object,
    const Local<String>& name,
    double Endpoint::Options::*member) {
  Local<Value> value;
  if (UNLIKELY(!object->Get(env()->context(), name).ToLocal(&value)))
    return false;

  if (!value->IsUndefined()) {
    CHECK(value->IsNumber());
    double val = value.As<Number>()->Value();
    options_.*member = val;
  }
  return true;
}

template <>
bool OptionsObject::SetOption<ngtcp2_cc_algo>(
    const Local<Object>& object,
    const Local<String>& name,
    ngtcp2_cc_algo Endpoint::Options::*member) {
  Local<Value> value;
  if (UNLIKELY(!object->Get(env()->context(), name).ToLocal(&value)))
    return false;

  if (!value->IsUndefined()) {
    ngtcp2_cc_algo val = static_cast<ngtcp2_cc_algo>(value.As<Int32>()->Value());
    switch (val) {
      case NGTCP2_CC_ALGO_CUBIC:
        // Fall through
      case NGTCP2_CC_ALGO_RENO:
        // Fall through
      case NGTCP2_CC_ALGO_BBR:
        // Fall through
      case NGTCP2_CC_ALGO_BBR2:
        options_.*member = val;
        break;
      default:
        return false;
    }
  }

  return true;
}

template <>
bool OptionsObject::SetOption<bool>(
    const Local<Object>& object,
    const Local<String>& name,
    bool Endpoint::Options::*member) {
  Local<Value> value;
  if (UNLIKELY(!object->Get(env()->context(), name).ToLocal(&value)))
    return false;
  if (!value->IsUndefined()) {
    CHECK(value->IsBoolean());
    options_.*member = value->IsTrue();
  }
  return true;
}

void OptionsObject::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  auto env = Environment::GetCurrent(args);
  auto& state = BindingData::Get(env);
  auto options = new OptionsObject(env, args.This());
  options->options_.GenerateResetTokenSecret();

  CHECK(SocketAddressBase::HasInstance(env, args[0]));
  SocketAddressBase* address;
  ASSIGN_OR_RETURN_UNWRAP(&address, args[0]);

  options->options_.local_address = *address->address();

#define SET(key)                                                               \
  options->SetOption(object, state.key##_string(), &Endpoint::Options::key)

  if (LIKELY(args[1]->IsObject())) {
    auto object = args[1].As<Object>();
    if (!SET(retry_token_expiration) ||
        !SET(token_expiration) ||
        !SET(max_window_override) ||
        !SET(max_stream_window_override) ||
        !SET(max_connections_per_host) ||
        !SET(max_connections_total) ||
        !SET(max_stateless_resets) ||
        !SET(address_lru_size) ||
        !SET(retry_limit) ||
        !SET(max_payload_size) ||
        !SET(unacknowledged_packet_threshold) ||
        !SET(validate_address) ||
        !SET(disable_stateless_reset) ||
        !SET(rx_loss) ||
        !SET(tx_loss) ||
        !SET(cc_algorithm) ||
        !SET(ipv6_only) ||
        !SET(udp_receive_buffer_size) ||
        !SET(udp_send_buffer_size) ||
        !SET(udp_ttl)) {
      // The if block intentionally does nothing. The code is structured like
      // this to shortcircuit if any of the SetOptions() returns false signaling
      // that an error occurred.
    }
  }

#undef SET
}

void OptionsObject::GenerateResetTokenSecret(
    const FunctionCallbackInfo<Value>& args) {
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());
  options->options_.GenerateResetTokenSecret();
}

void OptionsObject::SetResetTokenSecret(
    const FunctionCallbackInfo<Value>& args) {
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());

  crypto::ArrayBufferOrViewContents<uint8_t> secret(args[0]);
  CHECK_EQ(secret.size(), TOKEN_SECRET_LENGTH);
  memcpy(options->options_.reset_token_secret, secret.data(), secret.size());
}

void OptionsObject::GenerateTokenSecret(
    const FunctionCallbackInfo<Value>& args) {
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());
  options->options_.GenerateTokenSecret();
}

void OptionsObject::SetTokenSecret(
    const FunctionCallbackInfo<Value>& args) {
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());

  crypto::ArrayBufferOrViewContents<uint8_t> secret(args[0]);
  CHECK_EQ(secret.size(), TOKEN_SECRET_LENGTH);
  memcpy(options->options_.token_secret, secret.data(), secret.size());
}

OptionsObject::OptionsObject(Environment* env, Local<Object> object)
    : BaseObject(env, object) {
  MakeWeak();
}

void OptionsObject::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
}
}

Endpoint::Options::Options() {
  GenerateResetTokenSecret();
  GenerateTokenSecret();
}

void Endpoint::Options::GenerateResetTokenSecret() {
  CHECK(crypto::CSPRNG(reinterpret_cast<unsigned char*>(&reset_token_secret),
                       arraysize(reset_token_secret)).is_ok());
}

void Endpoint::Options::GenerateTokenSecret() {
  CHECK(crypto::CSPRNG(reinterpret_cast<unsigned char*>(&token_secret),
                       arraysize(reset_token_secret)).is_ok());
}

// ======================================================================================
// Endpoint::UDP and Endpoint::UDP::Impl

class Endpoint::UDP::Impl final : public HandleWrap {
 public:
  static Local<FunctionTemplate> GetConstructorTemplate(Environment* env) {
    auto& state = BindingData::Get(env);
    auto tmpl = state.udp_constructor_template();
    if (tmpl.IsEmpty()) {
      tmpl = NewFunctionTemplate(env->isolate(), IllegalConstructor);
      tmpl->Inherit(HandleWrap::GetConstructorTemplate(env));
      tmpl->InstanceTemplate()->SetInternalFieldCount(
          HandleWrap::kInternalFieldCount);
      tmpl->SetClassName(state.endpoint_udp_string());
      state.set_udp_constructor_template(tmpl);
    }
    return tmpl;
  }

  static BaseObjectPtr<Impl> Create(Endpoint* endpoint) {
    Local<Object> obj;
    if (UNLIKELY(!GetConstructorTemplate(endpoint->env())
                      ->InstanceTemplate()
                      ->NewInstance(endpoint->env()->context())
                      .ToLocal(&obj))) {
      return BaseObjectPtr<Impl>();
    }

    return MakeBaseObject<Impl>(endpoint, obj);
  }

  static Impl* From(uv_udp_t* handle) {
    return ContainerOf(&Impl::handle_, handle);
  }

  static Impl* From(uv_handle_t* handle) {
    return From(reinterpret_cast<uv_udp_t*>(handle));
  }

  Impl(Endpoint* endpoint, Local<Object> object)
      : HandleWrap(endpoint->env(),
                   object,
                   reinterpret_cast<uv_handle_t*>(&handle_),
                   AsyncWrap::PROVIDER_QUIC_UDP),
        endpoint_(endpoint) {
    CHECK_EQ(uv_udp_init(endpoint->env()->event_loop(), &handle_), 0);
    handle_.data = this;
  }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(Endpoint::UDP::Impl)
  SET_SELF_SIZE(Impl)

 private:
  static void ClosedCb(uv_handle_t* handle) {
    std::unique_ptr<Impl> ptr(From(handle));
  }

  static void OnAlloc(uv_handle_t* handle,
                      size_t suggested_size,
                      uv_buf_t* buf) {
    *buf = From(handle)->env()->allocate_managed_buffer(suggested_size);
  }

  static void OnReceive(uv_udp_t* handle,
                        ssize_t nread,
                        const uv_buf_t* buf,
                        const sockaddr* addr,
                        unsigned int flags) {
    // Nothing to do it in this case.
    if (nread == 0) return;

    Impl* impl = From(handle);

    CHECK_NOT_NULL(impl);
    CHECK_NOT_NULL(impl->endpoint_);

    if (nread < 0) {
      impl->endpoint_->Destroy(CloseContext::RECEIVE_FAILURE,
                               static_cast<int>(nread));
      return;
    }

    if (UNLIKELY(flags & UV_UDP_PARTIAL)) {
      impl->endpoint_->Destroy(CloseContext::RECEIVE_FAILURE, UV_ENOBUFS);
      return;
    }

    impl->endpoint_->Receive(
        static_cast<size_t>(nread), *buf, SocketAddress(addr));
  }

  uv_udp_t handle_;
  Endpoint* endpoint_;

  friend class UDP;
};

Endpoint::UDP::UDP(Endpoint* endpoint)
    : impl_(Impl::Create(endpoint)) {
  endpoint->env()->AddCleanupHook(CleanupHook, this);
}

Endpoint::UDP::~UDP() { Close(); }

int Endpoint::UDP::Bind(const Endpoint::Options& options) {
  if (is_closed() || impl_->IsHandleClosing()) return UV_EBADF;

  int flags = 0;
  if (options.local_address.family() == AF_INET6 && options.ipv6_only)
    flags |= UV_UDP_IPV6ONLY;
  int err = uv_udp_bind(&impl_->handle_, options.local_address.data(), flags);
  int size;

  if (!err) {
    size = static_cast<int>(options.udp_receive_buffer_size);
    if (size > 0) {
      err = uv_recv_buffer_size(reinterpret_cast<uv_handle_t*>(&impl_->handle_),
                                &size);
      if (err) return err;
    }

    size = static_cast<int>(options.udp_send_buffer_size);
    if (size > 0) {
      err = uv_send_buffer_size(reinterpret_cast<uv_handle_t*>(&impl_->handle_),
                                &size);
      if (err) return err;
    }

    size = static_cast<int>(options.udp_ttl);
    if (size > 0) {
      err = uv_udp_set_ttl(&impl_->handle_, size);
      if (err) return err;
    }
  }

  return err;
}

void Endpoint::UDP::Ref() {
  if (!is_closed()) uv_ref(reinterpret_cast<uv_handle_t*>(&impl_->handle_));
}

void Endpoint::UDP::Unref() {
  if (!is_closed()) uv_unref(reinterpret_cast<uv_handle_t*>(&impl_->handle_));
}

int Endpoint::UDP::Start() {
  if (is_closed() || impl_->IsHandleClosing()) return UV_EBADF;
  if (is_started) return 0;
  int err = uv_udp_recv_start(&impl_->handle_, Impl::OnAlloc, Impl::OnReceive);
  is_started = (err == 0);
  return err;
}

void Endpoint::UDP::Stop() {
  if (is_closed() || impl_->IsHandleClosing() || !is_started) return;
  USE(uv_udp_recv_stop(&impl_->handle_));
}

void Endpoint::UDP::Close() {
  if (is_closed() || impl_->IsHandleClosing()) return;
  Stop();
  impl_->env()->RemoveCleanupHook(CleanupHook, this);
  impl_->Close();
  impl_.reset();
}

bool Endpoint::UDP::is_closed() const { return !impl_; }
Endpoint::UDP::operator bool() const { return !impl_; }

std::optional<SocketAddress> Endpoint::UDP::local_address() const {
  if (is_closed()) return std::nullopt;
  return SocketAddress::FromSockName(impl_->handle_);
}

int Endpoint::UDP::Send(BaseObjectPtr<Packet> req) {
  if (is_closed() || impl_->IsHandleClosing()) return UV_EBADF;
  CHECK(req && !req->is_pending());
  req->Attach(impl_);
  uv_buf_t buf = *req;
  // The packet maintains a strong reference to itself to keep it from being
  // gc'd until the callback is invoked.

  return req->Dispatch(uv_udp_send,
                       &impl_->handle_,
                       &buf, 1,
                       req->destination().data(),
                       uv_udp_send_cb{[](uv_udp_send_t* req, int status) {
                         BaseObjectPtr<Packet> ptr(
                             static_cast<Packet*>(ReqWrap<uv_udp_send_t>::from_req(req)));
                         ptr->Done(status);
                       }});
}

void Endpoint::UDP::MemoryInfo(MemoryTracker* tracker) const {
  if (impl_) tracker->TrackField("impl", impl_);
}

void Endpoint::UDP::CleanupHook(void* data) {
  static_cast<UDP*>(data)->Close();
}

// ======================================================================================
// Endpoint

namespace {

// A RETRY packet communicates a retry token to the client. Retry tokens are
// generated only by QUIC servers for the purpose of validating the network path
// between a client and server. The content payload of the RETRY packet is
// opaque to the clientand must not be guessable by on- or off-path attackers.
//
// A QUIC server sends a RETRY token as a way of initiating explicit path
// validation in response to an initial QUIC packet. The client, upon receiving
// a RETRY, must abandon the initial connection attempt and try again with the
// received retry token included with the new initial packet sent to the server.
// If the server is performing explicit validation, it will look for the
// presence of the retry token and attempt to validate it if found. The internal
// structure of the retry token must be meaningful to the server, and the server
// must be able to validate that the token is correct without relying on any
// state left over from the previous connection attempt. We use an
// implementation that is provided by ngtcp2.
//
// The token secret must be kept secret on the QUIC server that generated the
// retry. When multiple QUIC servers are used in a cluster, it cannot be
// guaranteed that the same QUIC server instance will receive the subsequent new
// Initial packet. Therefore, all QUIC servers in the cluster should either
// share or be aware of the same token secret or a mechanism needs to be
// implemented to ensure that subsequent packets are routed to the same QUIC
// server instance.
//
// A malicious peer could attempt to guess the token secret by sending a large
// number specially crafted RETRY-eliciting packets to a server then analyzing
// the resulting retry tokens. To reduce the possibility of such attacks, the
// current implementation of QuicSocket generates the token secret randomly for
// each instance, and the number of RETRY responses sent to a given remote
// address should be limited. Such attacks should be of little actual value in
// most cases. In cases where the secret is shared across multiple servers, be
// sure to implement a mechanism to rotate those.

// Validates a retry token, returning the original CID extracted from the token
// if it is valid.
std::optional<CID> ValidateRetryToken(quic_version version,
                                      const ngtcp2_vec& token,
                                      const SocketAddress& addr,
                                      const CID& dcid,
                                      const uint8_t* token_secret,
                                      uint64_t verification_expiration) {
  ngtcp2_cid ocid;
  int ret = ngtcp2_crypto_verify_retry_token(&ocid,
                                             token.base,
                                             token.len,
                                             token_secret,
                                             TOKEN_SECRET_LENGTH,
                                             version,
                                             addr.data(),
                                             addr.length(),
                                             dcid,
                                             verification_expiration,
                                             uv_hrtime());
  if (ret != 0) return std::nullopt;
  return CID(ocid);
}

// Generates a RETRY packet.
bool GenerateRetryPacket(const BaseObjectPtr<Packet>& packet,
                         const uint8_t* token_secret,
                         const Endpoint::PathDescriptor& options) {
  uint8_t token[256];
  auto cid = CIDFactory::random().Generate(NGTCP2_MAX_CIDLEN);

  auto ret = ngtcp2_crypto_generate_retry_token(token,
                                                token_secret,
                                                TOKEN_SECRET_LENGTH,
                                                options.version,
                                                options.remote_address.data(),
                                                options.remote_address.length(),
                                                cid,
                                                options.dcid,
                                                uv_hrtime());
  if (ret == -1) return false;

  size_t tokenlen = ret;
  size_t pktlen = tokenlen + (2 * NGTCP2_MAX_CIDLEN) + options.scid.length() + 8;

  ngtcp2_vec vec = *packet;

  ssize_t nwrite = ngtcp2_crypto_write_retry(vec.base,
                                             pktlen,
                                             options.version,
                                             options.scid,
                                             cid,
                                             options.dcid,
                                             token,
                                             tokenlen);
  if (nwrite <= 0) return false;

  packet->Truncate(nwrite);
  return true;
}
}

Local<FunctionTemplate> Endpoint::GetConstructorTemplate(Environment* env) {
  auto& state = BindingData::Get(env);
  auto tmpl = state.endpoint_constructor_template();
  if (tmpl.IsEmpty()) {
    auto isolate = env->isolate();
    tmpl = NewFunctionTemplate(isolate, IllegalConstructor);
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->SetClassName(state.endpoint_string());
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Endpoint::kInternalFieldCount);
    SetProtoMethod(isolate, tmpl, "listen", DoListen);
    SetProtoMethod(isolate, tmpl, "closeGracefully", DoCloseGracefully);
    SetProtoMethod(isolate, tmpl, "connect", DoConnect);
    SetProtoMethod(isolate, tmpl, "markBusy", MarkBusy);
    SetProtoMethod(isolate, tmpl, "ref", Ref);
    SetProtoMethod(isolate, tmpl, "unref", Unref);
    SetProtoMethodNoSideEffect(isolate, tmpl, "address", LocalAddress);
    state.set_endpoint_constructor_template(tmpl);
  }
  return tmpl;
}

void Endpoint::Initialize(Environment* env, Local<Object> target) {
  SetMethod(env->context(), target, "createEndpoint", CreateEndpoint);

  OptionsObject::Initialize(env, target);

#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATS_ENDPOINT_##name);
  ENDPOINT_STATS(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATS_ENDPOINT_COUNT);
#undef V
#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATE_ENDPOINT_##name);
  ENDPOINT_STATE(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATE_ENDPOINT_COUNT);
#undef V
}

void Endpoint::RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(IllegalConstructor);
  registry->Register(CreateEndpoint);
  registry->Register(DoConnect);
  registry->Register(DoListen);
  registry->Register(DoCloseGracefully);
  registry->Register(LocalAddress);
  registry->Register(Ref);
  registry->Register(Unref);
  OptionsObject::RegisterExternalReferences(registry);
}

BaseObjectPtr<Endpoint> Endpoint::Create(Environment* env,
                                         const Endpoint::Options& options) {
  Local<Object> obj;
  if (UNLIKELY(!GetConstructorTemplate(env)
                    ->InstanceTemplate()
                    ->NewInstance(env->context())
                    .ToLocal(&obj))) {
    return BaseObjectPtr<Endpoint>();
  }

  return MakeDetachedBaseObject<Endpoint>(env, obj, options);
}

Endpoint::Endpoint(Environment* env,
                   Local<Object> object,
                   const Endpoint::Options& options)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUIC_ENDPOINT),
      stats_(env),
      state_(env->isolate()),
      options_(options),
      udp_(this),
      addrLRU_(options.address_lru_size) {
  MakeWeak();

  const auto defineProperty = [&](auto name, auto value) {
    object
        ->DefineOwnProperty(
            env->context(), name, value, PropertyAttribute::ReadOnly)
        .Check();
  };

  defineProperty(env->state_string(), state_.GetArrayBuffer());
  defineProperty(env->stats_string(), stats_.ToBigUint64Array(env));
}

Endpoint::~Endpoint() {
  if (udp_) udp_.Close();
  CHECK_EQ(state_->pending_callbacks, 0);
  CHECK(sessions_.empty());
  CHECK(is_closed());
}

std::optional<SocketAddress> Endpoint::local_address() const {
  if (is_closed()) return std::nullopt;
  return udp_.local_address();
}

void Endpoint::MarkAsBusy(bool on) {
  if (!is_closed()) state_->busy = on ? 1 : 0;
}

Maybe<size_t> Endpoint::GenerateNewToken(quic_version version,
                                         uint8_t* token,
                                         const SocketAddress& remote_address) {
  if (is_closed() || is_closing()) return Nothing<size_t>();

  auto ret = ngtcp2_crypto_generate_regular_token(token,
                                                  options_.token_secret,
                                                  TOKEN_SECRET_LENGTH,
                                                  remote_address.data(),
                                                  remote_address.length(),
                                                  uv_hrtime());
  // A return value of -1 signals an error condition here so use of the
  // Maybe/Nothing/Just syntax is appropriate.
  if (ret == -1) return Nothing<size_t>();
  return Just(static_cast<size_t>(ret));
}

void Endpoint::AddSession(const CID& cid, BaseObjectPtr<Session> session) {
  if (is_closed() || is_closing()) return;
  sessions_[cid] = session;
  IncrementSocketAddressCounter(session->remote_address());
  if (session->is_server()) {
    stats_.Increment<&Stats::server_sessions>();
  } else {
    stats_.Increment<&Stats::client_sessions>();
  }
  if (session->is_server()) EmitNewSession(session);
}

void Endpoint::RemoveSession(const CID& cid, const SocketAddress& addr) {
  if (is_closed()) return;
  DecrementSocketAddressCounter(addr);
  sessions_.erase(cid);
  if (state_->waiting_for_callbacks == 1) MaybeDestroy();
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

void Endpoint::AssociateCID(const CID& cid, const CID& scid) {
  if (!is_closed() && !is_closing() && cid && scid && cid != scid &&
      dcid_to_scid_[cid] != scid) {
    dcid_to_scid_[cid] = scid;
  }
}

void Endpoint::DisassociateCID(const CID& cid) {
  if (!is_closed() && cid) dcid_to_scid_.erase(cid);
}

void Endpoint::AssociateStatelessResetToken(const StatelessResetToken& token,
                                            Session* session) {
  if (is_closed() || is_closing()) return;
  token_map_[token] = session;
}

void Endpoint::DisassociateStatelessResetToken(
    const StatelessResetToken& token) {
  if (!is_closed()) token_map_.erase(token);
}

void Endpoint::Send(BaseObjectPtr<Packet> packet) {
  if (is_closed() || is_closing() || packet->length() == 0) return;
  state_->pending_callbacks++;
  int err = udp_.Send(packet);

  if (err != 0) {
    packet->Done(err);
    Destroy(CloseContext::SEND_FAILURE, err);
  }
  stats_.Increment<&Stats::bytes_sent>(packet->length());
  stats_.Increment<&Stats::packets_sent>();
}

void Endpoint::SendRetry(const Endpoint::PathDescriptor& options) {
  auto info = addrLRU_.Upsert(options.remote_address);
  if (++(info->retry_count) <= options_.retry_limit) {
    // A retry packet will never be larger than the default 1200 so we're safe
    // not providing a size here...
    auto packet = Packet::Create(env(),
                                 this,
                                 options.remote_address,
                                 kDefaultMaxPacketLength,
                                 "retry");
    if (GenerateRetryPacket(packet, options_.token_secret, options))
      Send(std::move(packet));

    // If creating the retry is unsuccessful, we just drop things on the floor.
    // It's not worth committing any further resources to this one packet. We
    // might want to log the failure at some point tho.
  }
}

void Endpoint::SendVersionNegotiation(const PathDescriptor& options) {
  const auto generateReservedVersion = [&] {
    socklen_t addrlen = options.remote_address.length();
    quic_version h = 0x811C9DC5u;
    quic_version ver = htonl(options.version);
    const uint8_t* p = options.remote_address.raw();
    const uint8_t* ep = p + addrlen;
    for (; p != ep; ++p) {
      h ^= *p;
      h *= 0x01000193u;
    }
    p = reinterpret_cast<const uint8_t*>(&ver);
    ep = p + sizeof(options.version);
    for (; p != ep; ++p) {
      h ^= *p;
      h *= 0x01000193u;
    }
    h &= 0xf0f0f0f0u;
    h |= NGTCP2_RESERVED_VERSION_MASK;
    return h;
  };

  uint32_t sv[2] = {generateReservedVersion(), NGTCP2_PROTO_VER_MAX};

  uint8_t unused_random;
  CHECK(crypto::CSPRNG(&unused_random, 1).is_ok());
  size_t pktlen = options.dcid.length() + options.scid.length() + (sizeof(sv)) + 7;

  auto packet = Packet::Create(env(),
                               this,
                               options.remote_address,
                               kDefaultMaxPacketLength,
                               "version negotiation");
  ngtcp2_vec vec = *packet;

  ssize_t nwrite = ngtcp2_pkt_write_version_negotiation(vec.base,
                                                        pktlen,
                                                        unused_random,
                                                        options.dcid,
                                                        options.dcid.length(),
                                                        options.scid,
                                                        options.scid.length(),
                                                        sv,
                                                        arraysize(sv));
  if (nwrite > 0) {
    packet->Truncate(nwrite);
    Send(std::move(packet));
  }
}

bool Endpoint::SendStatelessReset(const PathDescriptor& options,
                                  size_t source_len) {
  if (UNLIKELY(options_.disable_stateless_reset)) return false;

  static constexpr size_t kRandlen = NGTCP2_MIN_STATELESS_RESET_RANDLEN * 5;
  static constexpr size_t kMinStatelessResetLen = 41;
  uint8_t random[kRandlen];

  const auto exceeds_limits = [&] {
    SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(options.remote_address);
    auto count = counts != nullptr ? counts->reset_count : 0;
    return count >= options_.max_stateless_resets;
  };

  // Per the QUIC spec, we need to protect against sending too many stateless
  // reset tokens to an endpoint to prevent endless looping.
  if (exceeds_limits()) return false;

  // Per the QUIC spec, a stateless reset token must be strictly smaller than
  // the packet that triggered it. This is one of the mechanisms to prevent
  // infinite looping exchange of stateless tokens with the peer. An endpoint
  // should never send a stateless reset token smaller than 41 bytes per the
  // QUIC spec. The reason is that packets less than 41 bytes may allow an
  // observer to reliably determine that it's a stateless reset.
  size_t pktlen = source_len - 1;
  if (pktlen < kMinStatelessResetLen) return false;

  StatelessResetToken token(options_.reset_token_secret, options.dcid);
  CHECK(crypto::CSPRNG(random, kRandlen).is_ok());

  auto packet = Packet::Create(env(),
                               this,
                               options.remote_address,
                               kDefaultMaxPacketLength,
                               "stateless reset");
  ngtcp2_vec vec = *packet;

  ssize_t nwrite = ngtcp2_pkt_write_stateless_reset(
      vec.base, pktlen, token, random, kRandlen);
  if (nwrite >= static_cast<ssize_t>(kMinStatelessResetLen)) {
    addrLRU_.Upsert(options.remote_address)->reset_count++;
    packet->Truncate(nwrite);
    Send(std::move(packet));
    return true;
  }
  return false;
}

void Endpoint::SendImmediateConnectionClose(const PathDescriptor& options,
                                            QuicError reason) {
  auto packet = Packet::Create(env(),
                               this,
                               options.remote_address,
                               kDefaultMaxPacketLength,
                               "immediate connection close (endpoint)");
  ngtcp2_vec vec = *packet;
  ssize_t nwrite = ngtcp2_crypto_write_connection_close(
      vec.base,
      vec.len,
      options.version,
      options.dcid,
      options.scid,
      reason.code(),
      // We do not bother sending a reason string here, even if
      // there is one in the QuicError
      nullptr,
      0);
  if (nwrite > 0) {
    packet->Truncate(static_cast<size_t>(nwrite));
    Send(std::move(packet));
  }
}

bool Endpoint::Start() {
  if (is_closed() || is_closing()) return false;
  if (state_->receiving == 1) return true;

  int err = 0;
  if (state_->bound == 0) {
    err = udp_.Bind(options_);
    if (err != 0) {
      // If we failed to bind, destroy the endpoint. There's nothing we can do.
      Destroy(CloseContext::BIND_FAILURE, err);
      return false;
    }
    state_->bound = 1;
  }

  err = udp_.Start();
  if (err != 0) {
    // If we failed to start listening, destroy the endpoint. There's nothing we
    // can do.
    Destroy(CloseContext::START_FAILURE, err);
    return false;
  }

  BindingData::Get(env()).listening_endpoints[this] = BaseObjectPtr<Endpoint>(this);
  state_->receiving = 1;
  return true;
}

bool Endpoint::Listen(const Session::Options& options) {
  if (is_closed() || is_closing()) return false;
  if (state_->listening == 1) return true;

  server_options_ = options;

  if (Start()) {
    state_->listening = 1;
    return true;
  }
  return false;
}

BaseObjectPtr<Session> Endpoint::Connect(const SocketAddress& remote_address,
                                         const Session::Options& options,
                                         BaseObjectPtr<SessionTicket> sessionTicket) {
  // If starting fails, the endpoint will be destroyed.
  if (!Start()) return BaseObjectPtr<Session>();

  auto local = local_address().value();

  auto config = Session::Config(
      CryptoContext::Side::CLIENT,
      *this,
      // For client sessions, we always generate a random intial CID for the
      // server. This is generally just a throwaway. The server will generate
      // it's own CID and send that back to us.
      CIDFactory::random().Generate(NGTCP2_MIN_INITIAL_DCIDLEN),
      local,
      remote_address);

  if (options.qlog) config.EnableQLog();

  config.session_ticket = sessionTicket;

  auto session =
      Session::Create(BaseObjectPtr<Endpoint>(this), config, options);
  if (!session) return BaseObjectPtr<Session>();

  session->set_wrapped();

  auto on_exit = OnScopeLeave([&] { session->SendPendingData(); });

  return session;
}

void Endpoint::MaybeDestroy() {
  if (!is_closing() && sessions_.empty() && state_->pending_callbacks == 0 &&
      state_->listening == 0) {
    Destroy();
  }
}

void Endpoint::Destroy(CloseContext context, int status) {
  if (is_closed() || is_closing()) return;

  stats_.RecordTimestamp<&Stats::destroyed_at>();

  state_->closing = true;

  // Stop listening for new connections while we shut things down.
  state_->listening = 0;

  // If there are open sessions still, shut them down. As those clean themselves
  // up, they will remove themselves. The cleanup here will be synchronous and
  // no attempt will be made to communicate further with the peer.
  if (!sessions_.empty()) {
    close_context_ = context;
    close_status_ = status;
    for (auto& session : sessions_) session.second->Close(Session::CloseMethod::SILENT);
  }
  CHECK(sessions_.empty());

  state_->closing = false;

  udp_.Close();
  state_->bound = 0;
  state_->receiving = 0;
  token_map_.clear();
  dcid_to_scid_.clear();
  BindingData::Get(env()).listening_endpoints.erase(this);

  return context == CloseContext::CLOSE
             ? EmitEndpointDone()
             : EmitError(close_context_, close_status_);
}

void Endpoint::CloseGracefully() {
  if (!is_closed() && !is_closing() && state_->waiting_for_callbacks == 0) {
    state_->listening = 0;
    state_->waiting_for_callbacks = 1;
  }

  MaybeDestroy();
}

void Endpoint::Receive(size_t nread,
                       const uv_buf_t& buf,
                       const SocketAddress& remote_address) {
  const auto is_diagnostic_packet_loss = [](auto probability) {
    if (LIKELY(probability == 0.0)) return false;
    unsigned char c = 255;
    CHECK(crypto::CSPRNG(&c, 1).is_ok());
    return (static_cast<double>(c) / 255) < probability;
  };

  const auto receive = [&](Store&& store,
                           const SocketAddress& local_address,
                           const SocketAddress& remote_address,
                           const CID& dcid,
                           const CID& scid) {
    stats_.Increment<&Stats::bytes_received>(store.length());
    auto session = FindSession(dcid);
    return session && !session->is_destroyed()
               ? session->Receive(
                     std::move(store), local_address, remote_address)
               : false;
  };

  const auto accept = [&](const Session::Config& config, Store&& store) {
    if (is_closed() || is_closing() || !is_listening()) return false;

    auto session =
        Session::Create(BaseObjectPtr<Endpoint>(this), config, server_options_);

    return session ?
        session->Receive(std::move(store), config.local_addr, config.remote_addr) :
        false;
  };

  const auto acceptInitialPacket = [&](const quic_version version,
                                       const CID& dcid,
                                       const CID& scid,
                                       Store&& store,
                                       const SocketAddress& local_address,
                                       const SocketAddress& remote_address) {
    // Conditionally accept an initial packet to create a new session.

    // If we're not listening, do not accept.
    if (state_->listening == 0) return false;

    ngtcp2_pkt_hd hd;

    // This is our first condition check... A minimal check to see if ngtcp2 can
    // even recognize this packet as a quic packet with the correct version.
    ngtcp2_vec vec = store;
    switch (ngtcp2_accept(&hd, vec.base, vec.len)) {
      case 1:
        // The requested QUIC protocol version is not supported
        SendVersionNegotiation(PathDescriptor {
            version,
            dcid,
            scid,
            local_address,
            remote_address
        });
        // The packet was successfully processed, even if we did refuse the
        // connection and send a version negotiation in response.
        return true;
      case -1:
        // The packet is invalid and we're just going to ignore it.
        return false;
    }

    // This is the second condition check... If the server has been marked busy
    // or the remote peer has exceeded their maximum number of concurrent
    // connections, any new connections will be shut down immediately.
    const auto limits_exceeded = [&] {
      if (sessions_.size() >= options_.max_connections_total) return true;

      SocketAddressInfoTraits::Type* counts = addrLRU_.Peek(remote_address);
      auto count = counts != nullptr ? counts->active_connections : 0;
      return count >= options_.max_connections_per_host;
    };

    if (state_->busy || limits_exceeded()) {
      // Endpoint is busy or the connection count is exceeded. The connection is
      // refused.
      if (state_->busy) stats_.Increment<&Stats::server_busy_count>();
      SendImmediateConnectionClose(PathDescriptor {
          version,
          scid,
          dcid,
          local_address,
          remote_address
      }, QuicError::ForTransport(NGTCP2_CONNECTION_REFUSED));
      // The packet was successfully processed, even if we did refuse the
      // connection.
      return true;
    }

    // At this point, we start to set up the configuration for our local
    // session. The second argument to the Config constructor here is the dcid.
    // We pass the received scid here as the value because that is the value
    // *this* session will use as it's outbound dcid.
    auto config = Session::Config(
        CryptoContext::Side::SERVER,
        *this,
        scid,
        local_address,
        remote_address,
        version,
        version);

    // The this point, the config.scid and config.dcid represent *our* views of
    // the CIDs. Specifically, config.dcid identifies the peer and config.scid
    // identifies us. config.dcid should equal scid. config.scid should *not*
    // equal dcid.

    const auto is_remote_address_validated = [&] {
      auto info = addrLRU_.Peek(remote_address);
      return info != nullptr ? info->validated : false;
    };

    config.ocid = dcid;

    // QUIC has address validation built in to the handshake but allows for
    // an additional explicit validation request using RETRY frames. If we
    // are using explicit validation, we check for the existence of a valid
    // retry token in the packet. If one does not exist, we send a retry with
    // a new token. If it does exist, and if it's valid, we grab the original
    // cid and continue.
    if (!is_remote_address_validated()) {
      switch (hd.type) {
        case NGTCP2_PKT_INITIAL:
          // First, let's see if we need to do anything here.

          if (options_.validate_address) {
            // If there is no token, generate and send one.
            if (hd.token.len == 0) {
              SendRetry(PathDescriptor {
                version,
                dcid,
                scid,
                local_address,
                remote_address,
              });
              return true;
            }

            // We have two kinds of tokens, each prefixed with a different magic
            // byte.
            switch (hd.token.base[0]) {
              case kRetryTokenMagic: {
                auto ocid = ValidateRetryToken(
                    version,
                    hd.token,
                    remote_address,
                    dcid,
                    options_.token_secret,
                    options_.retry_token_expiration * NGTCP2_SECONDS);
                if (ocid == std::nullopt) {
                  // Invalid retry token was detected. Close the connection.
                  SendImmediateConnectionClose(PathDescriptor {
                    version,
                    scid,
                    dcid,
                    local_address,
                    remote_address
                  }, QuicError::ForTransport(NGTCP2_CONNECTION_REFUSED));
                  return true;
                }

                // The ocid is the original dcid that was encoded into the
                // original retry packet sent to the client. We use it for
                // validation.
                config.ocid = ocid.value();
                config.retry_scid = dcid;
                break;
              }
              case kTokenMagic: {
                if (!NGTCP2_OK(ngtcp2_crypto_verify_regular_token(
                        hd.token.base,
                        hd.token.len,
                        options_.token_secret,
                        TOKEN_SECRET_LENGTH,
                        remote_address.data(),
                        remote_address.length(),
                        options_.token_expiration * NGTCP2_SECONDS,
                        uv_hrtime()))) {
                  SendRetry(PathDescriptor {
                    version,
                    dcid,
                    scid,
                    local_address,
                    remote_address,
                  });
                  return true;
                }
                hd.token.base = nullptr;
                hd.token.len = 0;
                break;
              }
              default: {
                SendRetry(PathDescriptor {
                  version,
                  dcid,
                  scid,
                  local_address,
                  remote_address,
                });
                return true;
              }
            }

            // Ok! If we've got this far, our token is valid! Which means our
            // path to the remote address is valid (for now). Let's record that
            // so we don't have to do this dance again for this endpoint
            // instance.
            addrLRU_.Upsert(remote_address)->validated = true;
            config.token = hd.token;
          } else if (hd.token.len > 0) {
            // If validation is turned off and there is a token, that's weird.
            // The peer should only have a token if we sent it to them and we
            // wouldn't have sent it unless validation was turned on. Let's
            // assume the peer is buggy or malicious and drop the packet on the
            // floor.
            return false;
          }
          break;
        case NGTCP2_PKT_0RTT:
          // If it's a 0RTT packet, we're always going to perform path
          // validation no matter what.
          SendRetry(PathDescriptor {
            version,
            dcid,
            scid,
            local_address,
            remote_address,
          });
          return true;
      }
    }

    return accept(config, std::move(store));
  };

  // When a received packet contains a QUIC short header but cannot be matched
  // to a known Session, it is either (a) garbage, (b) a valid packet for a
  // connection we no longer have state for, or (c) a stateless reset. Because
  // we do not yet know if we are going to process the packet, we need to try to
  // quickly determine -- with as little cost as possible -- whether the packet
  // contains a reset token. We do so by checking the final
  // NGTCP2_STATELESS_RESET_TOKENLEN bytes in the packet to see if they match
  // one of the known reset tokens previously given by the remote peer. If
  // there's a match, then it's a reset token, if not, we move on the to the
  // next check. It is very important that this check be as inexpensive as
  // possible to avoid a DOS vector.
  const auto maybeStatelessReset = [&](const CID& dcid,
                                       const CID& scid,
                                       Store& store,
                                       const SocketAddress& local_address,
                                       const SocketAddress& remote_address) {
    if (options_.disable_stateless_reset ||
        store.length() < NGTCP2_STATELESS_RESET_TOKENLEN)
      return false;

    ngtcp2_vec vec = store;
    vec.base += vec.len;
    vec.base -= NGTCP2_STATELESS_RESET_TOKENLEN;

    Session* session = nullptr;
    auto it = token_map_.find(StatelessResetToken(vec.base));
    if (it != token_map_.end()) session = it->second;

    return session != nullptr ? receive(std::move(store),
                                        local_address,
                                        remote_address,
                                        dcid,
                                        scid)
                              : false;
  };

  CHECK_LE(nread, buf.len);

  // When diagnostic packet loss is enabled, the packet will be randomly
  // dropped.
  if (UNLIKELY(is_diagnostic_packet_loss(options_.rx_loss))) {
    // Simulating rx packet loss
    return;
  }

  // TODO(@jasnell): Implement blocklist support
  // if (UNLIKELY(block_list_->Apply(remote_address))) {
  //   Debug(this, "Ignoring blocked remote address: %s", remote_address);
  //   return;
  // }

  std::shared_ptr<BackingStore> backing = env()->release_managed_buffer(buf);
  if (UNLIKELY(!backing))
    return Destroy(CloseContext::RECEIVE_FAILURE, UV_ENOMEM);

  Store store(backing, nread, 0);

  ngtcp2_vec vec = store;
  ngtcp2_version_cid pversion_cid;

  // This is our first check to see if the received data can be processed as a
  // QUIC packet. If this fails, then the QUIC packet header is invalid and
  // cannot be processed; all we can do is ignore it. If it succeeds, we have a
  // valid QUIC header but there is still no guarantee that the packet can be
  // successfully processed.
  if (ngtcp2_pkt_decode_version_cid(
          &pversion_cid, vec.base, vec.len, NGTCP2_MAX_CIDLEN) < 0) {
    return;  // Ignore the packet!
  }

  // QUIC currently requires CID lengths of max NGTCP2_MAX_CIDLEN. The ngtcp2
  // API allows non-standard lengths, and we may want to allow non-standard
  // lengths later. But for now, we're going to ignore any packet with a
  // non-standard CID length.
  if (pversion_cid.dcidlen > NGTCP2_MAX_CIDLEN ||
      pversion_cid.scidlen > NGTCP2_MAX_CIDLEN)
    return;  // Ignore the packet!

  // Each QUIC peer has two CIDs: The Source Connection ID (or scid), and the
  // Destination Connection ID (or dcid). For each peer, the dcid is the CID
  // identifying the other peer, and the scid is the CID identifying itself.
  // That is, the client's scid is the server dcid; likewise the server's scid
  // is the client's dcid.
  //
  // The dcid and scid below are the values sent from the peer received in the
  // current packet, so in this case, dcid represents who the peer sent the
  // packet too (this endpoint) and the scid represents who sent the packet.
  CID dcid(pversion_cid.dcid, pversion_cid.dcidlen);
  CID scid(pversion_cid.scid, pversion_cid.scidlen);

  // We index the current sessions by the dcid of the client. For initial
  // packets, the dcid is some random value and the scid is omitted from the
  // header (it uses what quic calls a "short header"). It is unlikely (but not
  // impossible) that this randomly selected dcid will be in our index. If we do
  // happen to have a collision, as unlikely as it is, ngtcp2 will do the right
  // thing when it tries to process the packet so we really don't have to worry
  // about it here. If the dcid is not known, the listener here will be nullptr.
  //
  // When the session is established, this peer will create it's own scid and
  // will send that back to the remote peer to use as it's new dcid on
  // subsequent packets. When that session is added, we will index it by the
  // local scid, so as long as the client sends the subsequent packets with the
  // right dcid, everything will just work.

  auto session = FindSession(dcid);
  auto addr = local_address().value();

  HandleScope handle_scope(env()->isolate());

  // If a session is not found, there are four possible reasons:
  // 1. The session has not been created yet
  // 2. The session existed once but we've lost the local state for it
  // 3. The packet is a stateless reset sent by the peer
  // 4. This is a malicious or malformed packet.
  if (!session) {
    // No existing session.

    // For the current version of QUIC, it is a short header if there is no
    // scid.
    bool is_short_header =
        (pversion_cid.version == NGTCP2_PROTO_VER_MAX && !scid);

    // Handle possible reception of a stateless reset token... If it is a
    // stateless reset, the packet will be handled with no additional action
    // necessary here. We want to return immediately without committing any
    // further resources.
    if (is_short_header &&
        maybeStatelessReset(dcid, scid, store, addr, remote_address))
      return;  // Stateless reset! Don't do any further processing.

    if (acceptInitialPacket(pversion_cid.version,
                            dcid,
                            scid,
                            std::move(store),
                            addr,
                            remote_address)) {
      // Packet was successfully received.
      stats_.Increment<&Stats::packets_received>();
    }
    return;
  }

  // If we got here, the dcid matched the scid of a known local session. Yay!
  if (receive(std::move(store), addr, remote_address, dcid, scid)) {
    stats_.Increment<&Stats::packets_received>();  // Success!
  }
}

void Endpoint::PacketDone(int status) {
  if (is_closed()) return;
  state_->pending_callbacks--;
  // Can we go ahead and close now? Yes, so long as there are no pending
  // callbacks and no sessions open.
  if (state_->waiting_for_callbacks == 1) {
    HandleScope scope(env()->isolate());
    MaybeDestroy();
  }
}

void Endpoint::IncrementSocketAddressCounter(const SocketAddress& addr) {
  addrLRU_.Upsert(addr)->active_connections++;
}

void Endpoint::DecrementSocketAddressCounter(const SocketAddress& addr) {
  auto* counts = addrLRU_.Peek(addr);
  if (counts != nullptr && counts->active_connections > 0)
    counts->active_connections--;
}

bool Endpoint::is_closed() const {
  return !udp_;
}
bool Endpoint::is_closing() const {
  return state_->closing;
}
bool Endpoint::is_listening() const {
  return state_->listening;
}

StatelessResetToken Endpoint::GenerateNewStatelessResetToken(
    uint8_t* token,
    const CID& cid) const {
  return StatelessResetToken(token, options_.reset_token_secret, cid);
}

void Endpoint::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
  tracker->TrackField("udp", udp_);
  tracker->TrackField("server_options", server_options_);
  tracker->TrackField("token_map", token_map_);
  tracker->TrackField("sessions", sessions_);
  tracker->TrackField("cid_map", dcid_to_scid_);
  tracker->TrackField("address LRU", addrLRU_);
}

// ======================================================================================
// Endpoint::SocketAddressInfoTraits

bool Endpoint::SocketAddressInfoTraits::CheckExpired(
    const SocketAddress& address, const Type& type) {
  return (uv_hrtime() - type.timestamp) > kSocketAddressInfoTimeout;
}

void Endpoint::SocketAddressInfoTraits::Touch(const SocketAddress& address,
                                              Type* type) {
  type->timestamp = uv_hrtime();
}

// ======================================================================================
// JavaScript call outs

void Endpoint::EmitNewSession(const BaseObjectPtr<Session>& session) {
  if (!env()->can_call_into_js()) return;
  CallbackScope<Endpoint> scope(this);
  session->set_wrapped();
  Local<Value> arg = session->object();

  MakeCallback(BindingData::Get(env()).session_new_callback(), 1, &arg);
}

void Endpoint::EmitEndpointDone() {
  if (!env()->can_call_into_js()) return;
  CallbackScope<Endpoint> scope(this);

  MakeCallback(BindingData::Get(env()).endpoint_done_callback(), 0, nullptr);
}

void Endpoint::EmitError(CloseContext context, int status) {
  if (!env()->can_call_into_js()) return;
  CallbackScope<Endpoint> scope(this);
  auto isolate = env()->isolate();
  Local<Value> argv[] = {Integer::New(isolate, static_cast<int>(context)),
                         Integer::New(isolate, static_cast<int>(status))};

  MakeCallback(BindingData::Get(env()).endpoint_error_callback(),
               arraysize(argv),
               argv);
}

// ======================================================================================
// Endpoint JavaScript API

void Endpoint::CreateEndpoint(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  auto env = Environment::GetCurrent(args);
  CHECK(OptionsObject::HasInstance(env, args[0]));
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args[0]);

  auto endpoint = Endpoint::Create(env, *options);
  if (endpoint) args.GetReturnValue().Set(endpoint->object());
}

void Endpoint::DoConnect(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());

  // args[0] is a SocketAddress
  // args[1] is a Session OptionsObject (see session.cc)
  // args[2] is an optional SessionTicket

  CHECK(SocketAddressBase::HasInstance(env, args[0]));
  auto& options = Session::Options::From(env, args[1]);
  CHECK_IMPLIES(!args[2]->IsUndefined(),
                SessionTicket::HasInstance(env, args[2]));

  SocketAddressBase* address;
  SessionTicket* sessionTicket = nullptr;

  ASSIGN_OR_RETURN_UNWRAP(&address, args[0]);

  if (!args[2]->IsUndefined()) ASSIGN_OR_RETURN_UNWRAP(&sessionTicket, args[2]);

  auto session = endpoint->Connect(
      *address->address(),
      options,
      BaseObjectPtr<SessionTicket>(sessionTicket));
  if (session) args.GetReturnValue().Set(session->object());
}

void Endpoint::DoListen(const FunctionCallbackInfo<Value>& args) {
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  auto env = Environment::GetCurrent(args);

  // args[0] is a Session OptionsObject (see session.cc)

  auto& options = Session::Options::From(env, args[0]);
  args.GetReturnValue().Set(endpoint->Listen(options));
}

void Endpoint::MarkBusy(const FunctionCallbackInfo<Value>& args) {
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  endpoint->MarkAsBusy(args[0]->IsTrue());
}

void Endpoint::DoCloseGracefully(const FunctionCallbackInfo<Value>& args) {
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  endpoint->CloseGracefully();
}

void Endpoint::LocalAddress(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  auto local_address = endpoint->local_address();
  if (local_address != std::nullopt) {
    auto addr = SocketAddressBase::Create(
        env, std::make_shared<SocketAddress>(local_address.value()));
    if (addr) args.GetReturnValue().Set(addr->object());
  }
}

void Endpoint::Ref(const FunctionCallbackInfo<Value>& args) {
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  endpoint->udp_.Ref();
}

void Endpoint::Unref(const FunctionCallbackInfo<Value>& args) {
  Endpoint* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args.Holder());
  endpoint->udp_.Unref();
}

}  // namespace quic
}  // namespace node
