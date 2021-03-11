#if HAVE_OPENSSL
# include <openssl/crypto.h>
#endif

#ifdef OPENSSL_INFO_QUIC
#include "quic/quic.h"
#include "quic/crypto.h"
#include "quic/endpoint.h"
#include "quic/session.h"
#include "quic/stream.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "node.h"
#include "node_errors.h"
#include "node_mem-inl.h"
#include "node_sockaddr-inl.h"
#include "util-inl.h"
#endif  // OPENSSL_INFO_QUIC

#include "env-inl.h"
#include "v8.h"

namespace node {

using v8::Context;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace quic {
#ifdef OPENSSL_INFO_QUIC
constexpr FastStringKey BindingState::type_name;

void IllegalConstructor(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  THROW_ERR_ILLEGAL_CONSTRUCTOR(env);
}

BindingState* BindingState::Get(Environment* env) {
  return env->GetBindingData<BindingState>(env->context());
}

bool BindingState::Initialize(Environment* env, Local<Object> target) {
  BindingState* const state =
      env->AddBindingData<BindingState>(env->context(), target);
  return state != nullptr;
}

BindingState::BindingState(Environment* env, Local<Object> object)
    : BaseObject(env, object) {}

ngtcp2_mem BindingState::GetAllocator(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  return state->MakeAllocator();
}

void BindingState::MemoryInfo(MemoryTracker* tracker) const {
#define V(name, _) tracker->TrackField(#name, name ## _callback());
  QUIC_JS_CALLBACKS(V)
#undef V
#define V(name, _) tracker->TrackField(#name, name ## _string());
  QUIC_STRINGS(V)
#undef V
}

void BindingState::CheckAllocatedSize(size_t previous_size) const {
  CHECK_GE(current_ngtcp2_memory_, previous_size);
}

void BindingState::IncreaseAllocatedSize(size_t size) {
  current_ngtcp2_memory_ += size;
}

void BindingState::DecreaseAllocatedSize(size_t size) {
  current_ngtcp2_memory_ -= size;
}

#define V(name)                                                                \
  void BindingState::set_ ## name ## _constructor_template(                    \
      Local<FunctionTemplate> tmpl) {                                          \
    name ## _constructor_template_.Reset(env()->isolate(), tmpl);              \
  }                                                                            \
  Local<FunctionTemplate> BindingState::name ## _constructor_template() const {\
    return PersistentToLocal::Default(                                         \
        env()->isolate(), name ## _constructor_template_);                     \
  }
  QUIC_CONSTRUCTORS(V)
#undef V

#define V(name, _)                                                             \
  void BindingState::set_ ## name ## _callback(Local<Function> fn) {           \
    name ## _callback_.Reset(env()->isolate(), fn);                            \
  }                                                                            \
  Local<Function> BindingState::name ## _callback() const {                    \
    return PersistentToLocal::Default(env()->isolate(), name ## _callback_);   \
  }
  QUIC_JS_CALLBACKS(V)
#undef V

#define V(name, value)                                                         \
  Local<String> BindingState::name ## _string() const {                        \
    if (name ## _string_.IsEmpty())                                            \
      name ## _string_.Set(                                                    \
          env()->isolate(),                                                    \
          OneByteString(env()->isolate(), value));                             \
    return name ## _string_.Get(env()->isolate());                             \
  }
  QUIC_STRINGS(V)
#undef V

AsyncSignal::AsyncSignal(Environment* env, const Callback& fn)
    : env_(env), fn_(fn) {
  CHECK_EQ(uv_async_init(env->event_loop(), &handle_, OnSignal), 0);
  handle_.data = this;
}

void AsyncSignal::Close() {
  handle_.data = nullptr;
  env_->CloseHandle(reinterpret_cast<uv_handle_t*>(&handle_), ClosedCb);
}

void AsyncSignal::ClosedCb(uv_handle_t* handle) {
  std::unique_ptr<AsyncSignal> ptr(
      ContainerOf(&AsyncSignal::handle_,
                  reinterpret_cast<uv_async_t*>(handle)));
}

void AsyncSignal::Send() {
  if (handle_.data == nullptr) return;
  uv_async_send(&handle_);
}

void AsyncSignal::Ref() {
  if (handle_.data == nullptr) return;
  uv_ref(reinterpret_cast<uv_handle_t*>(&handle_));
}

void AsyncSignal::Unref() {
  if (handle_.data == nullptr) return;
  uv_unref(reinterpret_cast<uv_handle_t*>(&handle_));
}

void AsyncSignal::OnSignal(uv_async_t* handle) {
  AsyncSignal* t = ContainerOf(&AsyncSignal::handle_, handle);
  t->fn_();
}

AsyncSignalHandle::AsyncSignalHandle(
    Environment* env,
    const AsyncSignal::Callback& fn)
    : signal_(new AsyncSignal(env, fn)) {
  env->AddCleanupHook(CleanupHook, this);
  Unref();
}

void AsyncSignalHandle::Close() {
  if (signal_ != nullptr) {
    signal_->env()->RemoveCleanupHook(CleanupHook, this);
    signal_->Close();
  }
  signal_ = nullptr;
}

void AsyncSignalHandle::Send() {
  if (signal_ != nullptr)
    signal_->Send();
}

void AsyncSignalHandle::Ref() {
  if (signal_ != nullptr)
    signal_->Ref();
}

void AsyncSignalHandle::Unref() {
  if (signal_ != nullptr)
    signal_->Unref();
}

void AsyncSignalHandle::MemoryInfo(MemoryTracker* tracker) const {
  if (signal_ != nullptr)
    tracker->TrackField("signal", *signal_);
}

void AsyncSignalHandle::CleanupHook(void* data) {
  static_cast<AsyncSignalHandle*>(data)->Close();
}

void Packet::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("allocated", ptr_ != data_ ? len_ : 0);
}

Path::Path(const SocketAddress& local, const SocketAddress& remote) {
  ngtcp2_addr_init(
      &this->local,
      local.data(),
      local.length(),
      const_cast<SocketAddress*>(&local));
  ngtcp2_addr_init(
      &this->remote,
      remote.data(),
      remote.length(),
      const_cast<SocketAddress*>(&remote));
}

StatelessResetToken::StatelessResetToken(
    uint8_t* token,
    const uint8_t* secret,
    const CID& cid) {
  GenerateResetToken(token, secret, cid);
  memcpy(buf_, token, sizeof(buf_));
}

StatelessResetToken::StatelessResetToken(
    const uint8_t* secret,
    const CID& cid) {
  GenerateResetToken(buf_, secret, cid);
}

void RandomConnectionIDTraits::NewConnectionID(
  const Options& options,
  State* state,
  Session* session,
  ngtcp2_cid* cid,
  size_t length_hint) {
  CHECK_NOT_NULL(cid);
  crypto::EntropySource(
      reinterpret_cast<unsigned char*>(cid->data),
      length_hint);
  cid->data[0] |= 0xc0;
  cid->datalen = length_hint;
}

void RandomConnectionIDTraits::New(
    const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  new RandomConnectionIDBase(env, args.This());
}

Local<FunctionTemplate> RandomConnectionIDTraits::GetConstructorTemplate(
    Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  Local<FunctionTemplate> tmpl =
      state->random_connection_id_strategy_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = env->NewFunctionTemplate(New);
    tmpl->SetClassName(OneByteString(env->isolate(), name));
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        BaseObject::kInternalFieldCount);
    state->set_random_connection_id_strategy_constructor_template(tmpl);
  }
  return tmpl;
}

namespace {
void InitializeCallbacks(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  if (!args[0]->IsObject())
    return THROW_ERR_INVALID_ARG_TYPE(env, "Missing Callbacks");
  Local<Object> obj = args[0].As<Object>();
#define V(name, key)                                                           \
  do {                                                                         \
    Local<Value> val;                                                          \
    if (!obj->Get(                                                             \
            env->context(),                                                    \
            FIXED_ONE_BYTE_STRING(                                             \
                env->isolate(),                                                \
                "on" # key)).ToLocal(&val) ||                                  \
        !val->IsFunction()) {                                                  \
      return THROW_ERR_MISSING_ARGS(                                           \
          env->isolate(),                                                      \
          "Missing Callback: on" # key);                                       \
    }                                                                          \
    state->set_ ## name ## _callback(val.As<Function>());                      \
  } while (0);
  QUIC_JS_CALLBACKS(V)
#undef V
}

template <ngtcp2_crypto_side side>
void CreateSecureContext(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  crypto::SecureContext* context = crypto::SecureContext::Create(env);
  if (UNLIKELY(context == nullptr)) return;
  InitializeSecureContext(context, side);
  args.GetReturnValue().Set(context->object());
}
}  // namespace

void Initialize(
    Local<Object> target,
    Local<Value> unused,
    Local<Context> context,
    void* priv) {
  Environment* env = Environment::GetCurrent(context);

  if (UNLIKELY(!BindingState::Initialize(env, target)))
    return;

  EndpointWrap::Initialize(env, target);
  Session::Initialize(env, target);
  Stream::Initialize(env);
  RandomConnectionIDBase::Initialize(env, target);

  env->SetMethod(target, "initializeCallbacks", InitializeCallbacks);
  env->SetMethod(target, "createClientSecureContext",
                 CreateSecureContext<NGTCP2_CRYPTO_SIDE_CLIENT>);
  env->SetMethod(target, "createServerSecureContext",
                 CreateSecureContext<NGTCP2_CRYPTO_SIDE_SERVER>);

  constexpr uint32_t NGTCP2_PREFERRED_ADDRESS_USE =
      static_cast<uint32_t>(PreferredAddress::Policy::USE);
  constexpr uint32_t NGTCP2_PREFERRED_ADDRESS_IGNORE =
      static_cast<uint32_t>(PreferredAddress::Policy::IGNORE);

  NODE_DEFINE_STRING_CONSTANT(target, "HTTP3_ALPN", &NGHTTP3_ALPN_H3[1]);
  NODE_DEFINE_CONSTANT(target, AF_INET);
  NODE_DEFINE_CONSTANT(target, AF_INET6);
  NODE_DEFINE_CONSTANT(target, NGTCP2_CC_ALGO_CUBIC);
  NODE_DEFINE_CONSTANT(target, NGTCP2_CC_ALGO_RENO);
  NODE_DEFINE_CONSTANT(target, NGTCP2_PREFERRED_ADDRESS_IGNORE);
  NODE_DEFINE_CONSTANT(target, NGTCP2_PREFERRED_ADDRESS_USE);
  NODE_DEFINE_CONSTANT(target, NGTCP2_MAX_CIDLEN);
  NODE_DEFINE_CONSTANT(target, NGTCP2_APP_NOERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_NO_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_INTERNAL_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_CONNECTION_REFUSED);
  NODE_DEFINE_CONSTANT(target, NGTCP2_FLOW_CONTROL_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_STREAM_LIMIT_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_STREAM_STATE_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_FINAL_SIZE_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_FRAME_ENCODING_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_TRANSPORT_PARAMETER_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_CONNECTION_ID_LIMIT_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_PROTOCOL_VIOLATION);
  NODE_DEFINE_CONSTANT(target, NGTCP2_INVALID_TOKEN);
  NODE_DEFINE_CONSTANT(target, NGTCP2_APPLICATION_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_CRYPTO_BUFFER_EXCEEDED);
  NODE_DEFINE_CONSTANT(target, NGTCP2_KEY_UPDATE_ERROR);
  NODE_DEFINE_CONSTANT(target, NGTCP2_CRYPTO_ERROR);
  NODE_DEFINE_CONSTANT(target, UV_UDP_IPV6ONLY);
}

#else
// Intentionally empty to ensure that the internal binding will never fail to
// resolve even if QUIC support has not been compiled. Nothing will be exported.
void Initialize(
    Local<Object> target,
    Local<Value> unused,
    Local<Context> context,
    void* priv) {}
#endif  // OPENSSL_INFO_QUIC
}  // namespace quic
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)
