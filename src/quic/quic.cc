#ifndef OPENSSL_NO_QUIC

#include "quic/buffer.h"
#include "quic/crypto.h"
#include "quic/endpoint.h"
#include "quic/session.h"
#include "quic/stream.h"
#include "quic/qlog.h"
#include "quic/quic.h"
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node.h"
#include "node_bob-inl.h"
#include "node_errors.h"
#include "node_http_common-inl.h"
#include "node_mem-inl.h"
#include "node_process.h"
#include "node_sockaddr-inl.h"
#include "util-inl.h"

#include <nghttp3/nghttp3.h>

#include <v8.h>

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

constexpr FastStringKey BindingState::binding_data_name;

BindingState::BindingState(Environment* env, Local<Object> object)
    : BaseObject(env, object) {

  http3_alpn_.Set(
      env->isolate(),
      OneByteString(env->isolate(), &NGHTTP3_ALPN_H3[1]));
}

Local<String> BindingState::http3_alpn(Environment* env) {
  return http3_alpn_.Get(env->isolate());
}

ngtcp2_mem BindingState::GetAllocator(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  return state->MakeAllocator();
}

void BindingState::MemoryInfo(MemoryTracker* tracker) const {
#define V(name, _) tracker->TrackField(#name, name ## _callback_);
  QUIC_JS_CALLBACKS(V)
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
      Environment* env,                                                        \
      Local<FunctionTemplate> tmpl) {                                          \
    name ## _constructor_template_.Reset(env->isolate(), tmpl);                \
  }                                                                            \
  Local<FunctionTemplate> BindingState::name ## _constructor_template(         \
      Environment* env) const {                                                \
    return PersistentToLocal::Default(                                         \
        env->isolate(),                                                        \
        name ## _constructor_template_);                                       \
  }
  QUIC_CONSTRUCTORS(V)
#undef V

#define V(name, _)                                                             \
  void BindingState::set_ ## name ## _callback(                                \
      Environment* env,                                                        \
      Local<Function> fn) {                                                    \
    name ## _callback_.Reset(env->isolate(), fn);                              \
  }                                                                            \
  Local<Function> BindingState::name ## _callback(Environment* env) const {    \
    return PersistentToLocal::Default(env->isolate(), name ## _callback_);     \
  }
  QUIC_JS_CALLBACKS(V)
#undef V

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

namespace {
void InitializeCallbacks(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->check_initialized();
  if (!args[0]->IsObject())
    return THROW_ERR_INVALID_ARG_TYPE(env, "Missing Callbacks");
  Local<Object> obj = args[0].As<Object>();
#define V(name, key)                                                           \
  do {                                                                         \
    Local<Value> val;                                                          \
    if (!obj->Get(                                                             \
            env->context(),                                                    \
            FIXED_ONE_BYTE_STRING(env->isolate(), #key)).ToLocal(&val) ||      \
        !val->IsFunction()) {                                                  \
      return THROW_ERR_MISSING_ARGS(                                           \
          env->isolate(),                                                      \
          "Missing Callback: " # key);                                         \
    }                                                                          \
    state->set_ ## name ## _callback(env, val.As<Function>());                 \
  } while (0);
  QUIC_JS_CALLBACKS(V)
#undef V
  state->set_initialized();
}
}  // namespace

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);

  BindingState* const state =
      env->AddBindingData<BindingState>(context, target);
  if (UNLIKELY(state == nullptr))
    return;

  env->SetMethod(target, "initializeCallbacks", InitializeCallbacks);

  Endpoint::Initialize(env);
  Session::Initialize(env);
  Stream::Initialize(env);

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

  NODE_DEFINE_STRING_CONSTANT(
      target,
      NODE_STRINGIFY_HELPER(NGHTTP3_ALPN_H3),
      NGHTTP3_ALPN_H3 + 1);
}

}  // namespace quic
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)

#endif  // OPENSSL_NO_QUIC
