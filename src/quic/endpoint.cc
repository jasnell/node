#ifndef OPENSSL_NO_QUIC

#include "quic/endpoint.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_sockaddr-inl.h"
#include "v8.h"

namespace node {

using v8::FunctionTemplate;
using v8::Local;
using v8::Object;

namespace quic {

template <typename Fn>
void EndpointStatsTraits::ToString(const Endpoint& ptr, Fn&& add_field) {
#define V(_n, name, label)                                                     \
  add_field(label, ptr.GetStat(&EndpointStats::name));
  ENDPOINT_STATS(V)
#undef V
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

BaseObjectPtr<Endpoint> Endpoint::Create(Environment* env) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(env);
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Endpoint>();

  return MakeBaseObject<Endpoint>(env, obj);
}

Endpoint::Endpoint(
    Environment* env,
    Local<Object> object)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUICENDPOINT),
      EndpointStatsBase(env, object) {
  MakeWeak();
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
