#ifndef OPENSSL_NO_QUIC

#include "quic/session.h"
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
void SessionStatsTraits::ToString(const Session& ptr, Fn&& add_field) {
#define V(n, name, label) add_field(label, ptr.GetStat(&SessionStats::name));
  SESSION_STATS(V)
#undef V
}

Local<FunctionTemplate> Session::GetConstructorTemplate(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  CHECK_NOT_NULL(state);
  Local<FunctionTemplate> tmpl = state->session_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicSession"));
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Session::kInternalFieldCount);
    state->set_session_constructor_template(env, tmpl);
  }
  return tmpl;
}

void Session::Initialize(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_session_constructor_template(env, GetConstructorTemplate(env));
}

BaseObjectPtr<Session> Session::Create(Environment* env) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(env);
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Session>();

  return MakeBaseObject<Session>(env, obj);
}

Session::Session(
    Environment* env,
    Local<Object> object)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUICSESSION),
      SessionStatsBase(env, object) {
  MakeWeak();
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
