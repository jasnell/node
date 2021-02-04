#include "quic/session.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "v8.h"

namespace node {

using v8::FunctionTemplate;
using v8::Local;
using v8::Object;

namespace quic {

Local<FunctionTemplate> Session::GetConstructorTemplate(Environment* env) {}

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
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUICSESSION) {
  MakeWeak();
}

}  // namespace quic
}  // namespace node
