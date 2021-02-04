#include "quic/stream.h"
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

Local<FunctionTemplate> Stream::GetConstructorTemplate(Environment* env) {}

BaseObjectPtr<Stream> Stream::Create(
    Environment* env,
    Session* session,
    stream_id id) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(env);
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Stream>();

  return MakeBaseObject<Stream>(env, obj, session, id);
}

Stream::Stream(
    Environment* env,
    Local<Object> object,
    Session* session,
    stream_id id)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_QUICSTREAM),
      session_(session),
      id_(id) {
  MakeWeak();
}

}  // namespace quic
}  // namespace node
