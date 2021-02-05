#ifndef OPENSSL_NO_QUIC

#include "quic/stream.h"
#include "quic/quic.h"
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
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
void StreamStatsTraits::ToString(const Stream& ptr, Fn&& add_field) {
#define V(_, name, label) add_field(label, ptr.GetStat(&StreamStats::name));
  STREAM_STATS(V)
#undef V
}

Local<FunctionTemplate> Stream::GetConstructorTemplate(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  CHECK_NOT_NULL(state);
  Local<FunctionTemplate> tmpl = state->stream_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicStream"));
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Stream::kInternalFieldCount);
    state->set_stream_constructor_template(env, tmpl);
  }
  return tmpl;
}

void Stream::Initialize(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_stream_constructor_template(env, GetConstructorTemplate(env));
}

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
      StreamStatsBase(env, object),
      session_(session),
      id_(id) {
  MakeWeak();
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
