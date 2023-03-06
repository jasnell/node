#include "bindingdata-inl.h"
#include "preferredaddress.h"
#include "sessionticket.h"
#include "endpoint.h"
#include "session-inl.h"
#include "streams-inl.h"
#include <node_errors.h>
#include <node_external_reference.h>
#include <node_internals.h>
#include <v8.h>

namespace node {

using v8::Context;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::Value;

namespace quic {

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
#if NODE_OPENSSL_HAS_QUIC
  Environment* env = Environment::GetCurrent(context);
  PreferredAddress::Initialize(env, target);
  BindingData::Initialize(env, target);
  SessionTicket::Initialize(env, target);
  Endpoint::Initialize(env, target);
  Session::Initialize(env, target);
  Stream::Initialize(env, target);
#endif // NODE_OPENSSL_HAS_QUIC
}

void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
#if NODE_OPENSSL_HAS_QUIC
  BindingData::RegisterExternalReferences(registry);
  SessionTicket::RegisterExternalReferences(registry);
  Endpoint::RegisterExternalReferences(registry);
  Session::RegisterExternalReferences(registry);
  Stream::RegisterExternalReferences(registry);
#endif // NODE_OPENSSL_HAS_QUIC
}

}  // namespace quic
}  // namespace node

NODE_BINDING_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)
NODE_BINDING_EXTERNAL_REFERENCE(quic,
                                node::quic::RegisterExternalReferences)
