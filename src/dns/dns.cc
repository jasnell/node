#include "dns/dns.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "req_wrap-inl.h"
#include "v8.h"

namespace node {

using v8::Context;
using v8::Local;
using v8::Object;
using v8::Value;

namespace dns {

void Initialize(
    Local<Object> target,
    Local<Value> unused,
    Local<Context> context,
    void* priv) {
  Environment* env = Environment::GetCurrent(context);

  uv::Initialize(env, target);
  cares::Initialize(env, target);

  NODE_DEFINE_CONSTANT(target, AF_INET);
  NODE_DEFINE_CONSTANT(target, AF_INET6);
  NODE_DEFINE_CONSTANT(target, AF_UNSPEC);
  NODE_DEFINE_CONSTANT(target, AI_ADDRCONFIG);
  NODE_DEFINE_CONSTANT(target, AI_ALL);
  NODE_DEFINE_CONSTANT(target, AI_V4MAPPED);
}

}  // namespace dns
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(dns, node::dns::Initialize);
