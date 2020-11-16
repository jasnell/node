#include "dns/dns_uv.h"
#include "async_wrap-inl.h"
#include "env-inl.h"
#include "base_object-inl.h"
#include "memory_tracker-inl.h"
#include "node.h"
#include "node_sockaddr-inl.h"
#include "req_wrap-inl.h"
#include "util-inl.h"

#include "ares.h"

#include <vector>

namespace node {

using v8::Array;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::HandleScope;
using v8::Int32;
using v8::Integer;
using v8::Local;
using v8::Null;
using v8::Object;
using v8::Uint32;
using v8::Value;

namespace dns {

namespace {
using ParseIPResult =
    decltype(static_cast<ares_addr_port_node*>(nullptr)->addr);

int ParseIP(const char* ip, ParseIPResult* result = nullptr) {
  ParseIPResult tmp;
  if (result == nullptr) result = &tmp;
  if (0 == uv_inet_pton(AF_INET, ip, result)) return 4;
  if (0 == uv_inet_pton(AF_INET6, ip, result)) return 6;
  return 0;
}

void CanonicalizeIP(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsString());
  Environment* env = Environment::GetCurrent(args);
  Utf8Value ip(env->isolate(), args[0]);

  ParseIPResult result;
  const int rc = ParseIP(*ip, &result);
  if (rc == 0) return;

  char canonical_ip[INET6_ADDRSTRLEN];
  const int af = (rc == 4 ? AF_INET : AF_INET6);
  CHECK_EQ(0, uv_inet_ntop(af, &result, canonical_ip, sizeof(canonical_ip)));
  args.GetReturnValue().Set(OneByteString(env->isolate(), canonical_ip));
}
}  // namespace

void GetAddrInfoTraits::After(
    uv_getaddrinfo_t* req,
    int status,
    struct addrinfo* res) {
  DeleteFnPtr<struct addrinfo, uv_freeaddrinfo> delete_res(res);
  std::unique_ptr<GetAddrInfoWrap> req_wrap {
      GetAddrInfoWrap::FromHandle(req) };

  Environment* env = req_wrap->env();

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Local<Value> argv[] = {
    Integer::New(env->isolate(), status),
    Null(env->isolate())
  };

  if (status == 0) {
    std::vector<Local<Value>> vec;

    auto add = [&](bool want_ipv4, bool want_ipv6) {
      for (auto p = res; p != nullptr; p = p->ai_next) {
        CHECK_EQ(p->ai_socktype, SOCK_STREAM);
        if ((want_ipv4 && p->ai_family == AF_INET) ||
            (want_ipv6 && p->ai_family == AF_INET6)) {
          vec.push_back(
              OneByteString(
                  env->isolate(),
                  SocketAddress::GetAddress(p->ai_addr).c_str()));
        }
      }
    };

    add(true, req_wrap->options().verbatim);
    if (!req_wrap->options().verbatim)
      add(false, true);

    if (vec.size() == 0) {
      argv[0] = Integer::New(env->isolate(), UV_EAI_NODATA);
    } else {
      argv[1] = Array::New(env->isolate(), vec.data(), vec.size());
    }
  }

  // TODO(@jasnell): Re-enable trace events
  // TRACE_EVENT_NESTABLE_ASYNC_END2(
  //     TRACING_CATEGORY_NODE2(dns, native), "lookup", req_wrap.get(),
  //     "count", n, "verbatim", verbatim);

  req_wrap->MakeCallback(env->oncomplete_string(), arraysize(argv), argv);
}

std::unique_ptr<GetAddrInfoWrap> GetAddrInfoTraits::Create(
    Environment* env,
    Local<Object> obj,
    const FunctionCallbackInfo<Value>& args) {
  CHECK(args[1]->IsString());  // hostname
  CHECK(args[2]->IsInt32());  // family
  CHECK_IMPLIES(!args[3]->IsUndefined(), args[3]->IsInt32());  // flags
  CHECK(args[4]->IsBoolean());  // verbatim

  GetAddrInfoWrap::Options options;

  Utf8Value hostname(env->isolate(), args[1]);
  options.hostname = *hostname;

  switch (args[2].As<Int32>()->Value()) {
    case 0: options.family = AF_UNSPEC; break;
    case 4: options.family = AF_INET; break;
    case 6: options.family = AF_INET6; break;
    default: UNREACHABLE();
  }

  if (args[3]->IsInt32())
    options.flags = args[3].As<Int32>()->Value();

  options.verbatim = args[4]->IsTrue();

  return std::make_unique<GetAddrInfoWrap>(env, obj, options);
}

int GetAddrInfoTraits::Dispatch(GetAddrInfoWrap* req_wrap) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = req_wrap->options().family;
  hints.ai_flags = req_wrap->options().flags;
  hints.ai_socktype = SOCK_STREAM;

  // TODO(@jasnell): Re-enable trace events
  // TRACE_EVENT_NESTABLE_ASYNC_BEGIN2(
  //     TRACING_CATEGORY_NODE2(dns, native), "lookup", req_wrap.get(),
  //     "hostname", TRACE_STR_COPY(*hostname),
  //     "family",
  //     family == AF_INET ? "ipv4" : family == AF_INET6 ? "ipv6" : "unspec");

  return req_wrap->Dispatch(uv_getaddrinfo,
                            GetAddrInfoTraits::After,
                            req_wrap->options().hostname.c_str(),
                            nullptr,
                            &hints);
}

void GetNameInfoTraits::After(
    uv_getnameinfo_t* req,
    int status,
    const char* hostname,
    const char* service) {
  std::unique_ptr<GetNameInfoWrap> req_wrap {
      GetNameInfoWrap::FromHandle(req) };
  Environment* env = req_wrap->env();

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Local<Value> argv[] = {
    Integer::New(env->isolate(), status),
    Null(env->isolate()),
    Null(env->isolate())
  };

  if (status == 0) {
    argv[1] = OneByteString(env->isolate(), hostname);
    argv[2] = OneByteString(env->isolate(), service);
  }

  // TODO(@jasnell): Re-enable trace events
  // TRACE_EVENT_NESTABLE_ASYNC_END2(
  //     TRACING_CATEGORY_NODE2(dns, native), "lookupService", req_wrap.get(),
  //     "hostname", TRACE_STR_COPY(hostname),
  //     "service", TRACE_STR_COPY(service));

  req_wrap->MakeCallback(env->oncomplete_string(), arraysize(argv), argv);
}

std::unique_ptr<GetNameInfoWrap> GetNameInfoTraits::Create(
    Environment* env,
    Local<Object> obj,
    const FunctionCallbackInfo<Value>& args) {
  CHECK(args[1]->IsString());
  CHECK(args[2]->IsUint32());

  Utf8Value ip(env->isolate(), args[1]);
  GetNameInfoWrap::Options options;
  options.ip = *ip;
  options.port = args[2].As<Uint32>()->Value();

  return std::make_unique<GetNameInfoWrap>(env, obj, options);
}

int GetNameInfoTraits::Dispatch(GetNameInfoWrap* req_wrap) {
  // TODO(@jasnell): Re-enable trace events
  // TRACE_EVENT_NESTABLE_ASYNC_BEGIN2(
  //     TRACING_CATEGORY_NODE2(dns, native), "lookupService", req_wrap.get(),
  //     "ip", TRACE_STR_COPY(*ip), "port", port);

  struct sockaddr_storage addr;
  CHECK(
      SocketAddress::ToSockAddr(
          AF_INET,
          req_wrap->options().ip.c_str(),
          req_wrap->options().port,
          &addr) ||
      SocketAddress::ToSockAddr(
          AF_INET6,
          req_wrap->options().ip.c_str(),
          req_wrap->options().port,
          &addr)
  );

  return req_wrap->Dispatch(uv_getnameinfo,
                            GetNameInfoTraits::After,
                            reinterpret_cast<struct sockaddr*>(&addr),
                            NI_NAMEREQD);
}

void uv::Initialize(Environment* env, v8::Local<v8::Object> target) {
  env->SetMethodNoSideEffect(target, "canonicalizeIP", CanonicalizeIP);

  GetAddrInfoWrap::Initialize(env, target);
  GetNameInfoWrap::Initialize(env, target);
}

}  // namespace dns
}  // namespace node
