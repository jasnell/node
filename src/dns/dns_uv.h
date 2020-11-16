#ifndef SRC_DNS_DNS_UV_H_
#define SRC_DNS_DNS_UV_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "async_wrap.h"
#include "req_wrap.h"
#include "env.h"
#include "uv.h"
#include "v8.h"

#include <string>

namespace node {
namespace dns {

template <typename GetInfoTraits>
class GetInfoWrap : public ReqWrap<typename GetInfoTraits::Type> {
 public:
  using Options = typename GetInfoTraits::Options;
  using Type = typename GetInfoTraits::Type;

  static void Initialize(Environment* env, v8::Local<v8::Object> target) {
    env->SetMethod(target, GetInfoTraits::Name, Request);

    v8::Local<v8::FunctionTemplate> wrap =
        BaseObject::MakeLazilyInitializedJSTemplate(env);
    wrap->Inherit(AsyncWrap::GetConstructorTemplate(env));
    v8::Local<v8::String> class_name =
        OneByteString(env->isolate(), GetInfoTraits::ClassName);
    wrap->SetClassName(class_name);
    target->Set(env->context(),
                class_name,
                wrap->GetFunction(env->context()).ToLocalChecked()).Check();
  }

  static void Request(const v8::FunctionCallbackInfo<v8::Value>& args) {
    CHECK(args[0]->IsObject());   // The req_wrap object
    Environment* env = Environment::GetCurrent(args);
    auto req_wrap = GetInfoTraits::Create(env, args[0].As<v8::Object>(), args);
    int err = req_wrap->Run();
    if (err == 0)
      USE(req_wrap.release());
    args.GetReturnValue().Set(err);
  }

  GetInfoWrap(
      Environment* env,
      v8::Local<v8::Object> obj,
      const Options& options)
      : ReqWrap<Type>(
            env,
            obj,
            GetInfoTraits::Provider),
        options_(options) {}

  const Options& options() const { return options_; }

  int Run() {
    return GetInfoTraits::Dispatch(this);
  }

  static GetInfoWrap<GetInfoTraits>* FromHandle(Type* req) {
    return static_cast<GetInfoWrap<GetInfoTraits>*>(req->data);
  }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(GetInfoWrap)
  SET_SELF_SIZE(GetInfoWrap)

 private:
  Options options_;
};

struct GetAddrInfoTraits {
  using Type = uv_getaddrinfo_t;
  static constexpr const char* Name = "getaddrinfo";
  static constexpr const char* ClassName = "GetAddrInfoWrap";
  static constexpr AsyncWrap::ProviderType Provider =
     AsyncWrap::PROVIDER_GETADDRINFOREQWRAP;

  struct Options {
    std::string hostname;
    int32_t family = AF_UNSPEC;
    int32_t flags = 0;
    bool verbatim = false;
  };

  static void After(
      uv_getaddrinfo_t* req,
      int status,
      struct addrinfo* res);

  static std::unique_ptr<GetInfoWrap<GetAddrInfoTraits>> Create(
      Environment* env,
      v8::Local<v8::Object> obj,
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static int Dispatch(GetInfoWrap<GetAddrInfoTraits>* req_wrap);
};

struct GetNameInfoTraits {
  using Type = uv_getnameinfo_t;
  static constexpr const char* Name = "getnameinfo";
  static constexpr const char* ClassName = "GetNameInfoWrap";
  static constexpr AsyncWrap::ProviderType Provider =
     AsyncWrap::PROVIDER_GETNAMEINFOREQWRAP;

  struct Options {
    std::string ip;
    unsigned port = 0;
  };

  static void After(
      uv_getnameinfo_t* req,
      int status,
      const char* hostname,
      const char* service);

  static std::unique_ptr<GetInfoWrap<GetNameInfoTraits>> Create(
      Environment* env,
      v8::Local<v8::Object> obj,
      const v8::FunctionCallbackInfo<v8::Value>& args);

  static int Dispatch(GetInfoWrap<GetNameInfoTraits>* req_wrap);
};

using GetAddrInfoWrap = GetInfoWrap<GetAddrInfoTraits>;
using GetNameInfoWrap = GetInfoWrap<GetNameInfoTraits>;

namespace uv {
void Initialize(Environment* env, v8::Local<v8::Object> target);
}  // namespace uv

}  // namespace dns
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_DNS_DNS_UV_U_
