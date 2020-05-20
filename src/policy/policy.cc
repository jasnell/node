#include "policy/policy-inl.h"
#include "env-inl.h"
#include "aliased_struct-inl.h"
#include "base_object-inl.h"
#include "memory_tracker-inl.h"
#include "v8.h"
#include "util-inl.h"

#include <string>
#include <vector>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace policy {

class BindingData : public BaseObject {
 public:
  BindingData(Environment* env, Local<Object> wrap)
      : BaseObject(env, wrap),
        detail(env->isolate()) {}

  static constexpr FastStringKey binding_data_name { "policy" };

  AliasedStruct<BindingDetail> detail;

  SET_NO_MEMORY_INFO()
  SET_SELF_SIZE(BindingData)
  SET_MEMORY_INFO_NAME(BindingData)
};

static void Deny(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Policy* policy = Policy::GetCurrent(env);

  CHECK(args[0]->IsString());
  Utf8Value value(env->isolate(), args[0]);
  std::string input(*value, value.length());

  std::vector<std::string> errors;
  std::vector<Permissions> permissions = Policy::Parse(input, &errors);

  if (errors.size() > 0) {
    return env->ThrowError("TODO: Proper error message");
  }

  for (Permissions permission : permissions) {
    policy->deny(permission);
  }
}

static void GetCurrent(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Policy* policy = Policy::GetCurrent(env);
  BindingData* const binding_data =
      env->GetBindingData<BindingData>(env->context());

#define V(name, label, __) \
  binding_data->detail->##name = policy->granted(Permissions::k##name) ? 1 : 0;
  PERMISSIONS(V)
#undef V
}

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);

  BindingData* const binding_data =
      env->AddBindingData<BindingData>(context, target);
  if (binding_data == nullptr) return;

  if (!target->Set(context,
                   FIXED_ONE_BYTE_STRING(env->isolate(), "detail"),
                   binding_data->detail.GetArrayBuffer()).FromJust()) {
    return;
  }

  Local<Object> nameMap = Object::New(env->isolate());
#define V(name, label, _)                                                      \
  nameMap->Set(context,                                                        \
               FIXED_ONE_BYTE_STRING(env->isolate(), label),                   \
               Integer::New(env->isolate(),                                    \
                            static_cast<int32_t>(Permissions::k##name)))       \
                              .FromJust();
  PERMISSIONS(V)
#undef V
  target->Set(context,
              FIXED_ONE_BYTE_STRING(env->isolate(), "nameMap"),
              nameMap).FromJust();

  env->SetMethodNoSideEffect(target, "getCurrent", GetCurrent);
  env->SetMethod(target, "deny", Deny);
}

}  // namespace policy
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(policy, node::policy::Initialize)
