#ifndef SRC_POLICY_POLICY_INL_H_
#define SRC_POLICY_POLICY_INL_H_

#include "policy/policy.h"
#include "node_errors.h"
#include "env-inl.h"

#include <array>
#include <string>
#include <vector>

namespace node {
namespace policy {

Policy* Policy::GetCurrent(Environment* env) {
  return GetCurrent(env->context());
}

Policy* Policy::GetCurrent(v8::Isolate* isolate) {
  return GetCurrent(isolate->GetCurrentContext());
}

Policy* Policy::GetCurrent(v8::Local<v8::Context> context) {
  if (UNLIKELY(context.IsEmpty())) {
    return nullptr;
  }
  if (UNLIKELY(context->GetNumberOfEmbedderDataFields() <=
               ContextEmbedderIndex::kPolicyIndex)) {
    return nullptr;
  }
  Policy* policy = static_cast<Policy*>(
      context->GetAlignedPointerFromEmbedderData(
          ContextEmbedderIndex::kPolicyIndex));
  return policy;
}

bool Policy::test(Permissions permission) const {
  return !permissions_.test(static_cast<size_t>(permission));
}

#define V(name, _, parent)                                                     \
  if (permission == Permissions::k##parent)                                    \
    SetRecursively(Permissions::k##name, value);
void Policy::SetRecursively(Permissions permission, bool value) {
  if (permission != Permissions::kPermissionsRoot)
    permissions_[static_cast<size_t>(permission)] = value;
  PERMISSIONS(V)
}
#undef V

template <typename...P>
bool Policy::granted(P...permissions) const {
  std::array<Permissions, sizeof...(permissions)> perms {
    std::forward<P>(permissions)...
  };
  for (Permissions permission : perms) {
    if (UNLIKELY(!test(permission)))
      return false;
  }
  return true;
}

template <typename...P>
void Policy::grant(P... permissions) {
  if (locked_) return;
  std::array<Permissions, sizeof...(permissions)> perms {
    std::forward<P>(permissions)...
  };
  for (Permissions permission : perms)
    SetRecursively(permission, false);
}

template <typename...P>
void Policy::deny(P... permissions) {
  std::array<Permissions, sizeof...(permissions)> perms {
    std::forward<P>(permissions)...
  };
  for (Permissions permission : perms)
    SetRecursively(permission, true);
}

#define V(Name, label, _)                                                      \
  if (strcmp(name.c_str(), label) == 0) return Permissions::k##Name;
Permissions Policy::PermissionFromName(const std::string& name) {
  if (strcmp(name.c_str(), "*") == 0) return Permissions::kPermissionsRoot;
  PERMISSIONS(V)
  return Permissions::kPermissionsCount;
}
#undef V

template <typename...P>
bool Policy::grantedByName(P...permissions) const {
  std::array<std::string, sizeof...(permissions)> perms {
    std::forward<P>(permissions)...
  };
  for (std::string& name : perms) {
    Permissions permission = PermissionFromName(name);
    if (permission == Permissions::kPermissionsCount || !granted(permission))
      return false;
  }
  return true;
}

template <typename...P>
void Policy::grantByName(P... permissions) {
  if (locked_) return;
  std::array<std::string, sizeof...(permissions)> perms {
    std::forward<P>(permissions)...
  };
  for (std::string& name : perms) {
    Permissions permission = PermissionFromName(name);
    if (permission != Permissions::kPermissionsCount)
      grant(permission);
  }
}

template <typename...P>
void Policy::denyByName(P... permissions) {
  if (locked_) return;
  std::array<std::string, sizeof...(permissions)> perms {
    std::forward<P>(permissions)...
  };
  for (std::string& name : perms) {
    Permissions permission = PermissionFromName(name);
    if (permission != Permissions::kPermissionsCount)
      deny(permission);
  }
}

std::vector<Permissions> Policy::Parse(
    const std::string& permissions,
    std::vector<std::string>* errors) {
  std::vector<Permissions> perms;
  std::string::size_type pos = 0;
  std::string::size_type index = 0;
  Permissions perm;
  std::string name;

  while ((index = permissions.find_first_of(",", pos)) != std::string::npos) {
    name = permissions.substr(pos, index - pos);
    if (name.length() == 0)
      continue;
    perm = PermissionFromName(name);
    if (perm == Permissions::kPermissionsCount) {
      errors->push_back(name + " is not a known permission");
    } else {
      perms.push_back(perm);
    }
    pos = index + 1;
  }

  name = permissions.substr(pos);
  if (name.length() > 0) {
    perm = PermissionFromName(name);
    if (perm == Permissions::kPermissionsCount) {
      errors->push_back(name + " is not a known permission");
    } else {
      perms.push_back(perm);
    }
  }

  return perms;
}

void Policy::Apply(
    Policy* policy,
    const std::string& deny,
    const std::string& grant,
    std::vector<std::string>* errors) {
  // Special categories are always disabled by default
  policy->grant(Permissions::kPermissionsRoot);
  policy->deny(Permissions::kSpecial);
  for (Permissions permission : Parse(deny, errors)) {
    policy->deny(permission);
  }

  if (!policy->is_grant_locked()) {
    for (Permissions permission : Parse(grant, errors))
      policy->grant(permission);
    policy->lockGrant();
  }
}

template <typename...P>
PolicyEnforcedScope::PolicyEnforcedScope(Environment* env, P...permissions) {
  Policy* policy = Policy::GetCurrent(env);
  if (!policy->granted(permissions...)) {
    threw = true;
    env->isolate()->ThrowException(ERR_ACCESS_DENIED(env->isolate()));
  }
}

}  // namespace policy
}  // namespace node

#endif  // SRC_POLICY_POLICY_INL_H_
