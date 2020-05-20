#ifndef SRC_POLICY_POLICY_H_
#define SRC_POLICY_POLICY_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "v8.h"

#include <bitset>
#include <string>
#include <vector>

namespace node {

class Environment;

namespace policy {

#define PERMISSIONS(V)                                                         \
  V(Special, "special", PermissionsRoot)                                       \
  V(SpecialInspector, "special.inspector", Special)                            \
  V(SpecialAddons, "special.addons", Special)                                  \
  V(SpecialChildProcess, "special.child_process", Special)                     \
  V(Workers, "workers", PermissionsRoot)                                       \
  V(FileSystem, "fs", PermissionsRoot)                                         \
  V(FileSystemIn, "fs.in", FileSystem)                                         \
  V(FileSystemOut, "fs.out", FileSystem)                                       \
  V(User, "user", PermissionsRoot)                                             \
  V(Net, "net", PermissionsRoot)                                               \
  V(NetUdp, "net.udp", Net)                                                    \
  V(NetDNS, "net.dns", Net)                                                    \
  V(NetTCP, "net.tcp", Net)                                                    \
  V(NetTCPIn, "net.tcp.in", NetTCP)                                            \
  V(NetTCPOut, "net.tcp.out", NetTCP)                                          \
  V(NetTLS, "net.tls", Net)                                                    \
  V(NetTLSLog, "net.tls.log", NetTLS)                                          \
  V(Process, "process", PermissionsRoot)                                       \
  V(Timing, "timing", PermissionsRoot)                                         \
  V(Signal, "signal", PermissionsRoot)                                         \
  V(Experimental, "experimental", PermissionsRoot)                             \
  V(ExperimentalWasi, "experimental.wasi", Experimental)

#define V(name, _, __) k##name,
enum class Permissions {
  kPermissionsRoot = -1,
  PERMISSIONS(V)
  kPermissionsCount
};
#undef V

class Policy {
 public:
  inline static Policy* GetCurrent(Environment* env);
  inline static Policy* GetCurrent(v8::Isolate* isolate);
  inline static Policy* GetCurrent(v8::Local<v8::Context> context);

  inline static std::vector<Permissions>Parse(
      const std::string& permissions,
      std::vector<std::string>* errors);

  inline static void Apply(
      Policy* policy,
      const std::string& deny,
      const std::string& grant,
      std::vector<std::string>* errors);

  void lockGrant() { locked_ = true; }

  bool is_grant_locked() const { return locked_; }

  template <typename...P>
  bool granted(P... permissions) const;

  template <typename...P>
  bool grantedByName(P... permissions) const;

  template <typename...P>
  void grant(P... permissions);

  template <typename...P>
  void grantByName(P... permissions);

  template <typename...P>
  void deny(P... permissions);

  template <typename...P>
  void denyByName(P... permissions);

 private:
  inline static Permissions PermissionFromName(const std::string& name);
  inline bool test(Permissions permission) const;
  inline void SetRecursively(Permissions permission, bool value);

  bool locked_ = false;
  std::bitset<static_cast<size_t>(
      Permissions::kPermissionsCount)> permissions_;
};

struct PolicyEnforcedScope {
  template <typename...P>
  PolicyEnforcedScope(Environment* env, P...permissions);
  bool threw = false;
};

struct BindingDetail {
#define V(name, _, __) uint8_t name;
  PERMISSIONS(V)
#undef V
};

}  // namespace policy
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_POLICY_POLICY_H_
