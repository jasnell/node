#include "policy/policy-inl.h"
#include "env-inl.h"
#include "base_object-inl.h"
#include "async_wrap-inl.h"
#include "libplatform/libplatform.h"

#include "gtest/gtest.h"
#include "node_test_fixture.h"

#include <string>
#include <vector>

using node::policy::Policy;
using node::policy::Permissions;

class EnvironmentTest : public EnvironmentTestFixture {
 private:
  void TearDown() override {
    NodeTestFixture::TearDown();
  }
};

TEST(PolicyTest, Simple) {
  Policy policy;

  EXPECT_EQ(policy.is_grant_locked(), false);

  // Permissions are granted by default because of legacy
  EXPECT_EQ(policy.granted(Permissions::kFileSystem), true);
  EXPECT_EQ(policy.granted(Permissions::kFileSystem,
                           Permissions::kNet), true);

  // Deny everything
  policy.deny(Permissions::kPermissionsRoot);

#define V(name, _, __)                                                         \
  EXPECT_EQ(policy.granted(Permissions::k##name), false);
  PERMISSIONS(V)
#undef V

  // Grant everything
  policy.grant(Permissions::kPermissionsRoot);
#define V(name, _, __)                                                         \
  EXPECT_EQ(policy.granted(Permissions::k##name), true);
  PERMISSIONS(V)
#undef V

  policy.deny(Permissions::kNet);
  EXPECT_EQ(policy.granted(Permissions::kFileSystem), true);
  EXPECT_EQ(policy.granted(Permissions::kNet), false);
  EXPECT_EQ(policy.granted(Permissions::kNetDNS,
                           Permissions::kNetTCP,
                           Permissions::kNetTCPIn,
                           Permissions::kNetTCPOut,
                           Permissions::kNetTLS,
                           Permissions::kNetTLSLog,
                           Permissions::kNetUdp), false);

  policy.grant(Permissions::kNetTCP);
  EXPECT_EQ(policy.granted(Permissions::kNetDNS,
                           Permissions::kNetTLS,
                           Permissions::kNetTLSLog,
                           Permissions::kNetUdp), false);
  EXPECT_EQ(policy.granted(Permissions::kNetTCP,
                           Permissions::kNetTCPIn,
                           Permissions::kNetTCPOut), true);
  policy.deny(Permissions::kNetTCPOut);
  EXPECT_EQ(policy.granted(Permissions::kNetTCP), true);
  EXPECT_EQ(policy.granted(Permissions::kNetTCPIn), true);
  EXPECT_EQ(policy.granted(Permissions::kNetTCPOut), false);

  policy.lockGrant();
  EXPECT_EQ(policy.is_grant_locked(), true);

  // Granting after lockGrant has no effect
  policy.grant(Permissions::kNetTCPOut);
  EXPECT_EQ(policy.granted(Permissions::kNetTCPOut), false);
}

TEST(PolicyTest, SimpleByName) {
  Policy policy;

  EXPECT_EQ(policy.is_grant_locked(), false);

  // Permissions are granted by default because of legacy
  EXPECT_EQ(policy.grantedByName(std::string("fs")), true);
  EXPECT_EQ(policy.grantedByName(std::string("fs"),
                                 std::string("net")), true);

  // Deny everything
  policy.denyByName("*");

#define V(_, label, __)                                                        \
  EXPECT_EQ(policy.grantedByName(std::string(label)), false);
  PERMISSIONS(V)
#undef V

  // Grant everything
  policy.grantByName("*");
#define V(_, label, __)                                                        \
  EXPECT_EQ(policy.grantedByName(std::string(label)), true);
  PERMISSIONS(V)
#undef V

  policy.denyByName(std::string("net"));
  EXPECT_EQ(policy.grantedByName(std::string("fs")), true);
  EXPECT_EQ(policy.grantedByName(std::string("net")), false);
  EXPECT_EQ(policy.grantedByName(std::string("net.dns"),
                                 std::string("net.tcp"),
                                 std::string("net.tcp.in"),
                                 std::string("net.tcp.out"),
                                 std::string("net.tls"),
                                 std::string("net.tls.log"),
                                 std::string("net.udp")), false);

  policy.grantByName(std::string("net.tcp"));
  EXPECT_EQ(policy.grantedByName(std::string("net.dns"),
                                std::string("net.tls"),
                                std::string("net.tls.log"),
                                std::string("net.udp")), false);
  EXPECT_EQ(policy.grantedByName(std::string("net.tcp"),
                                 std::string("net.tcp.in"),
                                 std::string("net.tcp.out")), true);
  policy.denyByName(std::string("net.tcp.out"));
  EXPECT_EQ(policy.grantedByName(std::string("net.tcp")), true);
  EXPECT_EQ(policy.grantedByName(std::string("net.tcp.in")), true);
  EXPECT_EQ(policy.grantedByName(std::string("net.tcp.out")), false);

  policy.lockGrant();
  EXPECT_EQ(policy.is_grant_locked(), true);

  // Granting after lockGrant has no effect
  policy.grantByName(std::string("net.tcp.out"));
  EXPECT_EQ(policy.grantedByName(std::string("net.tcp.out")), false);
}

TEST(PolicyTest, Parse) {
  std::vector<std::string> errors;
  std::vector<Permissions> permissions =
      Policy::Parse(std::string("*,net.tls.log,fghi,net.tcp.out"), &errors);
  EXPECT_EQ(permissions.size(), 3);
  EXPECT_EQ(errors.size(), 1);
  EXPECT_EQ(errors[0], "fghi is not a known permission");
  EXPECT_EQ(permissions[0], Permissions::kPermissionsRoot);
  EXPECT_EQ(permissions[1], Permissions::kNetTLSLog);
  EXPECT_EQ(permissions[2], Permissions::kNetTCPOut);
}

TEST(PolicyTest, Apply) {
  {
    Policy policy;
    std::vector<std::string> errors;
    EXPECT_EQ(policy.is_grant_locked(), false);

    Policy::Apply(&policy, "*", "net.tcp.out", &errors);
    EXPECT_EQ(errors.size(), 0);
    EXPECT_EQ(policy.is_grant_locked(), true);
    EXPECT_EQ(policy.grantedByName("net.tcp.out"), true);
    EXPECT_EQ(policy.grantedByName("fs"), false);
  }

  {
    Policy policy;
    std::vector<std::string> errors;

    Policy::Apply(&policy, "experimental.wasi", "", &errors);
    EXPECT_EQ(errors.size(), 0);
    EXPECT_EQ(policy.grantedByName("net"), true);
    EXPECT_EQ(policy.grantedByName("fs"), true);
    EXPECT_EQ(policy.grantedByName("experimental.wasi"), false);
  }
}

TEST_F(EnvironmentTest, GetCurrent) {
  const v8::HandleScope handle_scope(isolate_);
  const Argv argv;
  Env env {handle_scope, argv};

  node::LoadEnvironment(*env, [&](const node::StartExecutionCallbackInfo& info)
                                  -> v8::MaybeLocal<v8::Value> {
    return v8::Null(isolate_);
  });

  std::vector<std::string> errors;
  Policy* policy = Policy::GetCurrent(env.context());
  EXPECT_NE(policy, nullptr);

  Policy::Apply(policy, "*", "fs,net", &errors);
  EXPECT_EQ(policy->grantedByName("fs"), true);
  EXPECT_EQ(policy->grantedByName("fs.in"), true);
  EXPECT_EQ(policy->grantedByName("fs.out"), true);
  EXPECT_EQ(policy->grantedByName("net"), true);
  EXPECT_EQ(policy->grantedByName("net.dns"), true);
  EXPECT_EQ(policy->grantedByName("net.tcp"), true);
  EXPECT_EQ(policy->grantedByName("net.tcp.in"), true);
  EXPECT_EQ(policy->grantedByName("net.tcp.out"), true);
  EXPECT_EQ(policy->grantedByName("net.tls"), true);
  EXPECT_EQ(policy->grantedByName("net.tls.log"), true);
  EXPECT_EQ(policy->grantedByName("net.udp"), true);

  // Will have no effect
  policy->grantByName("timing");

  EXPECT_EQ(policy->grantedByName("timing"), false);

  EXPECT_EQ(policy->granted(Permissions::kFileSystem), true);
  EXPECT_EQ(policy->granted(Permissions::kFileSystemIn), true);
  EXPECT_EQ(policy->granted(Permissions::kFileSystemOut), true);
  EXPECT_EQ(policy->granted(Permissions::kNet), true);
  EXPECT_EQ(policy->granted(Permissions::kNetDNS), true);
  EXPECT_EQ(policy->granted(Permissions::kNetTCP), true);
  EXPECT_EQ(policy->granted(Permissions::kNetTCPIn), true);
  EXPECT_EQ(policy->granted(Permissions::kNetTCPOut), true);
  EXPECT_EQ(policy->granted(Permissions::kNetTLS), true);
  EXPECT_EQ(policy->granted(Permissions::kNetTLSLog), true);
  EXPECT_EQ(policy->granted(Permissions::kNetUdp), true);

  EXPECT_EQ(policy->granted(Permissions::kTiming), false);
}
