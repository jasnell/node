#include "node_options.h"

#include "gtest/gtest.h"

using node::options::Option;
using node::options::OptionsConfig;
using node::options::OptionsParser;

class OptionsTest : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}
};

unsigned int cbCalled = 0;

void noop(Option* option) {}
void noop(Option* option, const char* arg, size_t len) {}

TEST_F(OptionsTest, InvalidOption) {

  OptionsConfig config = {noop, noop, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "--this-is-not-a-valid-option" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);

  EXPECT_EQ(ret, OptionsParser::kInvalidOption);
}

TEST_F(OptionsTest, HelpCommand) {
  cbCalled = 0;

  auto oncommand = [](Option* option) {
    EXPECT_EQ(option->id(), Option::NODE_OPTION_ID_HELP);
    EXPECT_EQ(option->type(), Option::kCommand);
    EXPECT_EQ(option->flags(), Option::kDefault);
    cbCalled = 1;
  };
  OptionsConfig config = {oncommand, noop, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "--help" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);
  EXPECT_EQ(ret, 2);

  EXPECT_EQ(parser.exec_argv()->size(), 0u);

  EXPECT_EQ(parser.v8_argv()->size(), 1u);
  EXPECT_EQ((*parser.v8_argv())[0], "node");

  EXPECT_EQ(cbCalled, 1u);
}

TEST_F(OptionsTest, VersionCommand) {
  cbCalled = 0;

  auto oncommand = [](Option* option) {
    EXPECT_EQ(option->id(), Option::NODE_OPTION_ID_VERSION);
    EXPECT_EQ(option->type(), Option::kCommand);
    EXPECT_EQ(option->flags(), Option::kDefault);
    cbCalled = 1;
  };
  OptionsConfig config = {oncommand, noop, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "--version" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);
  EXPECT_EQ(ret, 2);

  EXPECT_EQ(parser.exec_argv()->size(), 0u);

  EXPECT_EQ(parser.v8_argv()->size(), 1u);
  EXPECT_EQ((*parser.v8_argv())[0], "node");

  EXPECT_EQ(cbCalled, 1u);
}

TEST_F(OptionsTest, V8OptionsCommand) {
  cbCalled = 0;

  auto oncommand = [](Option* option) {
    EXPECT_EQ(option->id(), Option::NODE_OPTION_ID_V8_OPTIONS);
    EXPECT_EQ(option->type(), Option::kCommand);
    EXPECT_EQ(option->flags(), Option::kDefault);
    cbCalled = 1;
  };
  OptionsConfig config = {oncommand, noop, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "--v8-options" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);
  EXPECT_EQ(ret, 2);

  EXPECT_EQ(parser.exec_argv()->size(), 0u);

  EXPECT_EQ(parser.v8_argv()->size(), 1u);
  EXPECT_EQ((*parser.v8_argv())[0], "node");

  EXPECT_EQ(cbCalled, 1u);
}

TEST_F(OptionsTest, CheckOption) {
  cbCalled = 0;

  auto onboolean = [](Option* option) {
    EXPECT_EQ(option->id(), Option::NODE_OPTION_ID_CHECK);
    EXPECT_EQ(option->type(), Option::kBoolean);
    EXPECT_EQ(option->flags(), Option::kDefault);
    cbCalled = 1;
  };
  OptionsConfig config = {noop, onboolean, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "--check" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);
  EXPECT_EQ(ret, 2);

  EXPECT_EQ(parser.exec_argv()->size(), 0u);

  EXPECT_EQ(parser.v8_argv()->size(), 1u);
  EXPECT_EQ((*parser.v8_argv())[0], "node");

  EXPECT_EQ(cbCalled, 1u);
}

TEST_F(OptionsTest, CheckOption2) {
  cbCalled = 0;

  auto onboolean = [](Option* option) {
    EXPECT_EQ(option->id(), Option::NODE_OPTION_ID_CHECK);
    EXPECT_EQ(option->type(), Option::kBoolean);
    EXPECT_EQ(option->flags(), Option::kDefault);
    cbCalled = 1;
  };
  OptionsConfig config = {noop, onboolean, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "-c" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);
  EXPECT_EQ(ret, 2);

  EXPECT_EQ(parser.exec_argv()->size(), 0u);

  EXPECT_EQ(parser.v8_argv()->size(), 1u);
  EXPECT_EQ((*parser.v8_argv())[0], "node");

  EXPECT_EQ(cbCalled, 1u);
}

TEST_F(OptionsTest, AbortOnUncaughtExceptionOption) {
  cbCalled = 0;

  auto onboolean = [](Option* option) {
    EXPECT_EQ(option->id(), Option::NODE_OPTION_ID_ABORT_ON_UNCAUGHT_EXCEPTION);
    EXPECT_EQ(option->type(), Option::kBoolean);
    EXPECT_EQ(option->flags(), Option::kAllowEnv);
    cbCalled = 1;
  };
  OptionsConfig config = {noop, onboolean, noop};
  OptionsParser parser(&config);

  const char* args[] { "node", "--abort-on-uncaught-exception" };
  size_t size = sizeof(args) / sizeof(const char*);

  ssize_t ret = parser.Parse(size, args);
  EXPECT_EQ(ret, 2);

  EXPECT_EQ(parser.exec_argv()->size(), 0u);

  EXPECT_EQ(parser.v8_argv()->size(), 1u);
  EXPECT_EQ((*parser.v8_argv())[0], "node");

  EXPECT_EQ(cbCalled, 1u);
}
