#ifndef SRC_NODE_OPTIONS_H_
#define SRC_NODE_OPTIONS_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"

#include <string>
#include <vector>

namespace node {

namespace options {

#define NODE_OPTION_COUNT(...) \
  sizeof((const char*[]) {__VA_ARGS__}) / sizeof(const char*)
#define NODE_OPTION_ALIASES(...) __VA_ARGS__

#define NODE_OPTIONS(V)                                                       \
  V(HELP, Command, Default,                                                   \
    NODE_OPTION_ALIASES("--help", "-h"))                                      \
  V(VERSION, Command, Default,                                                \
    NODE_OPTION_ALIASES("--version", "-v"))                                   \
  V(V8_OPTIONS, Command, Default,                                             \
    NODE_OPTION_ALIASES("--v8-options",                                       \
                        "--v8_options"))                                      \
  V(ABORT_ON_UNCAUGHT_EXCEPTION, Boolean, AllowEnv,                           \
    NODE_OPTION_ALIASES("--abort-on-uncaught-exception",                      \
                        "--abort_on_uncaught_exception"))                     \
  V(USE_CA, Argument, AllowEnv,                                               \
    NODE_OPTION_ALIASES("--use-bundled-ca",                                   \
                        "--use_bundled_ca",                                   \
                        "--use-openssl-ca",                                   \
                        "--use_openssl_ca"))                                  \
  V(CHECK, Boolean, Default,                                                  \
    NODE_OPTION_ALIASES("--check", "-c"))                                     \
  V(ENABLE_FIPS, Boolean, AllowEnv,                                           \
    NODE_OPTION_ALIASES("--enable-fips",                                      \
                        "--enable_fips"))                                     \
  V(EXPOSE_HTTP2, Boolean, AllowEnv,                                          \
    NODE_OPTION_ALIASES("--expose-http2",                                     \
                        "--expose_http2"))                                    \
  V(EXPOSE_INTERNALS, Boolean, Default,                                       \
    NODE_OPTION_ALIASES("--expose-internals",                                 \
                        "--expose_internals"))                                \
  V(FORCE_FIPS, Boolean, AllowEnv,                                            \
    NODE_OPTION_ALIASES("--force-fips",                                       \
                        "--force_fips"))                                      \
  V(ICU_DATA_DIR, Argument, AllowEnv,                                         \
    NODE_OPTION_ALIASES("--icu-data-dir",                                     \
                        "--icu_data_dir"))                                    \
  V(INSPECT, Argument, AllowEnv,                                              \
    NODE_OPTION_ALIASES("--debug",                                            \
                        "--debug-brk",                                        \
                        "--inspect",                                          \
                        "--inspect-brk"))                                     \
  V(INSPECT_PORT, Argument, AllowEnv,                                         \
    NODE_OPTION_ALIASES("--debug-port",                                       \
                        "--inspect-port"))                                    \
  V(INTERACTIVE, Boolean, Default,                                            \
    NODE_OPTION_ALIASES("--interactive", "-i"))                               \
  V(NAPI_MODULES, Boolean, AllowEnv,                                          \
    NODE_OPTION_ALIASES("--napi-modules",                                     \
                        "--napi_modules"))                                    \
  V(NO_DEPRECATION, Boolean, AllowEnv,                                        \
    NODE_OPTION_ALIASES("--no-deprecation",                                   \
                        "--no_deprecation"))                                  \
  V(NO_WARNINGS, Boolean, AllowEnv,                                           \
    NODE_OPTION_ALIASES("--no-warnings",                                      \
                        "--no_warnings"))                                     \
  V(OPENSSL_CONFIG, Argument, AllowEnv,                                       \
    NODE_OPTION_ALIASES("--openssl-config",                                   \
                        "--openssl_config"))                                  \
  V(PENDING_DEPRECATION, Boolean, AllowEnv,                                   \
    NODE_OPTION_ALIASES("--pending-deprecation",                              \
                        "--pending_deprecation"))                             \
  V(PRESERVE_SYMLINKS, Boolean, AllowEnv,                                     \
    NODE_OPTION_ALIASES("--preserve-symlinks",                                \
                        "--preserve_symlinks"))                               \
  V(PRINT_EVAL, Argument, Default,                                            \
    NODE_OPTION_ALIASES("--eval", "-e", "--print", "-p", "-pe"))              \
  V(PROF_PROCESS, Boolean, AllowEnv,                                          \
    NODE_OPTION_ALIASES("--prof-process",                                     \
                        "--prof_process"))                                    \
  V(REDIRECT_WARNINGS, Argument, AllowEnv,                                    \
    NODE_OPTION_ALIASES("--redirect-warnings",                                \
                        "--redirect_warnings"))                               \
  V(REQUIRE, Argument, AllowEnv,                                              \
    NODE_OPTION_ALIASES("--require", "-r"))                                   \
  V(SECURITY_REVERT, Argument, Default,                                       \
    NODE_OPTION_ALIASES("--security-revert",                                  \
                        "--security_revert"))                                 \
  V(THROW_DEPRECATION, Boolean, AllowEnv,                                     \
    NODE_OPTION_ALIASES("--throw-deprecation",                                \
                        "--throw_deprecation"))                               \
  V(TLS_CIPHER_LIST, Argument, AllowEnv,                                      \
    NODE_OPTION_ALIASES("--tls-cipher-list",                                  \
                        "--tls_cipher_list"))                                 \
  V(TRACE_DEPRECATION, Boolean, AllowEnv,                                     \
    NODE_OPTION_ALIASES("--trace-deprecation",                                \
                        "--trace_deprecation"))                               \
  V(TRACE_EVENT_CATEGORIES, Argument, AllowEnv,                               \
    NODE_OPTION_ALIASES("--trace-event-categories",                           \
                        "--trace_event_categories"))                          \
  V(TRACE_EVENTS_ENABLED, Boolean, AllowEnv,                                  \
    NODE_OPTION_ALIASES("--trace-events-enabled",                             \
                        "--trace_events_enabled"))                            \
  V(TRACE_SYNC_IO, Boolean, AllowEnv,                                         \
    NODE_OPTION_ALIASES("--trace-sync-io",                                    \
                        "--trace_sync_io"))                                   \
  V(TRACE_WARNINGS, Boolean, AllowEnv,                                        \
    NODE_OPTION_ALIASES("--trace-warnings",                                   \
                        "--trace_warnings"))                                  \
  V(TRACK_HEAP_OBJECTS, Boolean, AllowEnv,                                    \
    NODE_OPTION_ALIASES("--track-heap-objects",                               \
                        "--trace_heap_objects"))                              \
  V(ZERO_FILL_BUFFERS, Boolean, AllowEnv,                                     \
    NODE_OPTION_ALIASES("--zero-fill-buffers",                                \
                        "--zero_fill_buffers"))

class Option {
 public:

  enum OptionID {
#define V(name, ...) NODE_OPTION_ID_##name,
    NODE_OPTIONS(V)
#undef V
    NODE_OPTION_ID_INVALID
  };

  enum OptionType {
    kCommand,   // Option is a command
    kBoolean,   // Option sets a boolean configuration flag
    kArgument   // Option sets a const char configuration flag
  };

  enum OptionFlags {
    kDefault = 0x0,
    kAllowEnv = 0x1,        // Option may appear in NODE_OPTIONS env
  };

  static OptionID ToOptionID(const char* arg) {
#define V(id, _, __, ...)                                                     \
  do {                                                                        \
    const char* aliases[NODE_OPTION_COUNT(__VA_ARGS__)] {__VA_ARGS__};        \
    size_t count = arraysize(aliases);                                        \
    for (size_t n = 0; n < count; n++) {                                      \
      if (strncmp(arg, aliases[n], strlen(aliases[n])) == 0)                  \
        return NODE_OPTION_ID_##id;                                           \
    }                                                                         \
  } while (0);
  NODE_OPTIONS(V)
#undef V
    return NODE_OPTION_ID_INVALID;
  }

  Option(OptionID id,
         OptionType type,
         int flags,
         size_t count,
         const char* aliases[]) :
         id_(id),
         type_(type),
         flags_(flags) {}
  ~Option() {}

  OptionID id() const {
    return id_;
  }

  OptionType type() const {
    return type_;
  }

  int flags() const {
    return flags_;
  }

 private:
  OptionID id_;
  OptionType type_;
  int flags_;
};

typedef void (*command_cb)(Option* option);
typedef void (*boolean_cb)(Option* option);
typedef void (*argument_cb)(Option* option, const char* arg, size_t len);

struct OptionsConfig {
  command_cb oncommand;
  boolean_cb onboolean;
  argument_cb onargument;
};

class OptionsParser {
 public:
  enum ParseFlags {
    kNone,
    kEnvironment
  };

  enum ParseErrors {
    kInvalidOption = -1,
    kOptionNotPermittedInEnvironment = -2
  };

  OptionsParser(OptionsConfig* config = 0) {
    if (config != nullptr) {
      oncommand_ = config->oncommand;
      onboolean_ = config->onboolean;
      onargument_ = config->onargument;
    }
  }
  ~OptionsParser() {}

  ssize_t Parse(
    int argc,
    const char** argv,
    ParseFlags flags = kNone);

  std::vector<const char*>* exec_argv() {
    return &exec_argv_;
  }

  std::vector<const char*>* v8_argv() {
    return &v8_argv_;
  }

  std::vector<const char*>* new_argv() {
    return &new_argv_;
  }

 private:
  command_cb oncommand_ = nullptr;
  boolean_cb onboolean_ = nullptr;
  argument_cb onargument_ = nullptr;
  std::vector<const char*> exec_argv_;
  std::vector<const char*> v8_argv_;
  std::vector<const char*> new_argv_;

  // Options are registered statically. Add new options by adding them to the
  // NODE_OPTIONS macro above.
  Option options_[Option::NODE_OPTION_ID_INVALID] {
#define V(id, type, flags, ...)                                               \
  Option(Option::NODE_OPTION_ID_##id,                                         \
         Option::k##type,                                                     \
         Option::k##flags,                                                    \
         NODE_OPTION_COUNT(__VA_ARGS__),                                      \
         (const char*[]) {__VA_ARGS__}),
  NODE_OPTIONS(V)
#undef V
  };
};

}  // namespace options

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_OPTIONS_H_
