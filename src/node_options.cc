#include "node.h"
#include "node_options.h"

namespace node {

namespace options {

ssize_t OptionsParser::Parse(int argc, const char** argv, ParseFlags flags) {
  const size_t nargs = static_cast<size_t>(argc);

  bool short_circuit = false;
  size_t index = 1;

  v8_argv_.push_back(argv[0]);
  new_argv_.push_back(argv[0]);

  while (index < nargs && argv[index][0] == '-' && !short_circuit) {
    const char* const arg = argv[index];
    Option::OptionID id = Option::ToOptionID(arg);
    if (id == Option::NODE_OPTION_ID_INVALID)
      return kInvalidOption;
    Option option = options_[id];
    if ((flags & kEnvironment) && !(option.flags() & Option::kAllowEnv))
      return kOptionNotPermittedInEnvironment;
    switch (option.type()) {
      case Option::kCommand:
        if (oncommand_ != nullptr)
          oncommand_(&option);
        break;
      case Option::kBoolean:
        if (onboolean_ != nullptr)
          onboolean_(&option);
        break;
      case Option::kArgument:
        if (onargument_ != nullptr)
          onargument_(&option, "", 0);
        break;
      default:
        ABORT();
    }
    size_t consumed = 1;
    index += consumed;
  }
  return index;
}

// static void ParseArgs(int* argc,
//                       const char** argv,
//                       int* exec_argc,
//                       const char*** exec_argv,
//                       int* v8_argc,
//                       const char*** v8_argv,
//                       bool is_env) {
//   const unsigned int nargs = static_cast<unsigned int>(*argc);
//   const char** new_exec_argv = new const char*[nargs];
//   const char** new_v8_argv = new const char*[nargs];
//   const char** new_argv = new const char*[nargs];
// #if HAVE_OPENSSL
//   bool use_bundled_ca = false;
//   bool use_openssl_ca = false;
// #endif  // HAVE_OPENSSL

//   for (unsigned int i = 0; i < nargs; ++i) {
//     new_exec_argv[i] = nullptr;
//     new_v8_argv[i] = nullptr;
//     new_argv[i] = nullptr;
//   }

//   // exec_argv starts with the first option, the other two start with argv[0].
//   unsigned int new_exec_argc = 0;
//   unsigned int new_v8_argc = 1;
//   unsigned int new_argc = 1;
//   new_v8_argv[0] = argv[0];
//   new_argv[0] = argv[0];

//   unsigned int index = 1;
//   bool short_circuit = false;
//   while (index < nargs && argv[index][0] == '-' && !short_circuit) {
//     const char* const arg = argv[index];
//     unsigned int args_consumed = 1;

//     CheckIfAllowedInEnv(argv[0], is_env, arg);

//     if (debug_options.ParseOption(argv[0], arg)) {
//       // Done, consumed by DebugOptions::ParseOption().
//     } else if (strcmp(arg, "--eval") == 0 ||
//                strcmp(arg, "-e") == 0 ||
//                strcmp(arg, "--print") == 0 ||
//                strcmp(arg, "-pe") == 0 ||
//                strcmp(arg, "-p") == 0) {
//       bool is_eval = strchr(arg, 'e') != nullptr;
//       bool is_print = strchr(arg, 'p') != nullptr;
//       print_eval = print_eval || is_print;
//       // --eval, -e and -pe always require an argument.
//       if (is_eval == true) {
//         args_consumed += 1;
//         eval_string = argv[index + 1];
//         if (eval_string == nullptr) {
//           fprintf(stderr, "%s: %s requires an argument\n", argv[0], arg);
//           exit(9);
//         }
//       } else if ((index + 1 < nargs) &&
//                  argv[index + 1] != nullptr &&
//                  argv[index + 1][0] != '-') {
//         args_consumed += 1;
//         eval_string = argv[index + 1];
//         if (strncmp(eval_string, "\\-", 2) == 0) {
//           // Starts with "\\-": escaped expression, drop the backslash.
//           eval_string += 1;
//         }
//       }
//     } else if (strcmp(arg, "--require") == 0 ||
//                strcmp(arg, "-r") == 0) {
//       const char* module = argv[index + 1];
//       if (module == nullptr) {
//         fprintf(stderr, "%s: %s requires an argument\n", argv[0], arg);
//         exit(9);
//       }
//       args_consumed += 1;
//       preload_modules.push_back(module);
//     } else if (strcmp(arg, "--trace-event-categories") == 0) {
//       const char* categories = argv[index + 1];
//       if (categories == nullptr) {
//         fprintf(stderr, "%s: %s requires an argument\n", argv[0], arg);
//         exit(9);
//       }
//       args_consumed += 1;
//       trace_enabled_categories = categories;
//     } else if (strcmp(arg, "--v8-options") == 0) {
//       new_v8_argv[new_v8_argc] = "--help";
//       new_v8_argc += 1;
//     } else if (strncmp(arg, "--v8-pool-size=", 15) == 0) {
//       v8_thread_pool_size = atoi(arg + 15);
// #if HAVE_OPENSSL
//     } else if (strncmp(arg, "--tls-cipher-list=", 18) == 0) {
//       default_cipher_list = arg + 18;
//     } else if (strncmp(arg, "--use-openssl-ca", 16) == 0) {
//       ssl_openssl_cert_store = true;
//       use_openssl_ca = true;
//     } else if (strncmp(arg, "--use-bundled-ca", 16) == 0) {
//       use_bundled_ca = true;
//       ssl_openssl_cert_store = false;
// #if NODE_FIPS_MODE
//     } else if (strcmp(arg, "--enable-fips") == 0) {
//       enable_fips_crypto = true;
//     } else if (strcmp(arg, "--force-fips") == 0) {
//       force_fips_crypto = true;
// #endif /* NODE_FIPS_MODE */
//     } else if (strncmp(arg, "--openssl-config=", 17) == 0) {
//       openssl_config.assign(arg + 17);
// #endif /* HAVE_OPENSSL */
// #if defined(NODE_HAVE_I18N_SUPPORT)
//     } else if (strncmp(arg, "--icu-data-dir=", 15) == 0) {
//       icu_data_dir.assign(arg + 15);
// #endif
//     } else if (strcmp(arg, "-") == 0) {
//       break;
//     } else if (strcmp(arg, "--") == 0) {
//       index += 1;
//       break;
//     } else if (strcmp(arg, "--abort-on-uncaught-exception") == 0 ||
//                strcmp(arg, "--abort_on_uncaught_exception") == 0) {
//       abort_on_uncaught_exception = true;
//       // Also a V8 option.  Pass through as-is.
//       new_v8_argv[new_v8_argc] = arg;
//       new_v8_argc += 1;
//     } else {
//       // V8 option.  Pass through as-is.
//       new_v8_argv[new_v8_argc] = arg;
//       new_v8_argc += 1;
//     }

//     memcpy(new_exec_argv + new_exec_argc,
//            argv + index,
//            args_consumed * sizeof(*argv));

//     new_exec_argc += args_consumed;
//     index += args_consumed;
//   }

//   // Copy remaining arguments.
//   const unsigned int args_left = nargs - index;

//   if (is_env && args_left) {
//     fprintf(stderr, "%s: %s is not supported in NODE_OPTIONS\n",
//             argv[0], argv[index]);
//     exit(9);
//   }

//   memcpy(new_argv + new_argc, argv + index, args_left * sizeof(*argv));
//   new_argc += args_left;

//   *exec_argc = new_exec_argc;
//   *exec_argv = new_exec_argv;
//   *v8_argc = new_v8_argc;
//   *v8_argv = new_v8_argv;

//   // Copy new_argv over argv and update argc.
//   memcpy(argv, new_argv, new_argc * sizeof(*argv));
//   delete[] new_argv;
//   *argc = static_cast<int>(new_argc);
// }


}  // namespace options

}  // namespace node
