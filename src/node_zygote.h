#ifndef SRC_NODE_ZYGOTE_H_
#define SRC_NODE_ZYGOTE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include <optional>
#include <string>
#include <vector>

#include "node_exit_code.h"

namespace node::zygote {

// Implements `node --connect=<address> <script> [args...]` and
// `node --connect=<address> -e|-p <code> [args...]`, where `address` is a
// Unix domain socket path or a TCP `host:port`. `args` are the positional
// arguments left after option parsing (args[0] is the executable).
// `eval_code` holds the --eval/--print code, if any; `print_eval` is set for
// --print. Dispatches the program to the zygote listening at `address`,
// forwards signals to the child, and returns the child's exit code (or
// re-raises the signal that terminated it). Runs after option parsing and ICU
// initialization, before OpenSSL, the V8 platform and V8 are initialized.
ExitCode RunClient(const std::string& address,
                   const std::vector<std::string>& args,
                   const std::optional<std::string>& eval_code,
                   bool print_eval);

}  // namespace node::zygote

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_ZYGOTE_H_
