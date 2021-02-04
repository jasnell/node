#include "node.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_sockaddr-inl.h"
#include "util-inl.h"
#include "quic/session.h"
#include "quic/stream.h"
#include "quic/quic.h"
#include "node_errors.h"
#include "node_process.h"

#include <v8.h>

namespace node {

using v8::Context;
using v8::Local;
using v8::Object;
using v8::Value;

namespace quic {

Path::Path(const SocketAddress& local, const SocketAddress& remote) {
  ngtcp2_addr_init(
      &this->local,
      local.data(),
      local.length(),
      const_cast<SocketAddress*>(&local));
  ngtcp2_addr_init(
      &this->remote,
      remote.data(),
      remote.length(),
      const_cast<SocketAddress*>(&remote));
}

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {}

}  // namespace quic
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(quic, node::quic::Initialize)
