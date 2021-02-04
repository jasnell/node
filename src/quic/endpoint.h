#ifndef SRC_QUIC_ENDPOINT_H_
#define SRC_QUIC_ENDPOINT_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "quic/quic.h"
#include "quic/stats.h"

#include <ngtcp2/ngtcp2.h>
#include <v8.h>

namespace node {
namespace quic {

#define ENDPOINT_STATS(V)                                                      \
  V(CREATED_AT, created_at, "Created At")                                      \
  V(BOUND_AT, bound_at, "Bound At")                                            \
  V(LISTEN_AT, listen_at, "Listen At")                                         \
  V(DESTROYED_AT, destroyed_at, "Destroyed At")                                \
  V(BYTES_RECEIVED, bytes_received, "Bytes Received")                          \
  V(BYTES_SENT, bytes_sent, "Bytes Sent")                                      \
  V(PACKETS_RECEIVED, packets_received, "Packets Received")                    \
  V(PACKETS_IGNORED, packets_ignored, "Packets Ignored")                       \
  V(PACKETS_SENT, packets_sent, "Packets Sent")                                \
  V(SERVER_SESSIONS, server_sessions, "Server Sessions")                       \
  V(CLIENT_SESSIONS, client_sessions, "Client Sessions")                       \
  V(STATELESS_RESET_COUNT, stateless_reset_count, "Stateless Reset Count")     \
  V(SERVER_BUSY_COUNT, server_busy_count, "Server Busy Count")

class Endpoint;

#define V(name, _, __) IDX_STATS_ENDPOINT_##name,
enum class EndpointStatsIdx : int {
  ENDPOINT_STATS(V)
  IDX_STATS_ENDPOINT_COUNT
};
#undef V

#define V(_, name, __) uint64_t name;
struct EndpointStats {
  ENDPOINT_STATS(V)
};
#undef V

struct EndpointStatsTraits {
  using Stats = EndpointStats;
  using Base = Endpoint;

  template <typename Fn>
  static void ToString(const Base& ptr, Fn&& add_field);
};

using EndpointStatsBase = StatsBase<EndpointStatsTraits>;

class Endpoint final : public AsyncWrap,
                       public EndpointStatsBase {
 public:
  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static void Initialize(Environment* env);
  static BaseObjectPtr<Endpoint> Create(Environment* env);

  Endpoint(Environment* env, v8::Local<v8::Object> object);

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(Endpoint)
  SET_SELF_SIZE(Endpoint)

 private:
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_ENDPOINT_H_
