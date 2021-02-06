#ifndef SRC_QUIC_STREAM_H_
#define SRC_QUIC_STREAM_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "quic/quic.h"
#include "quic/session.h"
#include "quic/stats.h"

#include <ngtcp2/ngtcp2.h>

namespace node {
namespace quic {

#define STREAM_STATS(V)                                                        \
  V(CREATED_AT, created_at, "Created At")                                      \
  V(RECEIVED_AT, received_at, "Last Received At")                              \
  V(ACKED_AT, acked_at, "Last Acknowledged At")                                \
  V(CLOSING_AT, closing_at, "Closing At")                                      \
  V(DESTROYED_AT, destroyed_at, "Destroyed At")                                \
  V(BYTES_RECEIVED, bytes_received, "Bytes Received")                          \
  V(BYTES_SENT, bytes_sent, "Bytes Sent")                                      \
  V(MAX_OFFSET, max_offset, "Max Offset")                                      \
  V(MAX_OFFSET_ACK, max_offset_ack, "Max Acknowledged Offset")                 \
  V(MAX_OFFSET_RECV, max_offset_received, "Max Received Offset")               \
  V(FINAL_SIZE, final_size, "Final Size")

class Stream;

#define V(name, _, __) IDX_STATS_STREAM_##name,
enum class StreamStatsIdx : int {
  STREAM_STATS(V)
  IDX_STATS_STREAM_COUNT
};
#undef V

#define V(_, name, __) uint64_t name;
struct StreamStats {
  STREAM_STATS(V)
};
#undef V

struct StreamStatsTraits {
  using Stats = StreamStats;
  using Base = Stream;

  template <typename Fn>
  static void ToString(const Base& ptr, Fn&& add_field);
};

using StreamStatsBase = StatsBase<StreamStatsTraits>;

class Stream final : public AsyncWrap,
                     public StreamStatsBase {
 public:
  enum class Direction {
    UNIDIRECTIONAL,
    BIDIRECTIONAL,
  };

  enum class Origin {
    SERVER,
    CLIENT,
  };

  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static void Initialize(Environment* env);
  static BaseObjectPtr<Stream> Create(
      Environment* env,
      Session* session,
      stream_id id);

  Stream(
      Environment* env,
      v8::Local<v8::Object> object,
      Session* session,
      stream_id id);

  stream_id id() const { return id_; }

  Session* session() const { return session_.get(); }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(Stream)
  SET_SELF_SIZE(Stream)

 private:

  BaseObjectPtr<Session> session_;
  stream_id id_;
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_STREAM_H_
