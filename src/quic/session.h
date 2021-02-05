#ifndef SRC_QUIC_SESSION_H_
#define SRC_QUIC_SESSION_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "quic/quic.h"
#include "quic/stats.h"
#include "quic/stream.h"

#include <ngtcp2/ngtcp2.h>
#include <v8.h>

namespace node {
namespace quic {

#define SESSION_STATS(V)                                                       \
  V(CREATED_AT, created_at, "Created At")                                      \
  V(HANDSHAKE_START_AT, handshake_start_at, "Handshake Started")               \
  V(HANDSHAKE_SEND_AT, handshake_send_at, "Handshke Last Sent")                \
  V(HANDSHAKE_CONTINUE_AT, handshake_continue_at, "Handshke Continued")        \
  V(HANDSHAKE_COMPLETED_AT, handshake_completed_at, "Handshake Completed")     \
  V(HANDSHAKE_CONFIRMED_AT, handshake_confirmed_at, "Handshake Confirmed")     \
  V(HANDSHAKE_ACKED_AT, handshake_acked_at, "Handshake Last Acknowledged")     \
  V(SENT_AT, sent_at, "Last Sent At")                                          \
  V(RECEIVED_AT, received_at, "Last Received At")                              \
  V(CLOSING_AT, closing_at, "Closing")                                         \
  V(DESTROYED_AT, destroyed_at, "Destroyed At")                                \
  V(BYTES_RECEIVED, bytes_received, "Bytes Received")                          \
  V(BYTES_SENT, bytes_sent, "Bytes Sent")                                      \
  V(BIDI_STREAM_COUNT, bidi_stream_count, "Bidi Stream Count")                 \
  V(UNI_STREAM_COUNT, uni_stream_count, "Uni Stream Count")                    \
  V(STREAMS_IN_COUNT, streams_in_count, "Streams In Count")                    \
  V(STREAMS_OUT_COUNT, streams_out_count, "Streams Out Count")                 \
  V(KEYUPDATE_COUNT, keyupdate_count, "Key Update Count")                      \
  V(LOSS_RETRANSMIT_COUNT, loss_retransmit_count, "Loss Retransmit Count")     \
  V(ACK_DELAY_RETRANSMIT_COUNT,                                                \
    ack_delay_retransmit_count,                                                \
    "Ack Delay Retransmit Count")                                              \
  V(PATH_VALIDATION_SUCCESS_COUNT,                                             \
    path_validation_success_count,                                             \
    "Path Validation Success Count")                                           \
  V(PATH_VALIDATION_FAILURE_COUNT,                                             \
    path_validation_failure_count,                                             \
    "Path Validation Failure Count")                                           \
  V(MAX_BYTES_IN_FLIGHT, max_bytes_in_flight, "Max Bytes In Flight")           \
  V(BLOCK_COUNT, block_count, "Block Count")                                   \
  V(MIN_RTT, min_rtt, "Minimum RTT")                                           \
  V(LATEST_RTT, latest_rtt, "Latest RTT")                                      \
  V(SMOOTHED_RTT, smoothed_rtt, "Smoothed RTT")                                \
  V(CWND, cwnd, "Cwnd")                                                        \
  V(RECEIVE_RATE, receive_rate, "Receive Rate / Sec")                          \
  V(SEND_RATE, send_rate, "Send Rate  Sec")                                    \

class Session;

#define V(name, _, __) IDX_STATS_SESSION_##name,
enum class SessionStatsIdx : int {
  SESSION_STATS(V)
  IDX_STATS_SESSION_COUNT
};
#undef V

#define V(_, name, __) uint64_t name;
struct SessionStats {
  SESSION_STATS(V)
};
#undef V

struct SessionStatsTraits {
  using Stats = SessionStats;
  using Base = Session;

  template <typename Fn>
  static void ToString(const Base& ptr, Fn&& add_field);
};

using SessionStatsBase = StatsBase<SessionStatsTraits>;
class Session final : public AsyncWrap,
                      public SessionStatsBase {
 public:
  struct Config : public ngtcp2_settings {};

  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static void Initialize(Environment* env);
  static BaseObjectPtr<Session> Create(Environment* env);

  Session(Environment* env, v8::Local<v8::Object> object);

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(Session)
  SET_SELF_SIZE(Session)

 private:
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_SESSION_H_
