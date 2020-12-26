#ifndef SRC_QUIC_QUIC_STREAM_H_
#define SRC_QUIC_QUIC_STREAM_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_struct.h"
#include "async_wrap.h"
#include "env.h"
#include "memory_tracker.h"
#include "node_bob.h"
#include "node_http_common.h"
#include "quic_buffer.h"
#include "quic_state.h"
#include "quic_util.h"
#include "util-inl.h"
#include "v8.h"

#include <string>
#include <vector>

namespace node {
namespace quic {

class QuicSession;
class QuicStream;
class QuicApplication;

using QuicHeader = NgHeaderBase<QuicApplication>;

enum QuicStreamHeaderFlags : uint32_t {
  // No flags
  QUICSTREAM_HEADER_FLAGS_NONE = 0,

  // Set if the initial headers are considered
  // terminal (that is, the stream should be closed
  // after transmitting the headers). If headers are
  // not supported by the QUIC Application, flag is
  // ignored.
  QUICSTREAM_HEADER_FLAGS_TERMINAL = 1
};

enum QuicStreamHeadersKind : int {
  QUICSTREAM_HEADERS_KIND_NONE = 0,
  QUICSTREAM_HEADERS_KIND_INFORMATIONAL,
  QUICSTREAM_HEADERS_KIND_INITIAL,
  QUICSTREAM_HEADERS_KIND_TRAILING
};

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

#define V(name, _, __) IDX_QUIC_STREAM_STATS_##name,
enum QuicStreamStatsIdx : int {
  STREAM_STATS(V)
  IDX_QUIC_STREAM_STATS_COUNT
};
#undef V

#define V(_, name, __) uint64_t name;
struct QuicStreamStats {
  STREAM_STATS(V)
};
#undef V

struct QuicStreamStatsTraits {
  using Stats = QuicStreamStats;
  using Base = QuicStream;

  template <typename Fn>
  static void ToString(const Base& ptr, Fn&& add_field);
};

#define QUICSTREAM_SHARED_STATE(V)                                             \
  V(WRITE_ENDED, write_ended, uint8_t)                                         \
  V(READ_STARTED, read_started, uint8_t)                                       \
  V(READ_PAUSED, read_paused, uint8_t)                                         \
  V(READ_ENDED, read_ended, uint8_t)                                           \
  V(FIN_SENT, fin_sent, uint8_t)                                               \
  V(FIN_RECEIVED, fin_received, uint8_t)

#define V(_, name, type) type name;
struct QuicStreamState {
  QUICSTREAM_SHARED_STATE(V);
};
#undef V

#define V(id, name, _)                                                         \
  IDX_QUICSTREAM_STATE_##id = offsetof(QuicStreamState, name),
enum QuicStreamStateFields {
  QUICSTREAM_SHARED_STATE(V)
  IDX_QUICSTREAM_STATE_END
};
#undef V

enum QuicStreamDirection {
  // The QuicStream is readable and writable in both directions
  QUIC_STREAM_BIRECTIONAL,

  // The QuicStream is writable and readable in only one direction.
  // The direction depends on the QuicStreamOrigin.
  QUIC_STREAM_UNIDIRECTIONAL
};

enum QuicStreamOrigin {
  // The QuicStream was created by the server.
  QUIC_STREAM_SERVER,

  // The QuicStream was created by the client.
  QUIC_STREAM_CLIENT
};

// QuicStream's are simple data flows that may be:
//
// * Bidirectional or Unidirectional
// * Server or Client Initiated
//
// The flow direction and origin of the stream are important in
// determining the write and read state (Open or Closed). Specifically:
//
// A Unidirectional stream originating with the Server is:
//
// * Server Writable (Open) but not Client Writable (Closed)
// * Client Readable (Open) but not Server Readable (Closed)
//
// Likewise, a Unidirectional stream originating with the
// Client is:
//
// * Client Writable (Open) but not Server Writable (Closed)
// * Server Readable (Open) but not Client Readable (Closed)
//
// Bidirectional Stream States
// +------------+--------------+--------------------+---------------------+
// |            | Initiated By | Initial Read State | Initial Write State |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Server     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Client     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Server     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Client     |        Open        |         Open        |
// +------------+--------------+--------------------+---------------------+
//
// Unidirectional Stream States
// +------------+--------------+--------------------+---------------------+
// |            | Initiated By | Initial Read State | Initial Write State |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Server     |       Closed       |         Open        |
// +------------+--------------+--------------------+---------------------+
// | On Server  |   Client     |        Open        |        Closed       |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Server     |        Open        |        Closed       |
// +------------+--------------+--------------------+---------------------+
// | On Client  |   Client     |       Closed       |         Open        |
// +------------+--------------+--------------------+---------------------+
//
// All data sent via the QuicStream is buffered internally until either
// receipt is acknowledged from the peer or attempts to send are abandoned.
//
// A QuicStream may be in a fully closed state (No longer readable nor
// writable) state but still have unacknowledged data in it's outbound queue.
//
// A QuicStream is gracefully closed when (a) both Read and Write states
// are Closed, (b) all queued data has been acknowledged.
//
// The QuicStream may be forcefully closed immediately using destroy(err).
// This causes all queued data and pending JavaScript writes to be
// abandoned, and causes the QuicStream to be immediately closed at the
// ngtcp2 level.
class QuicStream : public AsyncWrap,
                   public bob::SourceImpl<ngtcp2_vec>,
                   public StatsBase<QuicStreamStatsTraits> {
 public:
  static void Initialize(
      Environment* env,
      v8::Local<v8::Object> target);

  static bool HasInstance(Environment* env, v8::Local<v8::Object> obj);

  static BaseObjectPtr<QuicStream> New(
      QuicSession* session,
      int64_t stream_id,
      QuicBufferSource* source = nullptr);

  QuicStream(
      QuicSession* session,
      v8::Local<v8::Object> target,
      int64_t stream_id,
      QuicBufferSource* source = nullptr);

  ~QuicStream() override;

  std::string diagnostic_name() const override;

  // The numeric identifier of the QuicStream.
  inline int64_t id() const { return stream_id_; }

  inline QuicSession* session() const { return session_.get(); }

  inline QuicStreamDirection direction() const {
    return stream_id_ & 0b10 ?
        QUIC_STREAM_UNIDIRECTIONAL :
        QUIC_STREAM_BIRECTIONAL;
  }

  inline QuicStreamOrigin origin() const {
    return stream_id_ & 0b01 ?
        QUIC_STREAM_SERVER :
        QUIC_STREAM_CLIENT;
  }

  void set_fin_sent();

  inline bool is_destroyed() const { return destroyed_; }

  inline void set_destroyed() { destroyed_ = true; }

  // Specifies the kind of headers currently being processed.
  inline void set_headers_kind(QuicStreamHeadersKind kind) {
    headers_kind_ = kind;
  }

  // Set the final size for the QuicStream. This only works
  // the first time it is called. Subsequent calls will be
  // ignored unless the subsequent size is greater than the
  // prior set size, in which case we have a bug and we'll
  // assert.
  void set_final_size(uint64_t final_size);

  // The final size is the maximum amount of data that has been
  // acknowleged to have been received for a QuicStream.
  inline uint64_t final_size() const {
    return GetStat(&QuicStreamStats::final_size);
  }

  // Marks the given data range as having been acknowledged.
  // This means that the data range may be released from
  // memory.
  void Acknowledge(uint64_t offset, size_t datalen);

  // Destroy the QuicStream and render it no longer usable.
  void Destroy(QuicError* error = nullptr);

  // Returns false if the header cannot be added. This will
  // typically only happen if a maximimum number of headers
  // has been reached.
  bool AddHeader(std::unique_ptr<QuicHeader> header);

  // Some QUIC applications support headers, others do not.
  // The following methods allow consistent handling of
  // headers at the QuicStream level regardless of the
  // protocol. For applications that do not support headers,
  // these are simply not used.
  void BeginHeaders(
       QuicStreamHeadersKind kind = QUICSTREAM_HEADERS_KIND_NONE);

  // Indicates an amount of unacknowledged data that has been
  // submitted to the QUIC connection.
  void Commit(size_t amount);

  void EndHeaders();

  // Passes a chunk of data on to the QuicStream listener.
  void ReceiveData(
      uint32_t flags,
      const uint8_t* data,
      size_t datalen,
      uint64_t offset);

  // Resets the QUIC stream, sending a signal to the peer that
  // no additional data will be transmitted for this stream.
  void ResetStream(uint64_t app_error_code = NGTCP2_NO_ERROR);

  // Instructs ngtcp2 to queue a STOP_SENDING frame to the connected peer
  void StopSending(uint64_t app_error_code = NGTCP2_NO_ERROR);

  // Submits informational headers. Returns false if headers are not
  // supported on the underlying QuicApplication.
  bool SubmitInformation(v8::Local<v8::Array> headers);

  // Submits initial headers. Returns false if headers are not
  // supported on the underlying QuicApplication.
  bool SubmitHeaders(v8::Local<v8::Array> headers, uint32_t flags);

  // Submits trailing headers. Returns false if headers are not
  // supported on the underlying QuicApplication.
  bool SubmitTrailers(v8::Local<v8::Array> headers);

  QuicState* quic_state() { return quic_state_.get(); }

  void AttachInboundConsumer(
      QuicBufferConsumer* consumer,
      BaseObjectPtr<AsyncWrap> strong_ptr = BaseObjectPtr<AsyncWrap>());

  void AttachOutboundSource(QuicBufferSource* source);

  int DoPull(
      bob::Next<ngtcp2_vec> next,
      int options,
      ngtcp2_vec* data,
      size_t count,
      size_t max_count_hint) override;

  // Moves the QuicStream back into the scheduler. This should only be
  // called when there is data available.
  void Resume();

  void OnClose();

  // QuicStream instances cannot be transferred or cloned meaningfully
  // to a Worker Thread.
  TransferMode GetTransferMode() const override {
    return TransferMode::kUntransferable;
  }

  // Required for MemoryRetainer
  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(QuicStream)
  SET_SELF_SIZE(QuicStream)

 private:
  // Process the inbound_ QuicBuffer instance. If there is an
  // inbound consumer it will be passed the full contents of
  // the inbound queue as an Array of Uint8Array objects.
  void ProcessInbound();

  void IncrementStats(size_t datalen);

  BaseObjectWeakPtr<QuicSession> session_;

  // The outbound_source_ provides the data that is to be
  // sent by this QuicStream. It maybe specified when the
  // QuicStream is created or any time after but it may
  // only be specified once. After the source is read
  // the writable side of the QuicStream will be closed
  // by sending a fin data frame.
  QuicBufferSource* outbound_source_ = nullptr;
  BaseObjectPtr<BaseObject> outbound_source_strong_ptr_;

  // The inbound_ buffer contains the data that has been
  // received by this QuicStream. The received data will
  // be buffered in inbound_ until an inbound_consumer_
  // is attached. Only a single inbound_consumer_ may be
  // attached at a time.
  QuicBuffer inbound_;
  QuicBufferConsumer* inbound_consumer_ = nullptr;
  BaseObjectPtr<AsyncWrap> inbound_consumer_strong_ptr_;

  int64_t stream_id_ = 0;
  bool destroyed_ = false;
  AliasedStruct<QuicStreamState> state_;
  DoneCB shutdown_done_ = nullptr;

  std::vector<std::unique_ptr<QuicHeader>> headers_;
  QuicStreamHeadersKind headers_kind_;
  size_t current_headers_length_ = 0;
  BaseObjectPtr<QuicState> quic_state_;

  ListNode<QuicStream> stream_queue_;

 public:
  // Linked List of QuicStream objects
  using Queue = ListHead<QuicStream, &QuicStream::stream_queue_>;

  void Schedule(Queue* queue);

  inline void Unschedule() { stream_queue_.Remove(); }

};

}  // namespace quic
}  // namespace node

#endif  // NODE_WANT_INTERNALS

#endif  // SRC_QUIC_QUIC_STREAM_H_
