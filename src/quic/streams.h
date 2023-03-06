#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "bindingdata.h"
#include "defs.h"
#include "session.h"
#include <aliased_struct.h>
#include <dataqueue/queue.h>
#include <memory_tracker.h>
#include <node_bob.h>
#include <node_external_reference.h>
#include <node_http_common.h>
#include <stream_base.h>
#include <optional>

namespace node {
namespace quic {

using Ngtcp2Source = bob::SourceImpl<ngtcp2_vec>;

// QUIC Stream's are simple data flows that may be:
//
// * Bidirectional or Unidirectional
// * Server or Client Initiated
//
// The flow direction and origin of the stream are important in determining the
// write and read state (Open or Closed). Specifically:
//
// Bidirectional Stream States:
// +--------+--------------+----------+----------+
// |   ON   | Initiated By | Readable | Writable |
// +--------+--------------+----------+----------+
// | Server |   Server     |    Y     |    Y     |
// +--------+--------------+----------+----------+
// | Server |   Client     |    Y     |    Y     |
// +--------+--------------+----------+----------+
// | Client |   Server     |    Y     |    Y     |
// +--------+--------------+----------+----------+
// | Client |   Client     |    Y     |    Y     |
// +--------+--------------+----------+----------+
//
// Unidirectional Stream States
// +--------+--------------+----------+----------+
// |   ON   | Initiated By | Readable | Writable |
// +--------+--------------+----------+----------+
// | Server |   Server     |    N     |    Y     |
// +--------+--------------+----------+----------+
// | Server |   Client     |    Y     |    N     |
// +--------+--------------+----------+----------+
// | Client |   Server     |    Y     |    N     |
// +--------+--------------+----------+----------+
// | Client |   Client     |    N     |    Y     |
// +--------+--------------+----------+----------+
//
// All data sent via the Stream is buffered internally until either receipt is
// acknowledged from the peer or attempts to send are abandoned. The fact that
// data is buffered in memory makes it essential that the flow control for the
// session and the stream are properly handled. For now, we are largely relying
// on ngtcp2's default flow control mechanisms which generally should be doing
// the right thing but we may need to switch to a more manual management process
// if too much data ends up being buffered for too long.
//
// A Stream may be in a fully closed state (No longer readable nor writable)
// state but still have unacknowledged data in it's outbound queue.
//
// A Stream is gracefully closed when (a) both Read and Write states are Closed,
// (b) all queued data has been acknowledged.
//
// The Stream may be forcefully closed immediately using destroy(err). This
// causes all queued data and pending JavaScript writes to be abandoned, and
// causes the Stream to be immediately closed at the ngtcp2 level without
// waiting for any outstanding acknowledgements. Keep in mind, however, that the
// peer is not notified that the stream is destroyed and may attempt to continue
// sending data and acknowledgements.
class Stream final : public AsyncWrap,
                     public Ngtcp2Source,
                     public DataQueue::BackpressureListener {
 public:
  #define V(_, name, __) uint64_t name;
  struct Stats final {
    STREAM_STATS(V)
  };
  #undef V

  // Whether or not a stream supports headers is determined by the application
  // that is configured for the owning session.
  using Header = NgHeaderBase<BindingData>;

  static Stream* From(ngtcp2_conn*, void* stream_user_data);

  HAS_INSTANCE()
  GET_CONSTRUCTOR_TEMPLATE()
  static void Initialize(Environment* env, v8::Local<v8::Object> object);
  static void RegisterExternalReferences(ExternalReferenceRegistry* registry);

  static BaseObjectPtr<Stream> Create(Environment* env,
                                      Session* session,
                                      stream_id id,
                                      std::unique_ptr<DataQueue> source = nullptr);

  Stream(BaseObjectPtr<Session> session,
         v8::Local<v8::Object> object,
         stream_id id,
         std::unique_ptr<DataQueue> source = nullptr);

  ~Stream() override;

  inline stream_id id() const;
  inline Direction direction() const;

  inline CryptoContext::Side origin() const;
  inline Session* session() const;

  inline bool is_destroyed() const;
  inline bool might_send_trailers() const;

  // DataQueue::BackpressureListener implementation
  void EntryRead(size_t amount) override;

  // Returns a DataQueue::Reader that can be used to consume the
  // data received by this stream. Because the inbound DataQueue
  // is non-idempotent, this can only be called once.
  std::shared_ptr<DataQueue::Reader> get_reader();

  void SetPriority(Session::Application::StreamPriority priority =
                       Session::Application::StreamPriority::DEFAULT,
                   Session::Application::StreamPriorityFlags flags =
                       Session::Application::StreamPriorityFlags::NONE);
  Session::Application::StreamPriority GetPriority();

  // The final size is the maximum amount of data that has been acknowleged to
  // have been received for a Stream.
  inline uint64_t final_size() const;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(Stream)
  SET_SELF_SIZE(Stream)

 private:
  struct State final {
#define V(_, name, type) type name;
    STREAM_STATE(V)
#undef V
  };

  // JavaScript API
  static void AttachSource(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DoDestroy(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DoSendHeaders(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DoStopSending(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DoResetStream(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DoSetPriority(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DoGetPriority(const v8::FunctionCallbackInfo<v8::Value>& args);

  // Internal API

  void UpdateStats(size_t datalen);

  void ReadyForTrailers();

  // Signals the beginning of a new block of headers.
  void BeginHeaders(Session::Application::HeadersKind kind);
  // Returns false if the header cannot be added. This will typically only
  // happen if a maximimum number of headers, or the maximum total header length
  // is received.
  bool AddHeader(const Header& header);

  void Commit(size_t amount);
  void Acknowledge(uint64_t offset, size_t datalen);

  // Attach the outbound source of data for the stream.
  void AttachDataQueue(std::shared_ptr<DataQueue> dataqueue);

  // In the typical case there is no reason to explicitly close a Stream as it
  // will be closed automatically when both the readable and writable sides are
  // both closed. However, in some cases it is necessary to close the Stream
  // immediately, such as when the owning Session is being closed immediately.
  // Once a stream is destroyed, there is nothing else it can do and the stream
  // should not be used for anything else. The only state remaining will be the
  // collected statistics.
  void Destroy(QuicError error = QuicError());

  void ReceiveData(Session::Application::ReceiveStreamDataFlags flags,
                   const uint8_t* data,
                   size_t datalen,
                   uint64_t offset);

  // When we have received a RESET_STREAM frame from the peer, it is an
  // indication that they have abruptly terminated their side and will not be
  // sending any more data. The final size is an indicator of the amount of data
  // *they* recognize as having been sent to us. The QUIC spec leaves the
  // specific handling of this frame up to the application. We can choose to
  // drop buffered inbound data on the floor or to deliver it to the
  // application. We choose to deliver it then end the readable side of the
  // stream. Importantly, receiving a RESET_STREAM does *not* destroy the
  // stream. It only ends the readable side. If there is a reset-stream event
  // registered on the JavaScript wrapper, we will emit the event.
  void ReceiveResetStream(size_t final_size, QuicError error);

  void ReceiveStopSending(QuicError error);

  // ResetStream will cause ngtcp2 to queue a RESET_STREAM for this stream,
  // signaling abrupt termination of the outbound flow of data.
  void ResetStream(QuicError error = QuicError());
  void Resume();

  // StopSending will cause ngtcp2 to queue a STOP_SENDING frame for this stream
  // if appropriate. For unidirectional streams for which we are the origin,
  // this ends up being a non-op. For Bidirectional streams, a STOP_SENDING
  // frame is essentially a polite request to the other side to stop sending
  // data on this stream. The other stream is expected to respond with a
  // RESET_STREAM frame that indicates abrupt termination of the inbound flow of
  // data into this stream.
  //
  // Calling this will have the effect of shutting down the readable side of
  // this stream. Any data currently in the buffer can still be read but no new
  // data will be accepted and ngtcp2 should not attempt to push any more in.
  void StopSending(QuicError error = QuicError());

  // Notifies that the stream writable side has been closed.
  void EndWritable();
  void EndReadable(std::optional<uint64_t> final_size = std::nullopt);

  void Blocked();

  // Sends headers to the QUIC Application. If headers are not supported, false
  // will be returned. Otherwise, returns true
  bool SendHeaders(Session::Application::HeadersKind kind,
                   const v8::Local<v8::Array>& headers,
                   Session::Application::HeadersFlags flags =
                       Session::Application::HeadersFlags::NONE);

  // Pulls data from the internal outbound DataQueue configured for this stream.
  int DoPull(bob::Next<ngtcp2_vec> next,
             int options,
             ngtcp2_vec* data,
             size_t count,
             size_t max_count_hint) override;

  // Set the final size for the Stream. This only works the first time it is
  // called. Subsequent calls will be ignored unless the subsequent size is
  // greater than the prior set size, in which case we have a bug and we'll
  // assert.
  void set_final_size(uint64_t final_size);
  inline void set_headers_kind(Session::Application::HeadersKind headers_kind);

  // ============================================================================================
  // JavaScript Outcalls
  using CallbackScope = CallbackScope<Stream>;

  void EmitClose();
  void EmitError(QuicError error);
  void EmitHeaders();
  void EmitReset(QuicError error);
  void EmitTrailers();
  //v8::Maybe<size_t> EmitData(Buffer::Chunk::Queue queue, bool ended);

  // ============================================================================================
  // Internal fields

  struct StatsTraits final {
    using Stats = Stats;
    using Base = StatsImpl<StatsTraits>;

    template <typename Fn>
    static void ToString(const Stats& stats, Fn&& add_field) {
  #define V(_, id, desc) add_field(desc, stats.id);
      STREAM_STATS(V)
  #undef V
    }
  };

  using StatsImpl = StatsImpl<StatsTraits>;

  StatsImpl stats_;

  BaseObjectPtr<Session> session_;
  AliasedStruct<State> state_;

  // The outbound buffer manages the data to be sent by this stream. It is used
  // only if an outbound DataQueue has been attached. The buffer will retain
  // sent outbound data in memory until it has been acknowledged.
  class OutboundBuffer;
  std::unique_ptr<OutboundBuffer> outbound_ = nullptr;

  // The inbound_ buffer contains the data that has been received by this Stream
  // but not yet delivered to the JavaScript wrapper.
  std::shared_ptr<DataQueue> inbound_;

  std::vector<v8::Local<v8::Value>> headers_;
  Session::Application::HeadersKind headers_kind_ =
      Session::Application::HeadersKind::INITIAL;

  // The current total byte length of the headers
  size_t current_headers_length_ = 0;

  ListNode<Stream> stream_queue_;

  friend class OutboundBuffer;
  friend class Session::Application;
  friend class Http3Application;
  friend class DefaultApplication;
  friend class Session;

 public:
  // The Queue/Schedule/Unschedule here are part of the mechanism used to
  // determine which streams have data to send on the session. When a stream
  // potentially has data available, it will be scheduled in the Queue. Then,
  // when the Session::Application starts sending pending data, it will check
  // the queue to see if there are streams waiting. If there are, it will grab
  // one and check to see if there is data to send. When a stream does not have
  // data to send (such as when it is initially created or is using an async
  // source that is still waiting for data to be pushed) it will not appear in
  // the queue.
  using Queue = ListHead<Stream, &Stream::stream_queue_>;

  void Schedule(Queue* queue);
  void Unschedule();
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
