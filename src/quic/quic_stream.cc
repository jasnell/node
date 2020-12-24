#include "quic_stream.h"  // NOLINT(build/include)
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "debug_utils-inl.h"
#include "env-inl.h"
#include "node.h"
#include "node_bob-inl.h"
#include "node_buffer.h"
#include "node_internals.h"
#include "node_sockaddr-inl.h"
#include "node_http_common-inl.h"
#include "quic_session.h"
#include "quic_socket.h"
#include "quic_util-inl.h"
#include "v8.h"
#include "uv.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

namespace node {

using v8::Array;
using v8::ArrayBufferView;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::Maybe;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyAttribute;
using v8::String;
using v8::Value;

namespace quic {

bool QuicStream::HasInstance(Environment* env, v8::Local<v8::Object> obj) {
  QuicState* state = env->GetBindingData<QuicState>(env->context());
  return state->quicserverstream()->HasInstance(obj);
}

QuicStream::QuicStream(
    QuicSession* sess,
    Local<Object> wrap,
    int64_t stream_id,
    QuicBufferSource* source)
    : AsyncWrap(sess->env(), wrap, AsyncWrap::PROVIDER_QUICSTREAM),
      StatsBase(sess->env(), wrap,
                HistogramOptions::ACK |
                HistogramOptions::RATE |
                HistogramOptions::SIZE),
    session_(sess),
    stream_id_(stream_id),
    state_(sess->env()->isolate()),
    quic_state_(sess->quic_state()) {
  CHECK_NOT_NULL(sess);
  MakeWeak();
  Debug(this, "Created");

  if (source != nullptr)
    AttachOutboundSource(source);

  wrap->DefineOwnProperty(
      env()->context(),
      env()->state_string(),
      state_.GetArrayBuffer(),
      PropertyAttribute::ReadOnly).Check();

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(session()->connection(), &params);
  IncrementStat(&QuicStreamStats::max_offset, params.initial_max_data);
}

QuicStream::~QuicStream() {
  DebugStats();
}

void QuicStream::Resume() {
  QuicSession::SendSessionScope send_scope(session());
  Debug(this, "Resuming stream %" PRIu64, id());
  session()->ResumeStream(id());
}

void QuicStream::set_final_size(uint64_t final_size) {
  CHECK_IMPLIES(
      state_->fin_received == 1,
      final_size <= GetStat(&QuicStreamStats::final_size));
  state_->fin_received = 1;
  SetStat(&QuicStreamStats::final_size, final_size);
  Debug(this, "Set final size to %" PRIu64, final_size);
}

void QuicStream::set_fin_sent() {
  Debug(this, "Final stream frame sent");
  state_->fin_sent = 1;
  if (shutdown_done_ != nullptr) {
    shutdown_done_(0);
  }
}

void QuicStream::EndHeaders() {
  Debug(this, "End Headers");
  // Upon completion of a block of headers, convert the
  // vector of Header objects into an array of name+value
  // pairs, then call the on_stream_headers function.
  session()->application()->StreamHeaders(stream_id_, headers_kind_, headers_);
  headers_.clear();
}

void QuicStream::BeginHeaders(QuicStreamHeadersKind kind) {
  Debug(this, "Beginning Headers");
  // Upon start of a new block of headers, ensure that any
  // previously collected ones are cleaned up.
  headers_.clear();
  set_headers_kind(kind);
}

void QuicStream::Commit(size_t amount) {
  CHECK(!is_destroyed());
  if (outbound_source_ == nullptr)
    return;
  size_t actual = outbound_source_->Seek(amount);
  CHECK_LE(actual, amount);
}

void QuicStream::Schedule(Queue* queue) {
  if (!stream_queue_.IsEmpty())  // Already scheduled?
    return;
  queue->PushBack(this);
}

void QuicStream::AttachInboundConsumer(
    QuicBufferConsumer* consumer,
    BaseObjectPtr<AsyncWrap> strong_ptr) {
  CHECK_NULL(inbound_consumer_);
  CHECK_IMPLIES(strong_ptr, consumer != nullptr);
  Debug(this, "%s data consumer",
        consumer != nullptr ? "Attaching" : "Clearing");
  inbound_consumer_ = consumer;
  inbound_consumer_strong_ptr_ = std::move(strong_ptr);
  ProcessInbound();
}

void QuicStream::AttachOutboundSource(QuicBufferSource* source) {
  CHECK_NULL(outbound_source_);
  Debug(this, "%s data source",
        source != nullptr ? "Attaching" : "Clearing");
  source->set_owner(this);
  outbound_source_ = source;
  outbound_source_strong_ptr_.reset(source->GetStrongPtr());
  Resume();
}

void QuicStream::ReceiveData(
    uint32_t flags,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  CHECK(!is_destroyed());
  Debug(this, "Receiving %d bytes. Final? %s",
        datalen,
        flags & NGTCP2_STREAM_DATA_FLAG_FIN ? "yes" : "no");

  // ngtcp2 guarantees that datalen will only be 0 if fin is set.
  DCHECK_IMPLIES(datalen == 0, flags & NGTCP2_STREAM_DATA_FLAG_FIN);

  // ngtcp2 guarantees that offset is greater than the previously received.
  DCHECK_GE(offset, GetStat(&QuicStreamStats::max_offset_received));
  SetStat(&QuicStreamStats::max_offset_received, offset);

  if (datalen > 0) {
    // IncrementStats will update the data_rx_rate_ and data_rx_size_
    // histograms. These will provide data necessary to detect and
    // prevent Slow Send DOS attacks specifically by allowing us to
    // see if a connection is sending very small chunks of data at very
    // slow speeds. It is important to emphasize, however, that slow send
    // rates may be perfectly legitimate so we cannot simply take blanket
    // action when slow rates are detected. Nor can we reliably define what
    // a slow rate even is! Will will need to determine some reasonable
    // default and allow user code to change the default as well as determine
    // what action to take. The current strategy will be to trigger an event
    // on the stream when data transfer rates are likely to be considered too
    // slow.
    IncrementStats(datalen);
    inbound_.Push(env(), data, datalen);
  }

  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    set_final_size(offset + datalen);
    inbound_.End();
  }

  ProcessInbound();
}

void QuicStream::ProcessInbound() {
  // If there is no inbound consumer, do nothing.
  if (inbound_consumer_ == nullptr)
    return;

  Debug(this, "Releasing the inbound queue to the consumer");

  Maybe<size_t> amt = inbound_.Release(inbound_consumer_);
  if (amt.IsNothing()) {
    Debug(this, "Failed to process the inbound queue");
    return Destroy();
  }
  size_t len = amt.FromJust();

  Debug(this, "Released %" PRIu64 " bytes to consumer", len);
  IncrementStat(&QuicStreamStats::max_offset, len);
  session_->ExtendStreamOffset(id(), len);
}

std::string QuicStream::diagnostic_name() const {
  return std::string("QuicStream ") + std::to_string(stream_id_) +
         " (" + std::to_string(static_cast<int64_t>(get_async_id())) +
         ", " + session_->diagnostic_name() + ")";
}

template <typename Fn>
void QuicStreamStatsTraits::ToString(const QuicStream& ptr, Fn&& add_field) {
#define V(_n, name, label)                                                     \
  add_field(label, ptr.GetStat(&QuicStreamStats::name));
  STREAM_STATS(V)
#undef V
}

// Acknowledge is called when ngtcp2 has received an acknowledgement
// for one or more stream frames for this QuicStream. This will cause
// data stored in the streambuf_ outbound queue to be consumed and may
// result in the JavaScript callback for the write to be invoked.
void QuicStream::Acknowledge(uint64_t offset, size_t datalen) {
  if (is_destroyed() || outbound_source_ == nullptr)
    return;

  // ngtcp2 guarantees that offset must always be greater
  // than the previously received offset.
  DCHECK_GE(offset, GetStat(&QuicStreamStats::max_offset_ack));
  SetStat(&QuicStreamStats::max_offset_ack, offset);
  RecordAck(&QuicStreamStats::acked_at);

  Debug(this, "Acknowledging %d bytes", datalen);

  // Consumes the given number of bytes in the buffer.
  CHECK_LE(outbound_source_->Acknowledge(offset, datalen), datalen);
}

// While not all QUIC applications will support headers, QuicStream
// includes basic, generic support for storing them.
bool QuicStream::AddHeader(std::unique_ptr<QuicHeader> header) {
  size_t len = header->length();
  QuicApplication* app = session()->application();
  // We cannot add the header if we've either reached
  // * the max number of header pairs or
  // * the max number of header bytes
  if (headers_.size() == app->max_header_pairs() ||
      current_headers_length_ + len > app->max_header_length()) {
    return false;
  }

  current_headers_length_ += header->length();
  Debug(this, "Header - %s", header.get());
  headers_.emplace_back(std::move(header));
  return true;
}

// Destroy is used to explicitly terminate the QuicStream early, possibly
// with an error code.
void QuicStream::Destroy(QuicError* error) {
  if (destroyed_)
    return;
  destroyed_ = true;
  session()->ShutdownStream(id(), error != nullptr ? error->code : 0);
  session_->RemoveStream(stream_id_);
}

void QuicStream::IncrementStats(size_t datalen) {
  uint64_t len = static_cast<uint64_t>(datalen);
  IncrementStat(&QuicStreamStats::bytes_received, len);
  RecordRate(&QuicStreamStats::received_at);
  RecordSize(len);
}

void QuicStream::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("outbound", outbound_source_);
  tracker->TrackField("outbound_strong_ptr",
                      outbound_source_strong_ptr_);
  tracker->TrackField("inbound", inbound_);
  tracker->TrackField("inbound_consumer_strong_ptr_",
                      inbound_consumer_strong_ptr_);
  tracker->TrackField("headers", headers_);
  StatsBase::StatsMemoryInfo(tracker);
}

BaseObjectPtr<QuicStream> QuicStream::New(
    QuicSession* session,
    int64_t stream_id,
    QuicBufferSource* source) {
  Local<Object> obj;
  if (!session->quic_state()
              ->quicserverstream()
              ->InstanceTemplate()
              ->NewInstance(session->env()->context()).ToLocal(&obj)) {
    return {};
  }

  BaseObjectPtr<QuicStream> stream =
      MakeDetachedBaseObject<QuicStream>(session, obj, stream_id, source);
  CHECK(stream);
  session->AddStream(stream);
  stream->Resume();
  return stream;
}

int QuicStream::DoPull(
    bob::Next<ngtcp2_vec> next,
    int options,
    ngtcp2_vec* data,
    size_t count,
    size_t max_count_hint) {
  Debug(this, "Pulling outbound data for serialization");
  // If an outbound source has not yet been attached, block until
  // one is available. When AttachOutboundSource() is called the
  // stream will be resumed.
  if (outbound_source_ == nullptr) {
    int status = bob::Status::STATUS_BLOCK;
    std::move(next)(status, nullptr, 0, [](size_t len) {});
    return status;
  }

  return outbound_source_->Pull(
      std::move(next),
      options,
      data,
      count,
      max_count_hint);
}

// ResetStream will cause ngtcp2 to queue a RESET_STREAM and STOP_SENDING
// frame, as appropriate, for the given stream_id. For a locally-initiated
// unidirectional stream, only a RESET_STREAM frame will be scheduled and
// the stream will be immediately closed. For a bidirectional stream, a
// STOP_SENDING frame will be sent.
void QuicStream::ResetStream(uint64_t app_error_code) {
  QuicSession::SendSessionScope send_scope(session());
  session()->ShutdownStream(id(), app_error_code);
  state_->read_ended = 1;
}

// StopSending will cause ngtcp2 to queue a STOP_SENDING frame if the
// stream is still inbound readable.
void QuicStream::StopSending(uint64_t app_error_code) {
  QuicSession::SendSessionScope send_scope(session());
  ngtcp2_conn_shutdown_stream_read(
      session()->connection(),
      stream_id_,
      app_error_code);
  state_->read_ended = 1;
}

bool QuicStream::SubmitInformation(v8::Local<v8::Array> headers) {
  return session_->SubmitInformation(stream_id_, headers);
}

bool QuicStream::SubmitHeaders(v8::Local<v8::Array> headers, uint32_t flags) {
  return session_->SubmitHeaders(stream_id_, headers, flags);
}

bool QuicStream::SubmitTrailers(v8::Local<v8::Array> headers) {
  return session_->SubmitTrailers(stream_id_, headers);
}

// JavaScript API
namespace {
void QuicStreamGetID(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(static_cast<double>(stream->id()));
}

void OpenUnidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  CHECK_IMPLIES(!args[1]->IsUndefined(), args[1]->IsObject());

  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  if (!session->OpenUnidirectionalStream(&stream_id))
    return;

  QuicBufferSource* source = nullptr;
  if (args[1]->IsObject()) {
    BaseObject* source_obj;
    ASSIGN_OR_RETURN_UNWRAP(&source_obj, args[1]);
    source = reinterpret_cast<QuicBufferSource*>(source_obj);
  }

  BaseObjectPtr<QuicStream> stream =
      QuicStream::New(session, stream_id, source);
  args.GetReturnValue().Set(stream->object());
}

void OpenBidirectionalStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(!args.IsConstructCall());
  CHECK(args[0]->IsObject());
  CHECK_IMPLIES(!args[1]->IsUndefined(), args[1]->IsObject());
  QuicSession* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());

  int64_t stream_id;
  if (!session->OpenBidirectionalStream(&stream_id))
    return;

  QuicBufferSource* source = nullptr;
  if (args[1]->IsObject()) {
    // TODO(@jasnell): Make this work for all...
    ArrayBufferViewSource* source_obj;
    ASSIGN_OR_RETURN_UNWRAP(&source_obj, args[1]);
    source = source_obj;
  }

  BaseObjectPtr<QuicStream> stream =
      QuicStream::New(session, stream_id, source);
  args.GetReturnValue().Set(stream->object());
}

void QuicStreamDestroy(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  QuicError error(env, args[0], args[1], QUIC_ERROR_APPLICATION);
  stream->Destroy(&error);
}

void QuicStreamReset(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());

  QuicError error(env, args[0], args[1], QUIC_ERROR_APPLICATION);

  stream->ResetStream(
      error.family == QUIC_ERROR_APPLICATION ?
          error.code : static_cast<uint64_t>(NGTCP2_NO_ERROR));
}

void QuicStreamStopSending(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());

  QuicError error(env, args[0], args[1], QUIC_ERROR_APPLICATION);

  stream->StopSending(
      error.family == QUIC_ERROR_APPLICATION ?
          error.code : static_cast<uint64_t>(NGTCP2_NO_ERROR));
}

// Requests transmission of a block of informational headers. Not all
// QUIC Applications will support headers. If headers are not supported,
// This will set the return value to false, otherwise the return value
// is set to true
void QuicStreamSubmitInformation(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsArray());
  args.GetReturnValue().Set(stream->SubmitInformation(args[0].As<Array>()));
}

// Requests transmission of a block of initial headers. Not all
// QUIC Applications will support headers. If headers are not supported,
// this will set the return value to false, otherwise the return value
// is set to true. For http/3, these may be request or response headers.
void QuicStreamSubmitHeaders(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsArray());
  uint32_t flags = QUICSTREAM_HEADER_FLAGS_NONE;
  CHECK(args[1]->Uint32Value(stream->env()->context()).To(&flags));
  args.GetReturnValue().Set(stream->SubmitHeaders(args[0].As<Array>(), flags));
}

// Requests transmission of a block of trailing headers. Not all
// QUIC Applications will support headers. If headers are not supported,
// this will set the return value to false, otherwise the return value
// is set to true.
void QuicStreamSubmitTrailers(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsArray());
  args.GetReturnValue().Set(stream->SubmitTrailers(args[0].As<Array>()));
}

void QuicStreamAttachConsumer(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsObject());
  JSQuicBufferConsumer* consumer;
  ASSIGN_OR_RETURN_UNWRAP(&consumer, args[0].As<Object>());
  stream->AttachInboundConsumer(consumer, BaseObjectPtr<AsyncWrap>(consumer));
}

void QuicStreamAttachSource(const FunctionCallbackInfo<Value>& args) {
  QuicStream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsObject());
  BaseObject* source_obj;
  ASSIGN_OR_RETURN_UNWRAP(&source_obj, args[0].As<Object>());
  QuicBufferSource* source = reinterpret_cast<QuicBufferSource*>(source_obj);
  stream->AttachOutboundSource(source);
}
}  // namespace

void QuicStream::Initialize(Environment* env, Local<Object> target) {
  QuicState* state = env->GetBindingData<QuicState>(env->context());
  Isolate* isolate = env->isolate();
  Local<String> class_name = FIXED_ONE_BYTE_STRING(isolate, "QuicStream");
  Local<FunctionTemplate> stream = FunctionTemplate::New(env->isolate());
  stream->SetClassName(class_name);
  stream->Inherit(AsyncWrap::GetConstructorTemplate(env));
  Local<ObjectTemplate> streamt = stream->InstanceTemplate();
  streamt->SetInternalFieldCount(StreamBase::kInternalFieldCount);
  streamt->Set(env->owner_symbol(), Null(env->isolate()));
  env->SetProtoMethod(stream, "destroy", QuicStreamDestroy);
  env->SetProtoMethod(stream, "resetStream", QuicStreamReset);
  env->SetProtoMethod(stream, "stopSending", QuicStreamStopSending);
  env->SetProtoMethod(stream, "id", QuicStreamGetID);
  env->SetProtoMethod(stream, "submitInformation", QuicStreamSubmitInformation);
  env->SetProtoMethod(stream, "submitHeaders", QuicStreamSubmitHeaders);
  env->SetProtoMethod(stream, "submitTrailers", QuicStreamSubmitTrailers);
  env->SetProtoMethod(stream, "attachConsumer", QuicStreamAttachConsumer);
  env->SetProtoMethod(stream, "attachSource", QuicStreamAttachSource);
  state->set_quicserverstream(stream);
  target->Set(env->context(),
              class_name,
              stream->GetFunction(env->context()).ToLocalChecked()).Check();

  env->SetMethod(target, "openBidirectionalStream", OpenBidirectionalStream);
  env->SetMethod(target, "openUnidirectionalStream", OpenUnidirectionalStream);
}

}  // namespace quic
}  // namespace node
