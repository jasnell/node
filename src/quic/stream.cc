#ifndef OPENSSL_NO_QUIC

#include "quic/stream.h"
#include "quic/quic.h"
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_sockaddr-inl.h"
#include "v8.h"

namespace node {

using v8::FunctionTemplate;
using v8::Local;
using v8::Maybe;
using v8::Object;
using v8::PropertyAttribute;

namespace quic {

Local<FunctionTemplate> Stream::GetConstructorTemplate(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  CHECK_NOT_NULL(state);
  Local<FunctionTemplate> tmpl = state->stream_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicStream"));
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Stream::kInternalFieldCount);
    state->set_stream_constructor_template(env, tmpl);
  }
  return tmpl;
}

bool Stream::HasInstance(Environment* env, Local<Object> obj) {
  return GetConstructorTemplate(env)->HasInstance(obj);
}

void Stream::Initialize(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_stream_constructor_template(env, GetConstructorTemplate(env));
}

BaseObjectPtr<Stream> Stream::Create(
    Environment* env,
    Session* session,
    stream_id id) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(env);
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Stream>();

  return MakeBaseObject<Stream>(session, obj, id);
}

Stream::Stream(
    Session* session,
    Local<Object> object,
    stream_id id,
    Buffer::Source* source)
    : AsyncWrap(session->env(), object, AsyncWrap::PROVIDER_QUICSTREAM),
      StreamStatsBase(session->env(), object),
      session_(session),
      state_(session->env()),
      id_(id) {
  MakeWeak();
  Debug(this, "Created");

  AttachOutboundSource(source);

  object->DefineOwnProperty(
      env()->context(),
      env()->state_string(),
      state_.GetArrayBuffer(),
      PropertyAttribute::ReadOnly).Check();

  ngtcp2_transport_params params;
  ngtcp2_conn_get_local_transport_params(session->connection(), &params);
  IncrementStat(&StreamStats::max_offset, params.initial_max_data);
}

Stream::~Stream() {
  DebugStats();
}

void Stream::Acknowledge(uint64_t offset, size_t datalen) {
  if (is_destroyed() || outbound_source_ == nullptr)
    return;

  // ngtcp2 guarantees that offset must always be greater
  // than the previously received offset.
  DCHECK_GE(offset, GetStat(&StreamStats::max_offset_ack));
  SetStat(&StreamStats::max_offset_ack, offset);

  Debug(this, "Acknowledging %d bytes", datalen);

  // Consumes the given number of bytes in the buffer.
  CHECK_LE(outbound_source_->Acknowledge(offset, datalen), datalen);
}

bool Stream::AddHeader(std::unique_ptr<Header> header) {
  size_t len = header->length();
  Session::Application* app = session()->application();
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

void Stream::AttachInboundConsumer(
    Buffer::Consumer* consumer,
    BaseObjectPtr<AsyncWrap> strong_ptr) {
  CHECK_IMPLIES(strong_ptr, consumer != nullptr);
  Debug(this, "%s data consumer",
      consumer != nullptr ? "Attaching" : "Clearing");
  inbound_consumer_ = consumer;
  inbound_consumer_strong_ptr_ = std::move(strong_ptr);
  ProcessInbound();
}

void Stream::AttachOutboundSource(Buffer::Source* source) {
  Debug(this, "%s data source",
        source != nullptr ? "Attaching" : "Clearing");
  if (source == nullptr) return;
  outbound_source_ = source;
  if (source != nullptr) {
    outbound_source_strong_ptr_ = source->GetStrongPtr();
    source->set_owner(this);
    Resume();
  }
}

void Stream::BeginHeaders(HeadersKind kind) {
  Debug(this, "Beginning Headers");
  headers_.clear();
  set_headers_kind(kind);
}

void Stream::Commit(size_t amount) {
  CHECK(!is_destroyed());
  if (outbound_source_ == nullptr)
    return;
  size_t actual = outbound_source_->Seek(amount);
  CHECK_LE(actual, amount);
}

void Stream::Destroy(const QuicError& error) {
  if (destroyed_)
    return;
  destroyed_ = true;
  // Triggers sending a RESET_STREAM and/or STOP_SENDING as
  // appropriate.
  // TODO(@jasnell): Determine if the shutdown stream triggers the
  // stream close flow. If so, then we don't need to call OnClose.
  session_->ShutdownStream(id_, error.code);
  OnClose();
}

int Stream::DoPull(
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

void Stream::EndHeaders() {
  Debug(this, "End Headers");
  session()->application()->StreamHeaders(id_, headers_kind_, headers_);
  headers_.clear();
}

void Stream::OnClose() {
  if (!destroyed_)
    destroyed_ = true;
  Unschedule();
  if (outbound_source_ != nullptr) {
    outbound_source_ = nullptr;
    outbound_source_strong_ptr_.reset();
  }
  session()->RemoveStream(id_);
  session_.reset();
}

void Stream::ProcessInbound() {
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
  IncrementStat(&StreamStats::max_offset, len);
  session_->ExtendStreamOffset(id_, len);
}

void Stream::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("outbound", outbound_source_);
  tracker->TrackField("outbound_strong_ptr", outbound_source_strong_ptr_);
  tracker->TrackField("inbound", inbound_);
  tracker->TrackField("inbound_consumer_strong_ptr_",
                      inbound_consumer_strong_ptr_);
  tracker->TrackField("headers", headers_);
  StatsBase::StatsMemoryInfo(tracker);
}

void Stream::ReceiveData(
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
  DCHECK_GE(offset, GetStat(&StreamStats::max_offset_received));
  SetStat(&StreamStats::max_offset_received, offset);

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
    UpdateStats(datalen);
    inbound_.Push(env(), data, datalen);
  }

  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
    set_final_size(offset + datalen);
    inbound_.End();
  }

  ProcessInbound();
}

void Stream::ResetStream(const QuicError& error) {
  CHECK_EQ(error.type, QuicError::Type::APPLICATION);
  Session::SendSessionScope send_scope(session());
  session()->ShutdownStream(id_, error.code);
  state_->read_ended = 1;
}

void Stream::Resume() {
  Session::SendSessionScope send_scope(session());
  Debug(this, "Resuming stream %" PRIu64, id_);
  session()->ResumeStream(id_);
}

void Stream::StopSending(const QuicError& error) {
  CHECK_EQ(error.type, QuicError::Type::APPLICATION);
  Session::SendSessionScope send_scope(session());
  ngtcp2_conn_shutdown_stream_read(
      session()->connection(),
      id_,
      error.code);
  state_->read_ended = 1;
}

void Stream::UpdateStats(size_t datalen) {
  uint64_t len = static_cast<uint64_t>(datalen);
  IncrementStat(&StreamStats::bytes_received, len);
}

void Stream::set_final_size(uint64_t final_size) {
  CHECK_IMPLIES(
      state_->fin_received == 1,
      final_size <= GetStat(&StreamStats::final_size));
  state_->fin_received = 1;
  SetStat(&StreamStats::final_size, final_size);
  Debug(this, "Set final size to %" PRIu64, final_size);
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
