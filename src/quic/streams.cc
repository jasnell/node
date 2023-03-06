#include "bindingdata-inl.h"
#include "defs.h"
#include "session-inl.h"
#include "streams-inl.h"
#include "util-inl.h"
#include <aliased_struct-inl.h>
#include <async_wrap-inl.h>
#include <env-inl.h>
#include <dataqueue/queue.h>
#include <memory_tracker.h>
#include <node_bob-inl.h>
#include <ngtcp2/ngtcp2.h>
#include <v8.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::BigInt;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::PropertyAttribute;
using v8::Uint32;
using v8::Undefined;
using v8::Value;

namespace quic {

// The data for a stream is provided in the form of a DataQueue.
// We use a DataQueue::Reader to consume that data.
// However, we are required to hold sent data in memory until
// it can be acknowledged, therefore we end up caching every bit
// of data we get from the reader and hold on to it until it can
// be acknowledged. This becomes tricky because of resends. We
// can never know in advance just what or how much data ngtcp2
// is going to actually encode within a data packet, so each
// time Pull is called, we simply provide a pointer to all of
// the data that is known to be available to be read right now.
class Stream::OutboundBuffer : public MemoryRetainer {
public:
  OutboundBuffer(Stream* stream, std::shared_ptr<DataQueue> queue)
      : stream_(stream),
        queue_(std::move(queue)),
        reader_(queue_->get_reader()) {}

  void Acknowledge(size_t amount) {
    size_t remaining = std::min(amount, total_ - uncommitted_);
    while (remaining > 0 && head_ != nullptr) {
      CHECK_LE(head_->ack_offset, head_->offset);
      // The amount to acknowledge in this chunk is the lesser of the total
      // amount remaining to acknowledge or the total remaining unacknowledged
      // bytes in the chunk.
      size_t amount_to_ack = std::min(remaining, head_->offset - head_->ack_offset);
      // If the amount to ack is zero here, it means our ack offset has caught up
      // to our commit offset, which means there's nothing left to acknowledge yet.
      // We could treat this as an error but let's just stop here.
      if (amount_to_ack == 0) break;

      // Adjust our remaining down and our ack_offset up...
      remaining -= amount_to_ack;
      head_->ack_offset += amount_to_ack;

      // If we've fully acknowledged this chunk, free it and decrement total.
      if (head_->ack_offset == head_->buf.len) {
        DCHECK_GE(total_, head_->buf.len);
        total_ -= head_->buf.len;
        // if tail_ == head_ here, it means we've fully acknowledged our current
        // buffer. Set tail to nullptr since we're freeing it here.
        if (head_.get() == tail_) {
          // In this case, commit_head_ should have already been set to nullptr.
          // Because we should only have hit this case if the entire buffer
          // had been committed.
          CHECK(commit_head_ == nullptr);
          tail_ = nullptr;
        }
        head_ = std::move(head_->next);
        CHECK_IMPLIES(head_ == nullptr, tail_ == nullptr);
      }
    }
  }

  void Commit(size_t amount) {
    // Commit amount number of bytes from the current uncommitted
    // byte queue. Importantly, this does not remove the bytes
    // from the byte queue.
    size_t remaining  = std::min(uncommitted_, amount);
    // There's nothing to commit.
    while (remaining > 0 && commit_head_ != nullptr) {
      // The amount to commit is the lesser of the total amount remaining to commit
      // and the remaining uncommitted bytes in this chunk.
      size_t amount_to_commit = std::min(remaining, commit_head_->buf.len - commit_head_->offset);

      // The amount to commit here should never be zero because that means we should
      // have already advanced the commit head.
      CHECK_NE(amount_to_commit, 0);
      uncommitted_ -= amount_to_commit;
      remaining -= amount_to_commit;
      commit_head_->offset += amount_to_commit;
      if (commit_head_->offset == commit_head_->buf.len) {
        count_--;
        commit_head_ = commit_head_->next.get();
      }
    }
  }

  // The "uncommitted bytes" are the bytes we have pulled from
  // the reader that we have not yet actually sent in a data
  // packet.
  size_t get_uncommitted_bytes_count() { return uncommitted_; }

  void Cap() {
    // Calling cap without a value halts the ability to add any
    // new data to the queue if it is not idempotent. If it is
    // idempotent, it's a non-op.
    queue_->cap();
  }

  // Pull only the set of uncommitted bytes.
  void PullUncommitted(bob::Next<ngtcp2_vec> next) {
    MaybeStackBuffer<ngtcp2_vec, 16> chunks;
    chunks.AllocateSufficientStorage(count_);
    auto head = commit_head_;
    size_t n = 0;
    while (head != nullptr && n < count_) {
      // There might only be one byte here but there should never be zero.
      DCHECK_LT(head->offset, head->buf.len);
      chunks[n].base = head->buf.base + head->offset;
      chunks[n].len = head->buf.len - head->offset;
      head = head->next.get();
      n++;
    }
    std::move(next)(bob::Status::STATUS_CONTINUE, chunks.out(), n, [](int) {});
  }

  struct OnComplete {
    bob::Done done;
    OnComplete(bob::Done done) : done(std::move(done)) {}
    ~OnComplete() { std::move(done)(0); }
  };

  void Append(const DataQueue::Vec* vectors, size_t count, bob::Done done) {
    if (count == 0) return;
    // The done callback should only be invoked after we're done with
    // all of the vectors passed in this call. To ensure of that, we
    // wrap it with a shared pointer that calls done when the final
    // instance is dropped.
    auto on_complete = std::make_shared<OnComplete>(std::move(done));
    for (size_t n = 0; n < count; n++) {
      if (vectors[n].len == 0 || vectors[n].base == nullptr) continue;
      auto entry = std::make_unique<Entry>(vectors[n], on_complete);
      if (tail_ == nullptr) {
        head_ = std::move(entry);
        tail_ = head_.get();
        commit_head_ = head_.get();
      } else {
        CHECK_NULL(tail_->next);
        tail_->next = std::move(entry);
        tail_ = tail_->next.get();
        if (commit_head_ == nullptr) commit_head_ = tail_;
      }
      count_++;
      total_ += vectors[n].len;
      uncommitted_ += vectors[n].len;
    }
  }

  int Pull(bob::Next<ngtcp2_vec> next,
           int options,
           ngtcp2_vec* data,
           size_t count,
           size_t max_count_hint) {
    if (next_pending_) {
      std::move(next)(bob::Status::STATUS_BLOCK, nullptr, 0, [](int) {});
      return bob::Status::STATUS_BLOCK;
    }

    // If eos_ is true and there are no uncommitted bytes we'll return eos.
    if (eos_ && get_uncommitted_bytes_count() == 0) {
      std::move(next)(bob::Status::STATUS_EOS, nullptr, 0, [](int) {});
      return bob::Status::STATUS_EOS;
    }

    // If there are uncommitted bytes in the queue_,
    // and there are enough to fill a full data packet,
    // then pull will just return the current uncommitted
    // bytes currently in the queue.
    if (get_uncommitted_bytes_count() >= kDefaultMaxPacketLength) {
      PullUncommitted(std::move(next));
      return bob::Status::STATUS_CONTINUE;
    }

    // If there aren't enough uncommitted bytes in the
    // queue to fill a data packet, we'll perform a
    // read from the reader.
    int ret = reader_->Pull([this](auto status, auto vecs, auto count, auto done) {
      // Always make sure next_pending_ is false when we're done.
      auto on_exit = OnScopeLeave([this] { next_pending_ = false; });

      // The status should never be wait here.
      CHECK_NE(status, bob::Status::STATUS_WAIT);

      if (status < 0) {
        // If next_pending_ is true then a pull from the reader
        // ended up being asynchronous, our stream is blocking
        // waiting for the data, but we have an error! oh no!
        // We need to error the stream.
        if (next_pending_) {
          stream_->Destroy(QuicError::ForNgtcp2Error(NGTCP2_INTERNAL_ERROR));
        }
        return;
      }

      if (status == bob::Status::STATUS_EOS) {
        eos_ = true;
        CHECK_EQ(count, 0);
        CHECK_NULL(vecs);
        // If next_pending_ is true then a pull from the reader
        // ended up being asynchronous, our stream is blocking
        // waiting for the data. Here, there is no more data to
        // read, but we will might have data in the uncommitted
        // queue. We'll resume the stream so that the session will
        // try to read from it again.
        if (next_pending_) stream_->Resume();
        return;
      }

      if (status == bob::Status::STATUS_BLOCK) {
        CHECK_EQ(count, 0);
        CHECK_NULL(vecs);
        // If next_pending_ is true then a pull from the reader
        // ended up being asynchronous, our stream is blocking
        // waiting for the data. Here, we're still blocking!
        // so there's nothing left for us to do!
        return;
      }

      CHECK_EQ(status, bob::Status::STATUS_CONTINUE);
      // If the read returns bytes, those will be added to the
      // uncommitted bytes in the queue.
      Append(vecs, count, std::move(done));

      // If next_pending_ is true, then a pull from the reader
      // ended up being asynchronous, our stream is blocking
      // waiting for the data. Now that we have data, let's
      // resume the stream so the session will pull from it
      // again.
      if (next_pending_) stream_->Resume();
    }, bob::OPTIONS_SYNC, nullptr, 0, kMaxVectorCount);

    if (ret < 0) {
      // There was an error. We'll report that immediately. We do not have
      // to destroy the stream here since that will be taken care of by
      // the caller.
      std::move(next)(ret, nullptr, 0, [](int) {});
      return ret;
    }

    if (ret == bob::Status::STATUS_EOS) {
      // The pull callback should have set eos_ to true.
      CHECK(eos_);
      if (get_uncommitted_bytes_count() > 0) {
        // If the read returns eos, and there are uncommitted
        // bytes in the queue, we'll set eos_ to true and
        // return the current set of uncommitted bytes.
        PullUncommitted(std::move(next));
        return bob::STATUS_CONTINUE;
      }
      // If the read returns eos, and there are no uncommitted
      // bytes in the queue, we'll return eos with no data.
      std::move(next)(bob::Status::STATUS_EOS, nullptr, 0, [](int){});
      return bob::Status::STATUS_EOS;
    }

    if (ret == bob::Status::STATUS_BLOCK) {
      // If the read returns blocked, and there are uncommitted
      // bytes in the queue, we'll return the current set of
      // uncommitted bytes.
      if (get_uncommitted_bytes_count() > 0) {
        PullUncommitted(std::move(next));
        return bob::Status::STATUS_CONTINUE;
      }
      // If the read returns blocked, and there are no uncommitted
      // bytes in the queue, we'll return blocked.
      std::move(next)(bob::Status::STATUS_BLOCK, nullptr, 0, [](int){});
      return bob::Status::STATUS_BLOCK;
    }

    if (ret == bob::Status::STATUS_WAIT) {
      // Unfortunately, reads here are generally expected to be synchronous.
      // If we have a reader that insists on providing data asynchronously,
      // then we'll have to pretend that we're blocking until the data is
      // actually available.
      next_pending_ = true;
      std::move(next)(bob::Status::STATUS_BLOCK, nullptr, 0, [](int) {});
      return bob::Status::STATUS_BLOCK;
    }

    CHECK_EQ(ret, bob::Status::STATUS_CONTINUE);
    PullUncommitted(std::move(next));
    return bob::Status::STATUS_CONTINUE;
  }

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackField("queue", queue_);
    tracker->TrackField("reader", reader_);
    tracker->TrackFieldWithSize("buffer", total_);
  }

  SET_MEMORY_INFO_NAME(Stream::OutboundBuffer)
  SET_SELF_SIZE(OutboundBuffer)

private:
  Stream* stream_;
  std::shared_ptr<DataQueue> queue_;
  std::shared_ptr<DataQueue::Reader> reader_;

  // Will be set to true if the reader_ ends up providing
  // a pull result asynchronously.
  bool next_pending_ = false;

  // Will be set to true once reader_ has returned eos.
  bool eos_ = false;

  // The collection of buffers that we have pulled from reader_
  // and are holding onto until they are acknowledged.
  struct Entry {
    size_t offset = 0;
    size_t ack_offset = 0;
    DataQueue::Vec buf;
    std::shared_ptr<OnComplete> on_complete;
    std::unique_ptr<Entry> next;
    Entry(DataQueue::Vec buf, std::shared_ptr<OnComplete> on_complete)
        : buf(buf), on_complete(std::move(on_complete)) {}
  };
  // The front of the queue.
  std::unique_ptr<Entry> head_ = nullptr;
  // The entry that marks the highest commit level
  Entry* commit_head_ = nullptr;
  Entry* tail_ = nullptr;

  // The total number of uncommitted chunks.
  size_t count_ = 0;

  // The total number of bytes currently held in the buffer.
  size_t total_ = 0;

  // The current byte offset of buffer_ that has been confirmed
  // to have been sent. Any offset lower than this represents
  // bytes that we are currently waiting to be acknowledged.
  // When we receive acknowledgement, we will automatically
  // free held bytes from the buffer.
  size_t uncommitted_ = 0;
};

void Stream::Initialize(Environment* env, Local<Object> target) {
  USE(GetConstructorTemplate(env));

#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATS_STREAM_##name);
  STREAM_STATS(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATS_STREAM_COUNT);
#undef V
#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATE_STREAM_##name);
  STREAM_STATE(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATE_STREAM_COUNT);
#undef V

  constexpr int QUIC_STREAM_HEADERS_KIND_INFO =
      static_cast<int>(Session::Application::HeadersKind::INFO);
  constexpr int QUIC_STREAM_HEADERS_KIND_INITIAL =
      static_cast<int>(Session::Application::HeadersKind::INITIAL);
  constexpr int QUIC_STREAM_HEADERS_KIND_TRAILING =
      static_cast<int>(Session::Application::HeadersKind::TRAILING);

  constexpr int QUIC_STREAM_HEADERS_FLAGS_NONE =
      static_cast<int>(Session::Application::HeadersFlags::NONE);
  constexpr int QUIC_STREAM_HEADERS_FLAGS_TERMINAL =
      static_cast<int>(Session::Application::HeadersFlags::TERMINAL);

  NODE_DEFINE_CONSTANT(target, QUIC_STREAM_HEADERS_KIND_INFO);
  NODE_DEFINE_CONSTANT(target, QUIC_STREAM_HEADERS_KIND_INITIAL);
  NODE_DEFINE_CONSTANT(target, QUIC_STREAM_HEADERS_KIND_TRAILING);

  NODE_DEFINE_CONSTANT(target, QUIC_STREAM_HEADERS_FLAGS_NONE);
  NODE_DEFINE_CONSTANT(target, QUIC_STREAM_HEADERS_FLAGS_TERMINAL);
}

BaseObjectPtr<Stream> Stream::Create(Environment* env,
                                     Session* session,
                                     stream_id id,
                                     std::unique_ptr<DataQueue> source) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(env);
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Stream>();

  return MakeDetachedBaseObject<Stream>(BaseObjectPtr<Session>(session),
                                        obj, id, std::move(source));
}

Stream::Stream(BaseObjectPtr<Session> session,
               Local<Object> object,
               stream_id id,
               std::unique_ptr<DataQueue> source)
    : AsyncWrap(session->env(), object, AsyncWrap::PROVIDER_QUIC_STREAM),
      stats_(session->env()),
      session_(session),
      state_(session->env()->isolate()),
      inbound_(DataQueue::Create()) {
  MakeWeak();
  state_->id = id;
  USE(ngtcp2_conn_set_stream_user_data(*session, id, this));

  // Allows us to be notified when data is actually read from the
  // inbound queue so that we can update the stream flow control.
  inbound_->addBackpressureListener(this);

  if (direction() == Direction::UNIDIRECTIONAL) {
    switch (origin()) {
      case CryptoContext::Side::CLIENT: {
        switch (session->crypto_context().side()) {
          case CryptoContext::Side::CLIENT: {
            // When a unidirectional stream originates on the client and
            // we're the client, this stream is outbound only. There's
            // nothing to read.
            EndReadable(0);
            break;
          }
          case CryptoContext::Side::SERVER: {
            // When a unidirectional stream originates on the client and
            // we're the server, this stream is inbound only. There's
            // nothing to write.
            EndWritable();
            CHECK(source == nullptr);
            break;
          }
        }
      }
      case CryptoContext::Side::SERVER: {
        switch (session->crypto_context().side()) {
          case CryptoContext::Side::CLIENT: {
            // When a unidirectional stream originates on the server and
            // we're the client, this stream is inbound only. There's
            // nothing to write.
            EndWritable();
            CHECK(source == nullptr);
            break;
          }
          case CryptoContext::Side::SERVER: {
            // When a unidirectional stream originates on the server and
            // we're the server, this stream is inbound only. There's
            // nothing to write.
            EndReadable(0);
            break;
          }
        }
      }
    }
  }

  AttachDataQueue(std::move(source));

  const auto defineProperty = [&](auto name, auto value) {
    object
        ->DefineOwnProperty(
            env()->context(), name, value, PropertyAttribute::ReadOnly)
        .Check();
  };

  defineProperty(env()->state_string(), state_.GetArrayBuffer());
  defineProperty(env()->stats_string(), stats_.ToBigUint64Array(env()));

  auto params = ngtcp2_conn_get_local_transport_params(*session);
  stats_.Increment<&Stats::max_offset>(params->initial_max_data);
}

Stream::~Stream() {
  // Just in case Destroy() wasn't called...
  inbound_->removeBackpressureListener(this);
}

void Stream::EntryRead(size_t amount) {
  // Tells us that amount bytes were read from inbound_
  // We use this as a signal to extend the flow control
  // window to receive more bytes.
  if (is_destroyed()) return;
  if (session_) session_->ExtendStreamOffset(id(), amount);
}

std::shared_ptr<DataQueue::Reader> Stream::get_reader() {
  return inbound_->get_reader();
}

void Stream::Acknowledge(uint64_t offset, size_t datalen) {
  if (is_destroyed() || outbound_ == nullptr) return;

  // ngtcp2 guarantees that offset must always be greater than the previously
  // received offset.
  DCHECK_GE(offset, stats_.Get<&Stats::max_offset_ack>());
  stats_.Set<&Stats::max_offset_ack>(offset);

  // // Consumes the given number of bytes in the buffer.
  outbound_->Acknowledge(datalen);
}

void Stream::AttachDataQueue(std::shared_ptr<DataQueue> source) {
  if (source == nullptr) return;
  outbound_ = std::make_unique<OutboundBuffer>(this, std::move(source));
  session_->ResumeStream(id());
}

void Stream::Resume() {
  if (is_destroyed()) return;
  session_->ResumeStream(id());
}

void Stream::Commit(size_t amount) {
  if (is_destroyed() || outbound_ == nullptr) return;
  outbound_->Commit(amount);
}

int Stream::DoPull(bob::Next<ngtcp2_vec> next,
                   int options,
                   ngtcp2_vec* data,
                   size_t count,
                   size_t max_count_hint) {
  if (is_destroyed() || state_->reset == 1) return bob::Status::STATUS_EOS;

  // If an outbound source has not yet been attached, block until one is
  // available. When AttachOutboundSource() is called the stream will be
  // resumed. Note that when we say "block" here we don't mean it in the
  // traditional "block the thread" sense. Instead, this will inform the
  // Session to not try to send any more data from this stream until there
  // is a source attached.
  if (outbound_ == nullptr) {
    std::move(next)(bob::Status::STATUS_BLOCK, nullptr, 0, [](size_t len) {});
    return bob::Status::STATUS_BLOCK;
  }

  return outbound_->Pull(
      std::move(next), options, data, count, max_count_hint);
}

bool Stream::AddHeader(const Header& header) {
  if (is_destroyed()) return false;
  size_t len = header.length();
  if (!session()->application().CanAddHeader(headers_.size(), current_headers_length_, len)) {
    return false;
  }

  current_headers_length_ += len;

  auto& state = BindingData::Get(env());

  const auto push = [&](auto raw) {
    Local<Value> value;
    if (UNLIKELY(!raw.ToLocal(&value))) return false;
    headers_.push_back(value);
    return true;
  };

  return push(header.GetName(&state)) && push(header.GetValue(&state));
}

void Stream::BeginHeaders(Session::Application::HeadersKind kind) {
  if (is_destroyed()) return;
  headers_.clear();
  headers_kind_ = kind;
}

void Stream::Blocked() {
  if (is_destroyed() || !env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);
  MakeCallback(BindingData::Get(env()).stream_blocked_callback(), 0, nullptr);
}

void Stream::EmitClose() {
  if (!env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);
  MakeCallback(BindingData::Get(env()).stream_close_callback(), 0, nullptr);
}

void Stream::EmitReset(QuicError error) {
  if (!env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);
  Local<Value> err;
  if (!error.ToV8Value(env()).ToLocal(&err))
    return;

  MakeCallback(BindingData::Get(env()).stream_reset_callback(), 1, &err);
}

void Stream::EmitError(QuicError error) {
  if (!env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);
  Local<Value> err;
  if (!error.ToV8Value(env()).ToLocal(&err))
    return;

  MakeCallback(BindingData::Get(env()).stream_reset_callback(), 1, &err);
}

void Stream::EmitHeaders() {
  if (!env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
      Array::New(env()->isolate(), headers_.data(), headers_.size()),
      Integer::NewFromUnsigned(env()->isolate(),
                               static_cast<uint32_t>(headers_kind_))};

  headers_.clear();

  MakeCallback(BindingData::Get(env()).stream_headers_callback(),
               arraysize(argv),
               argv);
}

void Stream::DoStopSending(const FunctionCallbackInfo<Value>& args) {
  Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (!args[0]->IsUndefined()) {
    CHECK(args[0]->IsBigInt());
    bool lossless = false;  // not used.
    error_code code = args[0].As<BigInt>()->Uint64Value(&lossless);
    stream->StopSending(QuicError::ForApplication(code));
  } else {
    stream->StopSending(QuicError::ForApplication(NGTCP2_APP_NOERROR));
  }
}

void Stream::DoResetStream(const FunctionCallbackInfo<Value>& args) {
  Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (!args[0]->IsUndefined()) {
    CHECK(args[0]->IsBigInt());
    bool lossless = false;  // not used.
    error_code code = args[0].As<BigInt>()->Uint64Value(&lossless);
    stream->ResetStream(QuicError::ForApplication(code));
  } else {
    stream->ResetStream(QuicError::ForApplication(NGTCP2_APP_NOERROR));
  }
}

void Stream::DoSendHeaders(const FunctionCallbackInfo<Value>& args) {
  Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsUint32());  // Kind
  CHECK(args[1]->IsArray());   // Headers
  CHECK(args[2]->IsUint32());  // Flags

  Session::Application::HeadersKind kind =
      static_cast<Session::Application::HeadersKind>(
          args[0].As<Uint32>()->Value());
  Local<Array> headers = args[1].As<Array>();
  Session::Application::HeadersFlags flags =
      static_cast<Session::Application::HeadersFlags>(
          args[2].As<Uint32>()->Value());

  args.GetReturnValue().Set(stream->SendHeaders(kind, headers, flags));
}

void Stream::DoDestroy(const FunctionCallbackInfo<Value>& args) {
  Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->Destroy();
}

void Stream::AttachSource(const FunctionCallbackInfo<Value>& args) {
  // Environment* env = Environment::GetCurrent(args);
  // Stream* stream;
  // ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());

  // CHECK_IMPLIES(!args[0]->IsUndefined(), args[0]->IsObject());

  // Buffer::Source* source = nullptr;

  // if (args[0]->IsUndefined()) {
  //   source = &null_source_;
  // } else if (ArrayBufferViewSource::HasInstance(env, args[0])) {
  //   ArrayBufferViewSource* view;
  //   ASSIGN_OR_RETURN_UNWRAP(&view, args[0]);
  //   source = view;
  // } else if (StreamSource::HasInstance(env, args[0])) {
  //   StreamSource* view;
  //   ASSIGN_OR_RETURN_UNWRAP(&view, args[0]);
  //   source = view;
  // } else if (StreamBaseSource::HasInstance(env, args[0])) {
  //   StreamBaseSource* view;
  //   ASSIGN_OR_RETURN_UNWRAP(&view, args[0]);
  //   source = view;
  // } else if (BlobSource::HasInstance(env, args[0])) {
  //   BlobSource* blob;
  //   ASSIGN_OR_RETURN_UNWRAP(&blob, args[0]);
  //   source = blob;
  // } else {
  //   UNREACHABLE();
  // }

  // stream->AttachOutboundSource(source);
}

void Stream::EndWritable() {
  if (is_destroyed()) return;
  Unschedule();
  if (outbound_ != nullptr) outbound_->Cap();
}

void Stream::EndReadable(std::optional<uint64_t> maybe_final_size) {
  if (is_destroyed()) return;
  if (maybe_final_size != std::nullopt) {
    set_final_size(maybe_final_size.value());
  } else {
    set_final_size(stats_.Get<&Stats::max_offset_received>());
  }
  inbound_->cap(final_size());
  state_->read_ended = 1;
}

void Stream::DoSetPriority(const FunctionCallbackInfo<Value>& args) {
  Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  CHECK(args[0]->IsUint32());  // Priority
  CHECK(args[1]->IsUint32());  // Priority flag

  Session::Application::StreamPriority priority =
      static_cast<Session::Application::StreamPriority>(
          args[0].As<Uint32>()->Value());
  Session::Application::StreamPriorityFlags flags =
      static_cast<Session::Application::StreamPriorityFlags>(
          args[1].As<Uint32>()->Value());

  stream->SetPriority(priority, flags);
}

void Stream::DoGetPriority(const FunctionCallbackInfo<Value>& args) {
  Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(static_cast<uint32_t>(stream->GetPriority()));
}

void Stream::Destroy(QuicError error) {
  if (is_destroyed()) return;

  // End the writable before marking as destroyed.
  EndWritable();

  // Also end the readable side if it isn't already.
  EndReadable();

  state_->destroyed = 1;

  if (error) EmitError(error);
  else EmitClose();

  inbound_->removeBackpressureListener(this);
  session_->RemoveStream(id());
}

void Stream::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("outbound", outbound_);
  tracker->TrackField("inbound", inbound_);
  tracker->TrackField("headers", headers_);
  tracker->TrackField("stats", stats_);
}

void Stream::ReadyForTrailers() {
  if (LIKELY(state_->trailers == 0)) return;

  EmitTrailers();
}

void Stream::EmitTrailers() {
  if (!env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);
  MakeCallback(BindingData::Get(env()).stream_trailers_callback(), 0, nullptr);
}

void Stream::ReceiveData(Session::Application::ReceiveStreamDataFlags flags,
                         const uint8_t* data,
                         size_t datalen,
                         uint64_t offset) {
  if (is_destroyed()) return;

  auto on_exit = OnScopeLeave([&] {
    if (flags.fin) EndReadable(offset + datalen);
  });

  // We should never receive data after we've already received the final size.
  CHECK(final_size() == 0 && !inbound_->is_capped());

  // ngtcp2 guarantees that datalen will only be 0 if fin is set.
  DCHECK_IMPLIES(datalen == 0, flags.fin);

  // ngtcp2 guarantees that offset is greater than the previously received.
  DCHECK_GE(offset, stats_.Get<&Stats::max_offset_received>());
  stats_.Set<&Stats::max_offset_received>(offset);

  // If reading has ended, or there is no data, do nothing.
  if (state_->read_ended == 1 || datalen == 0) return;

  UpdateStats(datalen);
  auto backing = ArrayBuffer::NewBackingStore(env()->isolate(), datalen);
  memcpy(backing->Data(), data, datalen);
  inbound_->append(DataQueue::CreateInMemoryEntryFromBackingStore(
      std::move(backing), 0, datalen));
}

void Stream::ReceiveResetStream(size_t final_size, QuicError error) {
  // Importantly, reset stream only impacts the inbound data flow.
  // It has no impact on the outbound data flow. It is essentially
  // a signal that the peer has abruptly terminated the writable end
  // of their stream with an error.
  if (is_destroyed()) return;
  EndReadable(final_size);
  EmitReset(error);
}

void Stream::ReceiveStopSending(QuicError error) {
  // Note that this comes from *this* endpoint, not the other side. We handle it
  // if we haven't already shutdown our *receiving* side of the stream.
  if (is_destroyed() || state_->read_ended) return;
  ngtcp2_conn_shutdown_stream_read(*session(), id(), error.code());
  EndReadable();
}

void Stream::ResetStream(QuicError error) {
  if (is_destroyed()) return;
  CHECK_EQ(error.type(), QuicError::Type::APPLICATION);
  Session::SendPendingDataScope send_scope(session());
  EndWritable();
  ngtcp2_conn_shutdown_stream_write(*session(), id(), error.code());
  state_->reset = 1;
}

void Stream::StopSending(QuicError error) {
  if (is_destroyed()) return;
  CHECK_EQ(error.type(), QuicError::Type::APPLICATION);
  Session::SendPendingDataScope send_scope(session());
  // Now we shut down the stream readable side.
  ngtcp2_conn_shutdown_stream_read(*session(), id(), error.code());
  EndReadable();
}

bool Stream::SendHeaders(Session::Application::HeadersKind kind,
                         const Local<Array>& headers,
                         Session::Application::HeadersFlags flags) {
  if (is_destroyed()) return false;
  return session_->application().SendHeaders(id(), kind, headers, flags);
}

void Stream::UpdateStats(size_t datalen) {
  stats_.Increment<&Stats::bytes_received>(static_cast<uint64_t>(datalen));
}

void Stream::set_final_size(uint64_t final_size) {
  CHECK_IMPLIES(state_->fin_received == 1,
                final_size <= stats_.Get<&Stats::final_size>());
  state_->fin_received = 1;
  stats_.Set<&Stats::final_size>(final_size);
}

void Stream::Schedule(Queue* queue) {
  if (is_destroyed() || outbound_ == nullptr) return;
  // If this stream is not already in the queue to send data, add it.
  if (stream_queue_.IsEmpty()) queue->PushBack(this);
}

void Stream::Unschedule() {
  stream_queue_.Remove();
}

void Stream::SetPriority(
    Session::Application::StreamPriority priority,
    Session::Application::StreamPriorityFlags flags) {
  if (is_destroyed()) return;
  session_->application().SetStreamPriority(this, priority, flags);
}

Session::Application::StreamPriority Stream::GetPriority() {
  if (is_destroyed()) return Session::Application::StreamPriority::DEFAULT;
  return session_->application().GetStreamPriority(this);
}

}  // namespace quic
}  // namespace node
