#include "quic_buffer.h"  // NOLINT(build/include)
#include "quic_crypto.h"
#include "quic_session.h"
#include "quic_stream.h"
#include "quic_util-inl.h"
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_sockaddr-inl.h"
#include "node_bob-inl.h"
#include "stream_base-inl.h"
#include "util.h"
#include "uv.h"
#include "v8.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::ArrayBufferView;
using v8::BackingStore;
using v8::EscapableHandleScope;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Just;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Nothing;
using v8::Object;
using v8::String;
using v8::Value;
namespace quic {
QuicBufferSource* QuicBufferSource::FromObject(Local<Object> object) {
  return static_cast<QuicBufferSource*>(
      object->GetAlignedPointerFromInternalField(
          QuicBufferSource::kSourceField));
}

void QuicBufferSource::AttachToObject(Local<Object> object) {
  object->SetAlignedPointerInInternalField(
      QuicBufferSource::kSourceField, this);
}

QuicBufferChunk::QuicBufferChunk(
    const std::shared_ptr<v8::BackingStore>& data,
    size_t length,
    size_t offset)
    : data_(std::move(data)),
      offset_(offset),
      length_(length),
      unacknowledged_(length) {}

std::unique_ptr<QuicBufferChunk> QuicBufferChunk::Create(
    Environment* env,
    const uint8_t* data,
    size_t len) {
  std::shared_ptr<v8::BackingStore> store =
      v8::ArrayBuffer::NewBackingStore(env->isolate(), len);
  memcpy(store->Data(), data, len);
  return std::unique_ptr<QuicBufferChunk>(
      new QuicBufferChunk(std::move(store), len));
}

std::unique_ptr<QuicBufferChunk> QuicBufferChunk::Create(
    const std::shared_ptr<v8::BackingStore>& data,
    size_t length,
    size_t offset) {
  return std::unique_ptr<QuicBufferChunk>(
      new QuicBufferChunk(std::move(data), length, offset));
}

v8::MaybeLocal<v8::Value> QuicBufferChunk::Release(Environment* env) {
  v8::EscapableHandleScope scope(env->isolate());
  v8::Local<v8::Uint8Array> ret =
      v8::Uint8Array::New(
          v8::ArrayBuffer::New(env->isolate(), std::move(data_)),
          offset_,
          length_);
  CHECK(!data_);
  offset_ = 0;
  length_ = 0;
  read_ = 0;
  unacknowledged_ = 0;
  return scope.Escape(ret);
}

size_t QuicBufferChunk::Seek(size_t amount) {
  amount = std::min(amount, remaining());
  read_ += amount;
  CHECK_LE(read_, length_);
  return amount;
}

size_t QuicBufferChunk::Acknowledge(size_t amount) {
  amount = std::min(amount, unacknowledged_);
  unacknowledged_ -= amount;
  return amount;
}

ngtcp2_vec QuicBufferChunk::vec() const {
  uint8_t* ptr = static_cast<uint8_t*>(data_->Data());
  ptr += offset_ + read_;
  return ngtcp2_vec { ptr, length() };
}

const uint8_t* QuicBufferChunk::data() const {
  uint8_t* ptr = static_cast<uint8_t*>(data_->Data());
  ptr += offset_ + read_;
  return ptr;
}

void QuicBuffer::Push(Environment* env, const uint8_t* data, size_t len) {
  CHECK(!ended_);
  queue_.emplace_back(QuicBufferChunk::Create(env, data, len));
  length_ += len;
  remaining_ += len;
}

void QuicBuffer::Push(
    std::shared_ptr<v8::BackingStore> data,
    size_t length,
    size_t offset) {
  CHECK(!ended_);
  queue_.emplace_back(QuicBufferChunk::Create(std::move(data), length, offset));
  length_ += length;
  remaining_ += length;
}

size_t QuicBuffer::Seek(size_t amount) {
  if (queue_.empty())
    return 0;
  amount = std::min(amount, remaining_);
  size_t len = 0;
  while (amount > 0) {
    size_t actual = queue_[head_]->Seek(amount);
    CHECK_LE(actual, amount);
    amount -= actual;
    remaining_ -= actual;
    len += actual;
    if (actual) {
      head_++;
      // head_ should never extend beyond queue size!
      CHECK_LE(head_, queue_.size() - 1);
    }
  }
  return len;
}

size_t QuicBuffer::Acknowledge(size_t amount) {
  if (queue_.empty())
    return 0;
  amount = std::min(amount, length_);
  size_t len = 0;
  while (amount > 0) {
    CHECK_GT(queue_.size(), 0);
    size_t actual = queue_.front()->Acknowledge(amount);

    CHECK_LE(actual, amount);
    amount -= actual;
    length_ -= actual;
    len += actual;
    // If we've acknowledged all of the bytes in the current
    // chunk, pop it to free the memory and decrement the
    // head_ pointer if necessary.
    if (queue_.front()->length() == 0) {
      queue_.pop_front();
      if (head_ > 0) head_--;
    }
  }
  return len;
}

void QuicBufferChunk::MemoryInfo(MemoryTracker* tracker) const {
  if (data_)
    tracker->TrackFieldWithSize("data", data_->ByteLength());
}

void QuicBuffer::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("queue", queue_);
}

int QuicBuffer::DoPull(
    bob::Next<ngtcp2_vec> next,
    int options,
    ngtcp2_vec* data,
    size_t count,
    size_t max_count_hint) {
  size_t len = 0;
  size_t numbytes = 0;
  int status = bob::Status::STATUS_CONTINUE;

  // There's no data to read.
  if (queue_.empty() || !remaining_) {
    status = ended_ ?
        bob::Status::STATUS_END :
        bob::Status::STATUS_BLOCK;
    std::move(next)(status, nullptr, 0, [](size_t len) {});
    return status;
  }

  // Ensure that there's storage space.
  MaybeStackBuffer<ngtcp2_vec, kMaxVectorCount> vec;
  size_t queue_size = queue_.size() - head_;
  max_count_hint = (max_count_hint == 0)
      ? queue_size
      : std::min(max_count_hint, queue_size);

  CHECK_IMPLIES(data == nullptr, count == 0);
  if (data == nullptr) {
    vec.AllocateSufficientStorage(max_count_hint);
    data = vec.out();
    count = max_count_hint;
  }

  // Count should be greater than or equal to the number of
  // items we have available.
  CHECK_GE(count, queue_size);

  // Build the list of buffers.
  for (size_t n = head_;
       n < queue_.size() && len < count;
       n++, len++) {
    data[len] = queue_[n]->vec();
    numbytes += data[len].len;
  }

  // If the buffer is ended, and the number of bytes
  // matches the total remaining, and OPTIONS_END is
  // used, set the status to STATUS_END.
  if (is_ended() &&
      numbytes == remaining() &&
      options & bob::OPTIONS_END) {
    status = bob::Status::STATUS_END;
  }

  // Pass the data back out to the caller.
  std::move(next)(
      status,
      data,
      len,
      [this](size_t len) {
        size_t actual = Seek(len);
        CHECK_LE(actual, len);
      });

  return status;
}

Maybe<size_t> QuicBuffer::Release(QuicBufferConsumer* consumer) {
  if (queue_.empty())
    return Just(static_cast<size_t>(0));
  head_ = 0;
  length_ = 0;
  remaining_ = 0;
  return consumer->Process(std::move(queue_), ended_);
}

JSQuicBufferConsumer::JSQuicBufferConsumer(Environment* env, Local<Object> wrap)
    : AsyncWrap(env, wrap, AsyncWrap::PROVIDER_JSQUICBUFFERCONSUMER) {}

Maybe<size_t> JSQuicBufferConsumer::Process(
    std::deque<std::unique_ptr<QuicBufferChunk>> queue,
    bool ended) {
  EscapableHandleScope scope(env()->isolate());
  std::vector<Local<Value>> items;
  size_t len = 0;
  while (!queue.empty()) {
    Local<Value> val;
    len += queue.front()->length();
    // If this fails, the error is unrecoverable and neither
    // is the data. Return nothing to signal error and handle
    // upstream.
    if (!queue.front()->Release(env()).ToLocal(&val))
      return Nothing<size_t>();
    queue.pop_front();
    items.emplace_back(val);
  }

  Local<Value> args[] = {
    Array::New(env()->isolate(), items.data(), items.size()),
    ended ? v8::True(env()->isolate()) : v8::False(env()->isolate())
  };
  MakeCallback(env()->emit_string(), arraysize(args), args);
  return Just(len);
}

void JSQuicBufferConsumer::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> temp =
      env->NewFunctionTemplate(JSQuicBufferConsumer::New);
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "JSQuicBufferConsumer");
  temp->InstanceTemplate()->SetInternalFieldCount(
      JSQuicBufferConsumer::kInternalFieldCount);
  temp->SetClassName(class_name);
  target->Set(
      env->context(),
      class_name,
      temp->GetFunction(env->context()).ToLocalChecked()).Check();
}

void ArrayBufferViewSource::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> temp =
     env->NewFunctionTemplate(ArrayBufferViewSource::New);
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "ArrayBufferViewSource");
  temp->InstanceTemplate()->SetInternalFieldCount(
      QuicBufferSource::kInternalFieldCount);
  temp->SetClassName(class_name);
  target->Set(
      env->context(),
      class_name,
      temp->GetFunction(env->context()).ToLocalChecked()).Check();
}

void StreamSource::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> temp = env->NewFunctionTemplate(StreamSource::New);
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "StreamSource");
  temp->Inherit(AsyncWrap::GetConstructorTemplate(env));
  StreamBase::AddMethods(env, temp);
  temp->InstanceTemplate()->SetInternalFieldCount(
      StreamBase::kInternalFieldCount);
  temp->InstanceTemplate()->Set(env->owner_symbol(), Null(env->isolate()));
  temp->SetClassName(class_name);
  target->Set(
      env->context(),
      class_name,
      temp->GetFunction(env->context()).ToLocalChecked()).Check();
}

void StreamBaseSource::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> temp =
     env->NewFunctionTemplate(StreamBaseSource::New);
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "StreamBaseSource");
  temp->InstanceTemplate()->SetInternalFieldCount(
      QuicBufferSource::kInternalFieldCount);
  temp->SetClassName(class_name);
  target->Set(
      env->context(),
      class_name,
      temp->GetFunction(env->context()).ToLocalChecked()).Check();
}

void JSQuicBufferConsumer::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  new JSQuicBufferConsumer(env, args.This());
}

void ArrayBufferViewSource::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  CHECK(args[0]->IsArrayBufferView());
  Environment* env = Environment::GetCurrent(args);
  Local<ArrayBufferView> view = args[0].As<ArrayBufferView>();
  new ArrayBufferViewSource(
      env,
      args.This(),
      QuicBufferChunk::Create(
          view->Buffer()->GetBackingStore(),
          view->ByteLength(),
          view->ByteOffset()));
}

ArrayBufferViewSource::ArrayBufferViewSource(
    Environment* env,
    Local<Object> wrap,
    std::unique_ptr<QuicBufferChunk> chunk)
    : QuicBufferSource(),
      BaseObject(env, wrap),
      chunk_(std::move(chunk)) {
  MakeWeak();
  AttachToObject(object());
}

int ArrayBufferViewSource::DoPull(
    bob::Next<ngtcp2_vec> next,
    int options,
    ngtcp2_vec* data,
    size_t count,
    size_t max_count_hint) {
  int status = bob::Status::STATUS_CONTINUE;

  if (!chunk_ || !chunk_->remaining()) {
    status = bob::Status::STATUS_END;
    std::move(next)(status, nullptr, 0, [](size_t len) {});
    return status;
  }

  ngtcp2_vec vec;
  CHECK_IMPLIES(data == nullptr, count == 0);
  if (data == nullptr) {
    data = &vec;
    count = 1;
  }

  *data = chunk_->vec();

  if (options & bob::OPTIONS_END)
    status = bob::Status::STATUS_END;

  // Pass the data back out to the caller.
  std::move(next)(
      status,
      data,
      1,
      [this](size_t len) { chunk_->Seek(len); });

  return status;
}

size_t ArrayBufferViewSource::Acknowledge(
    uint64_t offset,
    size_t datalen) {
  if (!chunk_) return 0;
  size_t actual = chunk_->Acknowledge(datalen);
  if (!chunk_->remaining())
    chunk_.reset();
  return actual;
}

size_t ArrayBufferViewSource::Seek(size_t amount) {
  if (!chunk_) return 0;
  return chunk_->Seek(amount);
}

void ArrayBufferViewSource::MemoryInfo(MemoryTracker* tracker) const {
  // if (chunk_)
  //   tracker->TrackField("data", chunk_);
}

void StreamSource::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);
  new StreamSource(env, args.This());
}

StreamSource::StreamSource(Environment* env, Local<Object> wrap)
    : AsyncWrap(env, wrap, AsyncWrap::PROVIDER_STREAMSOURCE),
      StreamBase(env) {
  MakeWeak();
}

int StreamSource::DoPull(
    bob::Next<ngtcp2_vec> next,
    int options,
    ngtcp2_vec* data,
    size_t count,
    size_t max_count_hint) {
  return queue_.DoPull(std::move(next), options, data, count, max_count_hint);
}

int StreamSource::DoShutdown(ShutdownWrap* wrap) {
  if (queue_.is_ended())
    return UV_EPIPE;
  queue_.End();
  env()->SetImmediate([
    wrap,
    ref = BaseObjectPtr<AsyncWrap>(wrap->GetAsyncWrap())](Environment* env) {
      wrap->Done(0);
    });
  return 0;
}

int StreamSource::DoWrite(
    WriteWrap* w,
    uv_buf_t* bufs,
    size_t count,
    uv_stream_t* send_handle) {
  CHECK_NOT_NULL(owner());
  for (size_t n = 0; n < count; n++) {
    std::shared_ptr<BackingStore> store;
    if (n == count - 1) {
      store = ArrayBuffer::NewBackingStore(
        bufs[n].base,
        bufs[n].len,
        [](void* data, size_t len, void* ptr) {
          WriteWrap* wrap = static_cast<WriteWrap*>(ptr);
          wrap->Done(0);
        },
        w);
    } else {
      store = ArrayBuffer::NewBackingStore(
        bufs[n].base,
        bufs[n].len,
        [](void* data, size_t len, void* ptr) {},
        nullptr);
    }
    queue_.Push(std::move(store), store->ByteLength());
  }
  owner()->Resume();
  return 0;
}

size_t StreamSource::Acknowledge(uint64_t offset, size_t datalen) {
  return queue_.Acknowledge(datalen);
}

size_t StreamSource::Seek(size_t amount) {
  return queue_.Seek(amount);
}

void StreamSource::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("queue", queue_);
}

void StreamBaseSource::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  CHECK(args[0]->IsObject());
  Environment* env = Environment::GetCurrent(args);
  StreamBase* wrap = StreamBase::FromObject(args[0].As<Object>());
  new StreamBaseSource(
      env,
      args.This(),
      wrap,
      BaseObjectPtr<AsyncWrap>(wrap->GetAsyncWrap()));
}

StreamBaseSource::StreamBaseSource(
    Environment* env,
    Local<Object> obj,
    StreamResource* resource,
    BaseObjectPtr<AsyncWrap> strong_ptr)
    : AsyncWrap(env, obj, AsyncWrap::PROVIDER_STREAMBASESOURCE),
      strong_ptr_(std::move(strong_ptr)) {
  MakeWeak();
  resource_->PushStreamListener(this);
}

StreamBaseSource::~StreamBaseSource() {
  resource_->RemoveStreamListener(this);
}

uv_buf_t StreamBaseSource::OnStreamAlloc(size_t suggested_size) {
  uv_buf_t buf;
  buf.base = Malloc<char>(suggested_size);
  buf.len = suggested_size;
  return buf;
}

void StreamBaseSource::OnStreamRead(ssize_t nread, const uv_buf_t& buf_) {
  CHECK_NOT_NULL(owner());
  if (nread < 0) {
    buffer_.End();
  } else {
    std::shared_ptr<BackingStore> store =
        ArrayBuffer::NewBackingStore(
            static_cast<void*>(buf_.base),
            buf_.len,
            [](void* ptr, size_t len, void* deleter_data) {
              std::unique_ptr<char> delete_me(static_cast<char*>(ptr));
            },
            nullptr);
    buffer_.Push(std::move(store), store->ByteLength());
  }
  owner()->Resume();
}

int StreamBaseSource::DoPull(
    bob::Next<ngtcp2_vec> next,
    int options,
    ngtcp2_vec* data,
    size_t count,
    size_t max_count_hint) {
  return buffer_.DoPull(std::move(next), options, data, count, max_count_hint);
}

size_t StreamBaseSource::Acknowledge(uint64_t offset, size_t datalen) {
  return buffer_.Acknowledge(datalen);
}

size_t StreamBaseSource::Seek(size_t amount) {
  return buffer_.Seek(amount);
}

void StreamBaseSource::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("queue", buffer_);
}

}  // namespace quic
}  // namespace node
