#include "node_blob.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_bob-inl.h"
#include "node_errors.h"
#include "node_external_reference.h"
#include "node_file-inl.h"
#include "stream_base-inl.h"
#include "threadpoolwork-inl.h"
#include "v8.h"

#include <algorithm>

namespace node {

using node::fs::FileHandle;

using v8::Array;
using v8::ArrayBuffer;
using v8::ArrayBufferView;
using v8::BackingStore;
using v8::Context;
using v8::EscapableHandleScope;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Just;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Nothing;
using v8::Number;
using v8::Object;
using v8::Uint32;
using v8::Undefined;
using v8::Value;

std::shared_ptr<BackingStoreView> empty_backing_store_view =
    std::make_shared<BackingStoreView>();

BackingStoreView::BackingStoreView(std::shared_ptr<v8::BackingStore> store)
    : BackingStoreView(std::move(store), store->ByteLength(), 0) {}

BackingStoreView::BackingStoreView(
    std::shared_ptr<v8::BackingStore> store,
    size_t length,
    size_t offset)
    : store_(store),
      length_(length),
      offset_(offset) {
  if (store_) {
    CHECK_LE(offset, store_->ByteLength());
    CHECK_LE(length, store_->ByteLength() - offset);
  }
  if (!store_) {
    view_ = { nullptr, 0 };
  } else {
    char* base = reinterpret_cast<char*>(store_->Data());
    base += offset_;
    view_ = uv_buf_init(base, length_);
  }
}

BackingStoreView::BackingStoreView()
    : BackingStoreView(std::shared_ptr<BackingStore>(), 0, 0) {}

BackingStoreView::BackingStoreView(const BackingStoreView& other)
    : store_(other.store_),
      length_(other.length_),
      offset_(other.offset_),
      view_(other.view_) {}

BackingStoreView& BackingStoreView::operator=(
    const BackingStoreView& other) {
  if (&other == this) return *this;
  this->~BackingStoreView();
  return *new (this) BackingStoreView(other);
}

BackingStoreView::BackingStoreView(BackingStoreView&& other)
    : store_(std::move(other.store_)),
      length_(other.length_),
      offset_(other.offset_),
      view_(other.view_) {
  other.length_ = 0;
  other.offset_ = 0;
  other.view_ = uv_buf_init(nullptr, 0);
}

BackingStoreView& BackingStoreView::operator=(BackingStoreView&& other) {
  if (&other == this) return *this;
  this->~BackingStoreView();
  return *new (this) BackingStoreView(other);
}

std::shared_ptr<BackingStoreView> BackingStoreView::Slice(
    size_t start,
    size_t end) {
  if (!store_) return empty_backing_store_view;
  CHECK_LE(offset_ + start, store_->ByteLength());
  CHECK_LE(offset_ + end, store_->ByteLength());
  CHECK_LE(start, end);
  return std::make_shared<BackingStoreView>(
      store_,
      end - start,
      offset_ + start);
}

Maybe<bool> BackingStoreView::CopyInto(
    std::shared_ptr<BackingStore> dest,
    size_t offset) {
  const uv_buf_t view = View();
  if (!dest ||
      offset > dest->ByteLength() ||
      (dest->ByteLength() - offset) < view.len) {
    return Nothing<bool>();
  }
  if (view.len > 0) {
    CHECK_NOT_NULL(view.base);
    memcpy(dest->Data(), view.base, view.len);
  }
  return Just(true);
}

BlobItem::BlobItem(Environment* env, const BackingStoreView::List& items)
    : env_(env),
      realized_(items) {
  size_t length = 0;
  for (const auto& item : realized_)
    length += item->length();
  expected_length_ = realized_length_ = length;
}

BlobItem::BlobItem(Environment* env, Loader loader, size_t expected_length)
    : env_(env),
      loader_(std::move(loader)),
      expected_length_(expected_length),
      min_waiting_reader_offset_(expected_length) {
  uv_async_init(env_->event_loop(), &waiting_reader_signal_, OnWaitingReader);
}

void BlobItem::OnWaitingReader(uv_async_t* signal) {
  BlobItem* item = ContainerOf(&BlobItem::waiting_reader_signal_, signal);
  item->ReadMore();
}

Maybe<bool> BlobItem::WaitForData(
    Reader* reader,
    size_t start_hint,
    size_t end_hint) {
  if (!is_loading() || start_hint > end_hint)
    return Nothing<bool>();

  // There's no point in waiting for nothing, or in waiting for
  // data that has already been realized.
  if (start_hint == end_hint || end_hint <= realized_length_)
    return Just(false);

  {
    Mutex::ScopedLock lock(waiting_readers_mutex_);

    // The minimum waiting reader offset is the minimum offset
    min_waiting_reader_offset_ =
        std::max(
            realized_length_,
            std::min(
                min_waiting_reader_offset_,
                start_hint));
    max_waiting_reader_offset_ =
        std::max(
            max_waiting_reader_offset_,
            end_hint);

    waiting_readers_.insert(reader);
  }

  uv_async_send(&waiting_reader_signal_);

  return Just(true);
}

void BlobItem::StopWaitingForData(Reader* reader) {
  Mutex::ScopedLock lock(waiting_readers_mutex_);
  waiting_readers_.erase(reader);
}

Maybe<BackingStoreView::List> BlobItem::Slice(size_t start, size_t end) {
  if (start > end || end > realized_length_)
    return Nothing<BackingStoreView::List>();

  BackingStoreView::List list;

  if (end - start > 0) {
    for (const auto& item : realized_) {
      if (start > item->length()) {
        start -= item->length();
        end -= item->length();
        continue;
      }
      size_t current_end = std::min(end, item->length());
      list.emplace_back(item->Slice(start, current_end));
      start = 0;
      end -= current_end;
      if (end == 0)
        break;
    }
  }

  return Just(list);
}

void BlobItem::ReadMore() {
  // If there is no loader, or we're already waiting on the loader,
  // just return. There's nothing else to do.
  if (!loader_ || waiting_on_loader_) return;

  waiting_on_loader_ = true;

  loader_->Pull([&](
      int status,
      const std::shared_ptr<BackingStoreView>* views,
      size_t count,
      bob::Done done) {
        // No need to lock here since adding to the realized data is always
        // done on the same event loop thread.
        waiting_on_loader_ = false;
        size_t prior_realized_length_ = realized_length_;
        for (size_t n = 0; n < count; n++) {
          realized_.emplace_back(views[n]);
          realized_length_ += views[n]->length();
          expected_length_ = std::max(expected_length_, realized_length_);
        }
        Mutex::ScopedLock lock(waiting_readers_mutex_);
        std::set<Reader*> waiting_readers = waiting_readers_;
        Reader::NotifyFlag flag = (status == bob::Status::STATUS_END)
            ? Reader::NotifyFlag::kDone
            : Reader::NotifyFlag::kNone;
        for (Reader* reader : waiting_readers) {
          if (!reader->Notify(prior_realized_length_, realized_length_, flag))
            waiting_readers_.erase(reader);
        }
        if (flag == Reader::NotifyFlag::kDone) {
          waiting_readers_.clear();
          loader_.reset();
        }
        done(count);
        if (realized_length_ < max_waiting_reader_offset_)
          uv_async_send(&waiting_reader_signal_);
      },
      bob::OPTIONS_NONE,
      nullptr, 0);
}

BlobItem::Reader::Reader(Environment* env, std::shared_ptr<BlobItem> item)
    : env_(env),
      item_(item) {
  uv_async_init(env_->event_loop(), &notify_signal_, OnNotify);
  uv_unref(reinterpret_cast<uv_handle_t*>(&notify_signal_));
}

void BlobItem::Reader::OnNotify(uv_async_t* signal) {
  BlobItem::Reader* reader =
      ContainerOf(&BlobItem::Reader::notify_signal_, signal);
  if (reader->next_ == nullptr) return;
  USE(reader->ProcessNext());
}

bool BlobItem::Reader::Notify(size_t start, size_t end, NotifyFlag flag) {
  eos_ = (flag == NotifyFlag::kDone);
  if (next_ != nullptr)
    uv_async_send(&notify_signal_);

  // Returning false from this function will instruct the BlobItem to remove
  // this Reader from the waiting_readers set. Returning true will keep the
  // Reader in the set until the end of the stream is reached. Typically,
  // returning false is what we want.
  return end < waiting_for_end_;
}

bob::Status BlobItem::Reader::ProcessNext() {
  Maybe<BackingStoreView::List> maybe_slice =
      item_->Slice(max_offset_, item_->realized_length());
  CHECK(maybe_slice.IsJust());
  max_offset_ = item_->realized_length();

  BackingStoreView::List slice = maybe_slice.FromJust();
  bob::Status status =
      eos_ ? bob::Status::STATUS_END : bob::Status::STATUS_BLOCK;
  std::move(next_)(
      status,
      slice.data(),
      slice.size(),
      [](size_t count) {});
  next_ = nullptr;
  return status;
}

int BlobItem::Reader::DoPull(
    bob::Next<std::shared_ptr<BackingStoreView>> next,
    int options,
    std::shared_ptr<BackingStoreView>* data,
    size_t count,
    size_t max_count_hint) {
  // If max_offset_ is less than the realized length, pull
  // the slice max_offset_ thru realized length, otherwise
  // queue the reader as pending.
  next_ = std::move(next);
  waiting_for_end_ = item_->realized_length();

  if (max_offset_ < waiting_for_end_) {
    eos_ = true;
    uv_async_send(&notify_signal_);
    return bob::STATUS_CONTINUE;
  }

  item_->WaitForData(this, max_offset_, waiting_for_end_);
  return bob::STATUS_WAIT;
}

void Blob2::Initialize(Environment* env, v8::Local<v8::Object> target) {
  env->SetMethod(target, "createBlob2", New);
  // FixedSizeBlobCopyJob::Initialize(env, target);
}

Local<FunctionTemplate> Blob2::GetConstructorTemplate(Environment* env) {
  Local<FunctionTemplate> tmpl = env->blob2_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->InstanceTemplate()->SetInternalFieldCount(1);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->SetClassName(
        FIXED_ONE_BYTE_STRING(env->isolate(), "Blob2"));
    // env->SetProtoMethod(tmpl, "toArrayBuffer", ToArrayBuffer);
    env->SetProtoMethod(tmpl, "slice", ToSlice);
    env->set_blob2_constructor_template(tmpl);
  }
  return tmpl;
}

bool Blob2::HasInstance(Environment* env, v8::Local<v8::Value> object) {
  return GetConstructorTemplate(env)->HasInstance(object);
}

BaseObjectPtr<Blob2> Blob2::Create(
    Environment* env,
    const BlobItem::List& store,
    size_t length) {

  HandleScope scope(env->isolate());

  Local<Function> ctor;
  if (!GetConstructorTemplate(env)->GetFunction(env->context()).ToLocal(&ctor))
    return BaseObjectPtr<Blob2>();

  Local<Object> obj;
  if (!ctor->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Blob2>();

  return MakeBaseObject<Blob2>(env, obj, store, length);
}

void Blob2::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsArray());  // sources
  CHECK(args[1]->IsUint32());  // length

  BlobItem::List entries;

  size_t length = args[1].As<Uint32>()->Value();
  size_t len = 0;
  Local<Array> ary = args[0].As<Array>();
  for (size_t n = 0; n < ary->Length(); n++) {
    Local<Value> entry;
    if (!ary->Get(env->context(), n).ToLocal(&entry))
      return;
    if (entry->IsArrayBufferView()) {
      Local<ArrayBufferView> view = entry.As<ArrayBufferView>();
      CHECK_EQ(view->ByteOffset(), 0);
      std::shared_ptr<BackingStore> store = view->Buffer()->GetBackingStore();
      size_t byte_length = view->ByteLength();
      view->Buffer()->Detach();  // The Blob will own the backing store now.

      BackingStoreView::List view_list;
      view_list.emplace_back(
          std::make_shared<BackingStoreView>(std::move(store), byte_length));

      entries.emplace_back(std::make_shared<BlobItem>(env, view_list));
      len += byte_length;
    } else if (Blob2::HasInstance(env, entry)) {
      Blob2* blob;
      ASSIGN_OR_RETURN_UNWRAP(&blob, entry);
      auto source = blob->entries();
      entries.insert(entries.end(), source.begin(), source.end());
      len += blob->length();
    } else if (FileHandle::HasInstance(env, entry)) {
      FileHandle* file;
      ASSIGN_OR_RETURN_UNWRAP(&file, entry);

      uv_fs_t fs;
      fs.file = file->GetFD();
      if (uv_fs_stat(env->event_loop(), &fs, nullptr, nullptr) != 0) {
        // TODO(@jasnell): Better, more appropriate error
        return THROW_ERR_INVALID_ARG_VALUE(env, "Invalid File");
      }
      len += fs.statbuf.st_size;

      BlobItem::Loader loader(
          new StreamBaseBlobItemLoader(
              env,
              file,
              BaseObjectPtr<FileHandle>(file)));
      entries.emplace_back(
          std::make_shared<BlobItem>(
              env,
              std::move(loader),
              fs.statbuf.st_size));
    } else {
      UNREACHABLE();
    }
  }

  BaseObjectPtr<Blob2> blob = Create(env, entries, length);
  if (blob) {
    blob->object()->Set(
        env->context(),
        env->size_string(),
        Number::New(env->isolate(), len));
    args.GetReturnValue().Set(blob->object());
  }
}

void Blob2::ToSlice(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Blob2* blob;
  ASSIGN_OR_RETURN_UNWRAP(&blob, args.Holder());
  CHECK(args[0]->IsUint32());
  CHECK(args[1]->IsUint32());
  size_t start = args[0].As<Uint32>()->Value();
  size_t end = args[1].As<Uint32>()->Value();
  BaseObjectPtr<Blob2> slice = blob->Slice(env, start, end);

  if (slice)
    args.GetReturnValue().Set(slice->object());
}

void Blob2::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("store", length_);
}

BaseObjectPtr<Blob2> Blob2::Slice(Environment* env, size_t start, size_t end) {
  CHECK_LE(start, length());
  CHECK_LE(end, length());
  CHECK_LE(start, end);

  BlobItem::List slices;
  size_t total = end - start;

  if (total == 0) return Create(env, slices, 0);

  for (const auto& entry : entries()) {
    if (start >= entry->expected_length()) {
      start -= entry->expected_length();
      end -= entry->expected_length();
      continue;
    }

    size_t adjusted_end = std::min(end, entry->expected_length());

    Maybe<BackingStoreView::List> slice = entry->Slice(start, adjusted_end);
    if (slice.IsNothing())
      return BaseObjectPtr<Blob2>();

    slices.emplace_back(std::make_shared<BlobItem>(env, slice.FromJust()));

    start = 0;
    end -= adjusted_end;

    if (end == 0)
      break;
  }

  return Create(env, slices, total);
}

Blob2::Blob2(
    Environment* env,
    v8::Local<v8::Object> obj,
    const BlobItem::List& store,
    size_t length)
    : BaseObject(env, obj),
      store_(store),
      length_(length) {
  MakeWeak();
}

BaseObjectPtr<BaseObject>
Blob2::BlobTransferData::Deserialize(
    Environment* env,
    Local<Context> context,
    std::unique_ptr<worker::TransferData> self) {
  if (context != env->context()) {
    THROW_ERR_MESSAGE_TARGET_CONTEXT_UNAVAILABLE(env);
    return {};
  }
  return Blob2::Create(env, store_, length_);
}

BaseObject::TransferMode Blob2::GetTransferMode() const {
  return BaseObject::TransferMode::kCloneable;
}

std::unique_ptr<worker::TransferData> Blob2::CloneForMessaging() const {
  return std::make_unique<BlobTransferData>(store_, length_);
}

void Blob2::RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(Blob2::New);
  registry->Register(Blob2::ToSlice);
}

void BlobReader::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  registry->Register(BlobReader::New);
  registry->Register(BlobReader::StartReading);
}

void BlobReader::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> tmpl = env->NewFunctionTemplate(New);
  tmpl->InstanceTemplate()->SetInternalFieldCount(
      AsyncWrap::kInternalFieldCount);
  tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
  env->SetProtoMethod(tmpl, "startReading", StartReading);
  env->SetConstructorFunction(target, "BlobReader", tmpl);
}

void BlobReader::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  CHECK(Blob2::HasInstance(env, args[0]));

  Blob2* blob;
  ASSIGN_OR_RETURN_UNWRAP(&blob, args[0]);

  new BlobReader(env, args.This(), blob);
}

void BlobReader::MemoryInfo(MemoryTracker* tracker) const {
  // tracker->TrackField("blob", blob_);
  // tracker->TrackField("views", views_);
}

void BlobReader::StartReading(const FunctionCallbackInfo<Value>& args) {
  BlobReader* reader;
  ASSIGN_OR_RETURN_UNWRAP(&reader, args.Holder());
  args.GetReturnValue().Set(reader->Start());
}

BlobReader::BlobReader(Environment* env, Local<Object> obj, Blob2* blob)
    : AsyncWrap(env, obj, AsyncWrap::PROVIDER_FIXEDSIZEBLOBCOPY),
      blob_(blob) {
  MakeWeak();
  uv_async_init(env->event_loop(), &done_signal_, OnDone);
  uv_async_init(env->event_loop(), &read_signal_, OnRead);
  uv_unref(reinterpret_cast<uv_handle_t*>(&done_signal_));
  uv_unref(reinterpret_cast<uv_handle_t*>(&read_signal_));
}

void BlobReader::PullNext() {
  current_item_reader_->Pull(
      [&](int status,
          const std::shared_ptr<BackingStoreView>* views,
          size_t count,
          bob::Done done) {
        for (size_t n = 0; n < count; n++)
          views_.emplace_back(std::move(views[n]));
        if (status == bob::Status::STATUS_END) {
          current_item_++;
          if (current_item_ == blob_->entries().end()) {
            uv_async_send(&done_signal_);
            done(0);
            return;
          }
          current_item_reader_.reset(
              new BlobItem::Reader(env(), *current_item_));
        }

        uv_async_send(&read_signal_);
        done(0);
      },
      bob::Options::OPTIONS_NONE,
      nullptr, 0);
}

bool BlobReader::Start() {
  if (reading_) return false;

  if (blob_->entries().size() == 0) {
    uv_async_send(&done_signal_);
    return true;
  }

  reading_ = true;
  current_item_ = blob_->entries().begin();
  if (!*current_item_) return false;

  current_item_reader_ =
      std::make_unique<BlobItem::Reader>(env(), *current_item_);

  uv_ref(reinterpret_cast<uv_handle_t*>(&done_signal_));
  uv_ref(reinterpret_cast<uv_handle_t*>(&read_signal_));
  uv_async_send(&read_signal_);
  return true;
}

void BlobReader::OnDone(uv_async_t* handle) {
  BlobReader* reader = ContainerOf(&BlobReader::done_signal_, handle);
  reader->Done();
}

void BlobReader::OnRead(uv_async_t* handle) {
  BlobReader* reader = ContainerOf(&BlobReader::read_signal_, handle);
  reader->PullNext();
}

void BlobReader::Done() {
  reading_ = false;
  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  uv_unref(reinterpret_cast<uv_handle_t*>(&done_signal_));
  uv_unref(reinterpret_cast<uv_handle_t*>(&read_signal_));

  // TODO(@jasnell): Make the copy async again
  size_t total = 0;
  for (const auto& view : views_)
    total += view->View().len;

  std::shared_ptr<BackingStore> result =
      ArrayBuffer::NewBackingStore(env()->isolate(), total);
  char* ptr = static_cast<char*>(result->Data());

  for (const auto& view : views_) {
    uv_buf_t buf = view->View();
    if (buf.len > 0) {
      memcpy(ptr, buf.base, buf.len);
      ptr += buf.len;
    }
  }
  Local<Value> val = ArrayBuffer::New(env()->isolate(), result);

  MakeCallback(env()->ondone_string(), 1, &val);
}

StreamBaseBlobItemLoader::StreamBaseBlobItemLoader(
    Environment* env,
    StreamBase* stream,
    BaseObjectPtr<BaseObject> strong_ptr)
    : env_(env),
      stream_(stream),
      strong_ptr_(strong_ptr) {
  stream->PushStreamListener(this);
  uv_async_init(env->event_loop(), &data_signal_, OnData);
  uv_unref(reinterpret_cast<uv_handle_t*>(&data_signal_));
}

StreamBaseBlobItemLoader::~StreamBaseBlobItemLoader() {
  stream_->RemoveStreamListener(this);
}

uv_buf_t StreamBaseBlobItemLoader::OnStreamAlloc(
    size_t suggested_size) {
  return AllocatedBuffer::AllocateManaged(env(), suggested_size).release();
}

void StreamBaseBlobItemLoader::OnStreamRead(
    ssize_t nread,
    const uv_buf_t& buf) {
  AllocatedBuffer buffer(env(), buf);
  stream_->ReadStop();

  if (nread <= 0) {
    if (nread == 0) return;
    if (nread == UV_EOF)
      eos_ = true;
  } else {
    std::shared_ptr<BackingStoreView> view =
        std::make_shared<BackingStoreView>(
            buffer.ReleaseBackingStore());
    items_.emplace_back(std::move(view));
  }
  uv_async_send(&data_signal_);
}

void StreamBaseBlobItemLoader::OnData(uv_async_t* handle) {
  StreamBaseBlobItemLoader* loader =
      ContainerOf(&StreamBaseBlobItemLoader::data_signal_, handle);
  loader->ProcessNext();
}

void StreamBaseBlobItemLoader::ProcessNext() {
  CHECK_NOT_NULL(next_);
  int status = eos_ ? bob::Status::STATUS_END : bob::STATUS_CONTINUE;
  std::move(next_)(status, items_.data(), items_.size(), [](int status) {});
  items_.clear();
  next_ = nullptr;
}

int StreamBaseBlobItemLoader::DoPull(
    bob::Next<std::shared_ptr<BackingStoreView>> next,
    int options,
    std::shared_ptr<BackingStoreView>* data,
    size_t count,
    size_t max_count_hint) {
  if (next_ == nullptr)
    next_ = std::move(next);
  return stream_->ReadStart() == UV_EOF
      ? bob::Status::STATUS_EOS
      : bob::Status::STATUS_WAIT;
}

// --------------


void Blob::Initialize(Environment* env, v8::Local<v8::Object> target) {
  env->SetMethod(target, "createBlob", New);
  FixedSizeBlobCopyJob::Initialize(env, target);
}

Local<FunctionTemplate> Blob::GetConstructorTemplate(Environment* env) {
  Local<FunctionTemplate> tmpl = env->blob_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        BaseObject::kInternalFieldCount);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->SetClassName(
        FIXED_ONE_BYTE_STRING(env->isolate(), "Blob"));
    env->SetProtoMethod(tmpl, "toArrayBuffer", ToArrayBuffer);
    env->SetProtoMethod(tmpl, "slice", ToSlice);
    env->set_blob_constructor_template(tmpl);
  }
  return tmpl;
}

bool Blob::HasInstance(Environment* env, v8::Local<v8::Value> object) {
  return GetConstructorTemplate(env)->HasInstance(object);
}

BaseObjectPtr<Blob> Blob::Create(
    Environment* env,
    const std::vector<BlobEntry> store,
    size_t length) {

  HandleScope scope(env->isolate());

  Local<Function> ctor;
  if (!GetConstructorTemplate(env)->GetFunction(env->context()).ToLocal(&ctor))
    return BaseObjectPtr<Blob>();

  Local<Object> obj;
  if (!ctor->NewInstance(env->context()).ToLocal(&obj))
    return BaseObjectPtr<Blob>();

  return MakeBaseObject<Blob>(env, obj, store, length);
}

void Blob::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args[0]->IsArray());  // sources
  CHECK(args[1]->IsUint32());  // length

  std::vector<BlobEntry> entries;

  size_t length = args[1].As<Uint32>()->Value();
  size_t len = 0;
  Local<Array> ary = args[0].As<Array>();
  for (size_t n = 0; n < ary->Length(); n++) {
    Local<Value> entry;
    if (!ary->Get(env->context(), n).ToLocal(&entry))
      return;
    CHECK(entry->IsArrayBufferView() || Blob::HasInstance(env, entry));
    if (entry->IsArrayBufferView()) {
      Local<ArrayBufferView> view = entry.As<ArrayBufferView>();
      CHECK_EQ(view->ByteOffset(), 0);
      std::shared_ptr<BackingStore> store = view->Buffer()->GetBackingStore();
      size_t byte_length = view->ByteLength();
      view->Buffer()->Detach();  // The Blob will own the backing store now.
      entries.emplace_back(BlobEntry{std::move(store), byte_length, 0});
      len += byte_length;
    } else {
      Blob* blob;
      ASSIGN_OR_RETURN_UNWRAP(&blob, entry);
      auto source = blob->entries();
      entries.insert(entries.end(), source.begin(), source.end());
      len += blob->length();
    }
  }
  CHECK_EQ(length, len);

  BaseObjectPtr<Blob> blob = Create(env, entries, length);
  if (blob)
    args.GetReturnValue().Set(blob->object());
}

void Blob::ToArrayBuffer(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Blob* blob;
  ASSIGN_OR_RETURN_UNWRAP(&blob, args.Holder());
  Local<Value> ret;
  if (blob->GetArrayBuffer(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Blob::ToSlice(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Blob* blob;
  ASSIGN_OR_RETURN_UNWRAP(&blob, args.Holder());
  CHECK(args[0]->IsUint32());
  CHECK(args[1]->IsUint32());
  size_t start = args[0].As<Uint32>()->Value();
  size_t end = args[1].As<Uint32>()->Value();
  BaseObjectPtr<Blob> slice = blob->Slice(env, start, end);
  if (slice)
    args.GetReturnValue().Set(slice->object());
}

void Blob::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("store", length_);
}

MaybeLocal<Value> Blob::GetArrayBuffer(Environment* env) {
  EscapableHandleScope scope(env->isolate());
  size_t len = length();
  std::shared_ptr<BackingStore> store =
      ArrayBuffer::NewBackingStore(env->isolate(), len);
  if (len > 0) {
    unsigned char* dest = static_cast<unsigned char*>(store->Data());
    size_t total = 0;
    for (const auto& entry : entries()) {
      unsigned char* src = static_cast<unsigned char*>(entry.store->Data());
      src += entry.offset;
      memcpy(dest, src, entry.length);
      dest += entry.length;
      total += entry.length;
      CHECK_LE(total, len);
    }
  }

  return scope.Escape(ArrayBuffer::New(env->isolate(), store));
}

BaseObjectPtr<Blob> Blob::Slice(Environment* env, size_t start, size_t end) {
  CHECK_LE(start, length());
  CHECK_LE(end, length());
  CHECK_LE(start, end);

  std::vector<BlobEntry> slices;
  size_t total = end - start;
  size_t remaining = total;

  if (total == 0) return Create(env, slices, 0);

  for (const auto& entry : entries()) {
    if (start + entry.offset > entry.store->ByteLength()) {
      start -= entry.length;
      continue;
    }

    size_t offset = entry.offset + start;
    size_t len = std::min(remaining, entry.store->ByteLength() - offset);
    slices.emplace_back(BlobEntry{entry.store, len, offset});

    remaining -= len;
    start = 0;

    if (remaining == 0)
      break;
  }

  return Create(env, slices, total);
}

Blob::Blob(
    Environment* env,
    v8::Local<v8::Object> obj,
    const std::vector<BlobEntry>& store,
    size_t length)
    : BaseObject(env, obj),
      store_(store),
      length_(length) {
  MakeWeak();
}

BaseObjectPtr<BaseObject>
Blob::BlobTransferData::Deserialize(
    Environment* env,
    Local<Context> context,
    std::unique_ptr<worker::TransferData> self) {
  if (context != env->context()) {
    THROW_ERR_MESSAGE_TARGET_CONTEXT_UNAVAILABLE(env);
    return {};
  }
  return Blob::Create(env, store_, length_);
}

BaseObject::TransferMode Blob::GetTransferMode() const {
  return BaseObject::TransferMode::kCloneable;
}

std::unique_ptr<worker::TransferData> Blob::CloneForMessaging() const {
  return std::make_unique<BlobTransferData>(store_, length_);
}

FixedSizeBlobCopyJob::FixedSizeBlobCopyJob(
    Environment* env,
    Local<Object> object,
    Blob* blob,
    FixedSizeBlobCopyJob::Mode mode)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_FIXEDSIZEBLOBCOPY),
      ThreadPoolWork(env),
      mode_(mode) {
  if (mode == FixedSizeBlobCopyJob::Mode::SYNC) MakeWeak();
  source_ = blob->entries();
  length_ = blob->length();
}

void FixedSizeBlobCopyJob::AfterThreadPoolWork(int status) {
  Environment* env = AsyncWrap::env();
  CHECK_EQ(mode_, Mode::ASYNC);
  CHECK(status == 0 || status == UV_ECANCELED);
  std::unique_ptr<FixedSizeBlobCopyJob> ptr(this);
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());
  Local<Value> args[2];

  if (status == UV_ECANCELED) {
    args[0] = Number::New(env->isolate(), status),
    args[1] = Undefined(env->isolate());
  } else {
    args[0] = Undefined(env->isolate());
    args[1] = ArrayBuffer::New(env->isolate(), destination_);
  }

  ptr->MakeCallback(env->ondone_string(), arraysize(args), args);
}

void FixedSizeBlobCopyJob::DoThreadPoolWork() {
  Environment* env = AsyncWrap::env();
  destination_ = ArrayBuffer::NewBackingStore(env->isolate(), length_);
  unsigned char* dest = static_cast<unsigned char*>(destination_->Data());
  if (length_ > 0) {
    size_t total = 0;
    for (const auto& entry : source_) {
      unsigned char* src = static_cast<unsigned char*>(entry.store->Data());
      src += entry.offset;
      memcpy(dest, src, entry.length);
      dest += entry.length;
      total += entry.length;
      CHECK_LE(total, length_);
    }
  }
}

void FixedSizeBlobCopyJob::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("source", length_);
  tracker->TrackFieldWithSize(
      "destination",
      destination_ ? destination_->ByteLength() : 0);
}

void FixedSizeBlobCopyJob::Initialize(Environment* env, Local<Object> target) {
  v8::Local<v8::FunctionTemplate> job = env->NewFunctionTemplate(New);
  job->Inherit(AsyncWrap::GetConstructorTemplate(env));
  job->InstanceTemplate()->SetInternalFieldCount(
      AsyncWrap::kInternalFieldCount);
  env->SetProtoMethod(job, "run", Run);
  env->SetConstructorFunction(target, "FixedSizeBlobCopyJob", job);
}

void FixedSizeBlobCopyJob::New(const FunctionCallbackInfo<Value>& args) {
  static constexpr size_t kMaxSyncLength = 4096;
  static constexpr size_t kMaxEntryCount = 4;

  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  CHECK(args[0]->IsObject());
  CHECK(Blob::HasInstance(env, args[0]));

  Blob* blob;
  ASSIGN_OR_RETURN_UNWRAP(&blob, args[0]);

  // This is a fairly arbitrary heuristic. We want to avoid deferring to
  // the threadpool if the amount of data being copied is small and there
  // aren't that many entries to copy.
  FixedSizeBlobCopyJob::Mode mode =
      (blob->length() < kMaxSyncLength &&
       blob->entries().size() < kMaxEntryCount) ?
          FixedSizeBlobCopyJob::Mode::SYNC :
          FixedSizeBlobCopyJob::Mode::ASYNC;

  new FixedSizeBlobCopyJob(env, args.This(), blob, mode);
}

void FixedSizeBlobCopyJob::Run(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  FixedSizeBlobCopyJob* job;
  ASSIGN_OR_RETURN_UNWRAP(&job, args.Holder());
  if (job->mode() == FixedSizeBlobCopyJob::Mode::ASYNC)
    return job->ScheduleWork();

  job->DoThreadPoolWork();
  args.GetReturnValue().Set(
      ArrayBuffer::New(env->isolate(), job->destination_));
}

void FixedSizeBlobCopyJob::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  registry->Register(New);
  registry->Register(Run);
}

void Blob::RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(Blob::New);
  registry->Register(Blob::ToArrayBuffer);
  registry->Register(Blob::ToSlice);
}

}  // namespace node
