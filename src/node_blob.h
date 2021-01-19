#ifndef SRC_NODE_BLOB_H_
#define SRC_NODE_BLOB_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "memory_tracker.h"
#include "node_bob.h"
#include "node_internals.h"
#include "node_worker.h"
#include "v8.h"

#include <vector>

namespace node {

// BackingStoreEntry wraps a single shared v8::BackingStore
// with additional offset and length tracking.
class BackingStoreView {
 public:
  using List = std::vector<std::shared_ptr<BackingStoreView>>;

  // The offset cannot be greater than store->ByteLength().
  // The length cannot be greater than store->ByteLength() - offset.
  // The default offset is 0.
  BackingStoreView(
     std::shared_ptr<v8::BackingStore> store,
     size_t length,
     size_t offset = 0);

  // A simplified constructor that defaults the length to store->ByteLength()
  // and offset to 0.
  explicit BackingStoreView(std::shared_ptr<v8::BackingStore> store);

  // A simplified constructor that creates an empty view
  BackingStoreView();

  BackingStoreView(const BackingStoreView& other);
  BackingStoreView& operator=(const BackingStoreView& other);

  BackingStoreView(BackingStoreView&& other);
  BackingStoreView& operator=(BackingStoreView&& other);

  size_t length() const { return length_; }

  size_t offset() const { return offset_; }

  const std::shared_ptr<v8::BackingStore>& store() const { return store_; }

  // Returns the view of the store adjusted for offset and length.
  const uv_buf_t View() const;

  // Creates a new BackingStoreEntry that points to a subset of this
  // BackingStoreEntry. The start and end are calculated from offset
  // (that is, the actual start is offset + start; the actual end is
  // offset + end). Neither the actual start nor actual end may exceed
  // store->ByteLength(), and actual start must be <= actual end.
  // The new BackingStoreEntry maintains it's own shared ptr to the
  // backing store but is otherwise independent of the original
  // BackingStoreEntry.
  std::shared_ptr<BackingStoreView> Slice(size_t start, size_t end);

  // Copy this views store into the given store's buffer starting at offset,
  // returning Just(true) on success. If the destination buffer adjusted for
  // offset is not large enough, Nothing<bool>() will be returned.
  v8::Maybe<bool> CopyInto(
      std::shared_ptr<v8::BackingStore> dest,
      size_t offset = 0);

 private:
  std::shared_ptr<v8::BackingStore> store_;
  size_t length_;
  size_t offset_;
};

// A BlobItem is a collection of realized or future
// BackingStoreView items. A fully realized BlobItem
// has all of it's BackingStoreView items and no
// BlobItemLoader. A BlobItemLoader is a Bob source
// from which the BlobItem pulls new BackingStoreView
// items as needed until the loader signals that it is
// done. Any single BlobItem may have zero or more readers
// associated. Every reader is a Bob Source.
class BlobItem {
 public:
  using Loader = std::unique_ptr<bob::Source<BackingStoreView>>;

  // Creates a fully realized BlobItem from the given set of BackingStoreView
  // items. The expected_length_ and realized_length_ will be calculated and
  // is_loading() will be false.
  explicit BlobItem(const BackingStoreView::List& items);

  // Creates a BlobItem for which no data is yet loaded. is_loading() will
  // be true, expected_length is given, and realized_length will initially
  // be zero.
  BlobItem(Loader loader, size_t expected_length = 0);

  bool is_loading() const { return bool(loader_); }

  // The expected length is the expected total size of the BlobItem.
  // This may not be initially accurate and will be adjusted upward
  // to match realized_length if realized_length >= the initial
  // expected_length.
  size_t expected_length() const { return expected_length_; }

  // The realized length is the total amount of data actually store
  // in the realized_ BackingStoreView::List. It provides the upper
  // bound on what data is available to Readers at a given point in
  // time. While is_loading() is true, this value may grow. Once
  // is_loading() is false, this value will be constant.
  size_t realized_length() const { return realized_length_; }

  class Reader : public bob::SourceImpl<BackingStoreView> {
    public:
     explicit Reader(std::shared_ptr<BlobItem> item);

    protected:
      enum class NotifyFlag {
        kNone,
        kDone
      };

      // Signal the Reader that data is now available in the
      // BlobItem covering the given range from start to end.
      // If the data satisfies the Readers current wait, or if
      // the Reader does not want to continue waiting for data,
      // Notify must return false. If the Reader wants to still
      // wait for data, it must return true, and the BlobItem
      // will continue to notify the Reader as data is available.
      // If flag == NotifyFlag::kDone, the BlobItem is explicitly
      // signaling the Reader that there will be no more data read,
      // and therefore there will be no more notifications. After
      // this point, item_->is_loading() will be false and the
      // BlobItem will release any references it has to the Reader.
      bool Notify(
          size_t start,
          size_t end,
          NotifyFlag flag = NotifyFlag::kNone);

      // Consumers of Reader call the Pull() method on the
      // bob::Source interface to retrieve data. The Reader
      // will determine the appropriate range of data to
      // pull. If the Readers determined range is available,
      // the next() callback will be invoked immediately with
      // the data. Otherwise, the Reader will cache the next
      // callback and invoke it once Notify() signals that
      // the acceptable range has been realized. A Pull
      // will be rejected if the Reader has already completely
      // read the BlobItem or there is already a pending read
      // operation.
      int DoPull(
          bob::Next<BackingStoreView> next,
          int options,
          BackingStoreView* data,
          size_t count,
          size_t max_count_hint) override;

    private:
     std::shared_ptr<BlobItem> item_;
     bob::Next<BackingStoreView> next_;

     // The waiting_for_start_ and waiting_for_end_ specify the
     // range of Data in item_ the Reader is waiting for.
     size_t waiting_for_start_ = 0;
     size_t waiting_for_end_ = 0;

     // The max_offset_ is the total amount of data that has been
     // read from the item. If max_offset_ equals the items
     // realized_length() and the item is no longer loading, then
     // the Reader has read all of the data that is available.
     size_t max_offset_ = 0;
  };

  // When a Reader determines that a loading BlobItem does not yet
  // have enough data to complete it's current read operation, the
  // Reader will add itself to the set of waiting_readers_. As data
  // becomes available, the BlobItem will notify the waiting readers
  // so they can check whether these are the droids we're searching for.
  // Calling WaitForData will return Nothing<bool> if is_loading() is
  // false since there will be no more data expected and there's no sense
  // in trying to wait for more. If the BlobItem is not actively loading
  // the data, it will begin doing so as soon as a Reader is attached.
  // The offset_hint and length_hint provide information about what
  // pending data the Reader is waiting for. The BlobItem may perform
  // only a partial load of the data if the pending readers are not asking
  // for the complete data. If the given offset_hint and length_hint specify
  // a range that is already in the realized_ buffer while the BlobItem is
  // still loading, Just(false) be will returned indicating that the reader
  // has not been added to the waiting_readers_ list.
  v8::Maybe<bool> WaitForData(
      Reader* reader,
      size_t start_hint,
      size_t end_hint);

  // Removes the Reader from the waiting readers list if it is there.
  // If the Reader is not present in the list, this is a non-op.
  void StopWaitingForData(Reader* reader);

  // Returns a subset of the realized_ store covering the specified
  // range. If the given range cannot be satisified because the data
  // is not yet available, v8::Nothing will be returned. In that case,
  // the Reader will need to call WaitForData to wait for enough data
  // to be loaded to satify the request.
  v8::Maybe<BackingStoreView::List> Slice(size_t start, size_t end);

 private:
  // If still loading, triggers asking the loader for more data.
  void ReadMore();

  Loader loader_;
  BackingStoreView::List realized_;
  std::vector<Reader*> waiting_readers_;
  size_t expected_length_;
  size_t realized_length_ = 0;

  // The current minimum and maximum waiting reader offsets
  // These specify the lower and upper bound of data that the
  // currently active set of Readers are waiting on.
  size_t min_waiting_reader_offset_ = 0;
  size_t max_waiting_reader_offset_ = 0;
};

struct BlobEntry {
  std::shared_ptr<v8::BackingStore> store;
  size_t length;
  size_t offset;
};

class Blob : public BaseObject {
 public:
  static void RegisterExternalReferences(
      ExternalReferenceRegistry* registry);
  static void Initialize(Environment* env, v8::Local<v8::Object> target);

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ToArrayBuffer(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ToSlice(const v8::FunctionCallbackInfo<v8::Value>& args);

  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);

  static BaseObjectPtr<Blob> Create(
      Environment* env,
      const std::vector<BlobEntry> store,
      size_t length);

  static bool HasInstance(Environment* env, v8::Local<v8::Value> object);

  const std::vector<BlobEntry> entries() const {
    return store_;
  }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(Blob);
  SET_SELF_SIZE(Blob);

  // Copies the contents of the Blob into an ArrayBuffer.
  v8::MaybeLocal<v8::Value> GetArrayBuffer(Environment* env);

  BaseObjectPtr<Blob> Slice(Environment* env, size_t start, size_t end);

  inline size_t length() const { return length_; }

  class BlobTransferData : public worker::TransferData {
   public:
    explicit BlobTransferData(
        const std::vector<BlobEntry>& store,
      size_t length)
        : store_(store),
          length_(length) {}

    BaseObjectPtr<BaseObject> Deserialize(
        Environment* env,
        v8::Local<v8::Context> context,
        std::unique_ptr<worker::TransferData> self) override;

    SET_MEMORY_INFO_NAME(BlobTransferData)
    SET_SELF_SIZE(BlobTransferData)
    SET_NO_MEMORY_INFO()

   private:
    std::vector<BlobEntry> store_;
    size_t length_ = 0;
  };

  BaseObject::TransferMode GetTransferMode() const override;
  std::unique_ptr<worker::TransferData> CloneForMessaging() const override;

  Blob(
      Environment* env,
      v8::Local<v8::Object> obj,
      const std::vector<BlobEntry>& store,
      size_t length);

 private:
  std::vector<BlobEntry> store_;
  size_t length_ = 0;
};

class FixedSizeBlobCopyJob : public AsyncWrap, public ThreadPoolWork {
 public:
  enum class Mode {
    SYNC,
    ASYNC
  };

  static void RegisterExternalReferences(
      ExternalReferenceRegistry* registry);
  static void Initialize(Environment* env, v8::Local<v8::Object> target);
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Run(const v8::FunctionCallbackInfo<v8::Value>& args);

  bool IsNotIndicativeOfMemoryLeakAtExit() const override {
    return true;
  }

  void DoThreadPoolWork() override;
  void AfterThreadPoolWork(int status) override;

  Mode mode() const { return mode_; }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(FixedSizeBlobCopyJob)
  SET_SELF_SIZE(FixedSizeBlobCopyJob)

 private:
  FixedSizeBlobCopyJob(
    Environment* env,
    v8::Local<v8::Object> object,
    Blob* blob,
    Mode mode = Mode::ASYNC);

  Mode mode_;
  std::vector<BlobEntry> source_;
  std::shared_ptr<v8::BackingStore> destination_;
  size_t length_ = 0;
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_NODE_BLOB_H_
