#include "queue.h"
#include <async_wrap-inl.h>
#include <base_object-inl.h>
#include <env-inl.h>
#include <memory_tracker-inl.h>
#include <node.h>
#include <node_bob-inl.h>
#include <node_errors.h>
#include <node_file-inl.h>
#include <stream_base-inl.h>
#include <v8.h>
#include <util-inl.h>
#include <uv.h>
#include <algorithm>
#include <deque>
#include <initializer_list>
#include <memory>
#include <vector>
#include "base_object.h"
#include "memory_tracker.h"
#include "node_bob.h"
#include "node_external_reference.h"
#include "util.h"
#include "v8-function-callback.h"

namespace node {

using v8::ArrayBufferView;
using v8::BackingStore;
using v8::Context;
using v8::HandleScope;
using v8::Just;
using v8::Local;
using v8::Object;
using v8::Maybe;
using v8::Nothing;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::FunctionCallbackInfo;
using v8::Value;
using v8::String;
using v8::Global;
using v8::Function;
using v8::Int32;
using v8::Uint32;

namespace {
// ============================================================================
class IdempotentDataQueueReader;
class NonIdempotentDataQueueReader;

class EntryBase : public DataQueue::Entry {
 public:
   virtual std::unique_ptr<DataQueue::Reader> getReader() = 0;
};

class DataQueueImpl final : public DataQueue,
                            public std::enable_shared_from_this<DataQueueImpl> {
 public:
  // Constructor for an imdempotent, fixed sized DataQueue.
  DataQueueImpl(std::vector<std::unique_ptr<Entry>> list, size_t size)
      : entries_(std::move(list)),
        idempotent_(true),
        size_(Just(size)),
        capped_size_(Just<size_t>(0UL)) {}

  // Constructor for a non-idempotent DataQueue. This kind of queue can have
  // entries added to it over time. The size is set to 0 initially. The queue
  // can be capped immediately on creation. Depending on the entries that are
  // added, the size can be cleared if any of the entries are not capable of
  // providing a size.
  DataQueueImpl(Maybe<size_t> cap = Nothing<size_t>())
      : idempotent_(false),
        size_(Just<size_t>(0UL)),
        capped_size_(cap) {}

  // Disallow moving and copying.
  DataQueueImpl(const DataQueueImpl&) = delete;
  DataQueueImpl(DataQueueImpl&&) = delete;
  DataQueueImpl& operator=(const DataQueueImpl&) = delete;
  DataQueueImpl& operator=(DataQueueImpl&&) = delete;

  std::shared_ptr<DataQueue> slice(
      size_t start,
      Maybe<size_t> maybeEnd = Nothing<size_t>()) override {
    // If the data queue is not idempotent, or the size cannot be determined,
    // we cannot reasonably create a slice. Therefore, return nothing.
    if (!idempotent_ || size_.IsNothing()) return nullptr;

    size_t size = size_.FromJust();

    // start cannot be greater than the size.
    start = std::min(start, size);

    size_t end;
    if (maybeEnd.To(&end)) {
      // end cannot be less than start, or greater than the size.
      end = std::max(start, std::min(end, size));
    } else {
      end = size;
    }

    DCHECK_LE(start, end);

    size_t len = end - start;
    size_t remaining = end - start;
    std::vector<std::unique_ptr<Entry>> slices;

    if (remaining > 0) {
      for (const auto& entry : entries_) {
        size_t entrySize = entry->size().FromJust();
        if (start > entrySize) {
          start -= entrySize;
          continue;
        }

        size_t chunkStart = start;
        size_t len = std::min(remaining, entrySize - chunkStart);
        slices.emplace_back(entry->slice(chunkStart, Just(chunkStart + len)));
        remaining -= len;
        start = 0;

        if (remaining == 0) break;
      }
    }

    return std::make_shared<DataQueueImpl>(std::move(slices), len);
  }

  Maybe<size_t> size() const override { return size_; }

  bool isIdempotent() const override { return idempotent_; }

  bool isCapped() const override { return capped_size_.IsJust(); }

  Maybe<bool> append(std::unique_ptr<Entry> entry) override {
    if (idempotent_) return Nothing<bool>();
    if (!entry) return Just(false);

    // If this entry successfully provides a size, we can add it to our size_
    // if that has a value, otherwise, we keep size_t empty.
    size_t entrySize;
    size_t queueSize;
    if (entry->size().To(&entrySize) && size_.To(&queueSize)) {
      // If capped_size_ is set, size + entrySize cannot exceed capped_size_
      // or the entry cannot be added.
      size_t capped_size;
      if (capped_size_.To(&capped_size) && queueSize + entrySize > capped_size) {
        return Just(false);
      }

      size_ = Just(queueSize + entrySize);
    } else {
      // This entry cannot provide a size. We can still add it but we have to
      // clear the known size.
      size_ = Nothing<size_t>();
    }

    entries_.push_back(std::move(entry));
    return Just(true);
  }

  void cap(size_t limit = 0) override {
    if (isIdempotent()) return;
    size_t current_cap;
    // If the data queue is already capped, it is possible to call
    // cap again with a smaller size.
    if (capped_size_.To(&current_cap)) {
      capped_size_ = Just(std::min(limit, current_cap));
      return;
    }

    // Otherwise just set the limit.
    capped_size_ = Just(limit);
  }

  Maybe<size_t> maybeCapRemaining() const override {
    size_t capped_size;
    size_t size;
    if (capped_size_.To(&capped_size) && size_.To(&size)) {
      return capped_size > size ? Just(capped_size - size) : Just<size_t>(0UL);
    }
    return Nothing<size_t>();
  }

  void MemoryInfo(node::MemoryTracker* tracker) const override {
    tracker->TrackField("entries", entries_);
  }

  std::unique_ptr<Reader> getReader() override;
  SET_MEMORY_INFO_NAME(DataQueue);
  SET_SELF_SIZE(DataQueueImpl);

 private:
  std::vector<std::unique_ptr<Entry>> entries_;
  bool idempotent_;
  Maybe<size_t> size_;
  Maybe<size_t> capped_size_;
  bool lockedToReader_ = false;

  friend class DataQueue;
  friend class IdempotentDataQueueReader;
  friend class NonIdempotentDataQueueReader;
};

// An IdempotentDataQueueReader always reads the entire content of the
// DataQueue with which it is associated, and always from the beginning.
// Reads are non-destructive, meaning that the state of the DataQueue
// will not and cannot be changed.
class IdempotentDataQueueReader final : public DataQueue::Reader {
 public:
  IdempotentDataQueueReader(std::shared_ptr<DataQueueImpl> data_queue)
      : data_queue_(std::move(data_queue)) {
    CHECK(data_queue_->isIdempotent());
  }

  // Disallow moving and copying.
  IdempotentDataQueueReader(const IdempotentDataQueueReader&) = delete;
  IdempotentDataQueueReader(IdempotentDataQueueReader&&) = delete;
  IdempotentDataQueueReader& operator=(const IdempotentDataQueueReader&) = delete;
  IdempotentDataQueueReader& operator=(IdempotentDataQueueReader&&) = delete;

  int Pull(
      Next next,
      int options,
      DataQueue::Vec* data,
      size_t count,
      size_t max_count_hint = bob::kMaxCountHint) override {
    // If ended is true, this reader has already reached the end and cannot
    // provide any more data.
    if (ended_) {
      std::move(next)(bob::Status::STATUS_EOS, nullptr, 0, [](size_t) {});
      return bob::Status::STATUS_EOS;
    }

    // If this is the first pull from this reader, we are first going to
    // check to see if there is anything at all to actually do.
    if (current_index_.IsNothing()) {
      // First, let's check the number of entries. If there are no entries,
      // we've reached the end and have nothing to do.
      bool empty = data_queue_->entries_.empty();

      // Second, if there are entries, let's check the known size to see if
      // it is zero or not.
      if (!empty) {
        size_t size;
        if (data_queue_->size().To(&size)) {
          // If the size is known to be zero, there's absolutely nothing else for
          // us to do but end.
          empty = (size == 0);
        }
        // If the size cannot be determined, we will have to try reading from
        // the entry to see if it has any data or not, so fall through here.
      }

      if (empty) {
        std::move(next)(bob::Status::STATUS_END, nullptr, 0, [](size_t) {});
        ended_ = true;
        return bob::Status::STATUS_END;
      }

      current_index_ = Just(0U);
    }

    // We have current_index_, awesome, we are going to keep reading from
    // it until we receive and end.
    CHECK(!pull_pending_);
    pull_pending_ = true;
    int status = getCurrentReader().Pull(
        [this, next = std::move(next)]
        (int status, const DataQueue::Vec* vecs, size_t count, Done done) {
      pull_pending_ = false;
      last_status_ = status;

      // In each of these cases, we do not expect that the source will
      // actually have provided any actual data.
      CHECK_IMPLIES(status == bob::Status::STATUS_BLOCK ||
                    status == bob::Status::STATUS_WAIT ||
                    status == bob::Status::STATUS_EOS,
                    vecs == nullptr && count == 0);

      // Technically, receiving a STATUS_EOS is really an error because
      // we've read past the end of the data, but we are going to treat
      // it the same as end.
      if (status == bob::Status::STATUS_END ||
          status == bob::Status::STATUS_EOS) {
        uint32_t current = current_index_.FromJust() + 1;
        // We have reached the end of this entry. If this is the last entry,
        // then we are done. Otherwise, we advance the current_index_, clear
        // the current_reader_ and wait for the next read.
        if (current == data_queue_->entries_.size()) {
          // Yes, this was the final entry. We're all done.
          ended_ = true;
          status = bob::Status::STATUS_END;
        } else {
          // This was not the final entry, so we update the index and
          // continue on.
          current_index_ = Just(current);
          status = bob::Status::STATUS_CONTINUE;
        }
        current_reader_ = nullptr;
      }

      // Now that we have updated this readers state, we can forward
      // everything on to the outer next.
      std::move(next)(status, vecs, count, std::move(done));
    }, options, data, count, max_count_hint);

    if (!pull_pending_) {
      // The callback was resolved synchronously. Let's check our status.

      // Just as a double check, when next is called synchronous, the status
      // provided there should match the status returned.
      CHECK(status == last_status_);

      if (ended_) {
        // Awesome, we read everything. Return status end here and we're done.
        return bob::Status::STATUS_END;
      }

      if (status == bob::Status::STATUS_END ||
          status == bob::Status::STATUS_EOS) {
        // If we got here and ended_ is not true, there's more to read.
        return bob::Status::STATUS_CONTINUE;
      }

      // For all other status, we just fall through and return it straightaway.
    }

    // The other statuses that can be returned by the pull are:
    //  bob::Status::STATUS_CONTINUE - means that the entry has more data
    //                                 to pull.
    //  bob::Status::STATUS_BLOCK - means that the entry has more data to
    //                              pull but it is not available yet. The
    //                              caller should not keep calling pull for
    //                              now but may check again later.
    //  bob::Status::STATUS_WAIT - means that the entry has more data to
    //                             pull but it won't be provided
    //                             synchronously, instead the next() callback
    //                             will be called when the data is available.
    //
    // For any of these statuses, we want to keep the current index and
    // current_reader_ set for the next pull.

    return status;
  }

  DataQueue::Reader& getCurrentReader() {
    CHECK(!ended_);
    CHECK(current_index_.IsJust());
    if (current_reader_ == nullptr) {
      auto& entry = data_queue_->entries_[current_index_.FromJust()];
      // Because this is an idempotent reader, let's just be sure to
      // doublecheck that the entry itself is actually idempotent
      DCHECK(entry->isIdempotent());
      current_reader_ = static_cast<EntryBase&>(*entry).getReader();
    }
    CHECK_NOT_NULL(current_reader_);
    return *current_reader_;
  }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(IdempotentDataQueueReader);
  SET_SELF_SIZE(IdempotentDataQueueReader);

 private:
  std::shared_ptr<DataQueueImpl> data_queue_;
  Maybe<uint32_t> current_index_ = Nothing<uint32_t>();
  std::unique_ptr<DataQueue::Reader> current_reader_ = nullptr;
  bool ended_ = false;
  bool pull_pending_ = false;
  int last_status_ = 0;
};

// A NonIdempotentDataQueueReader reads entries from the DataEnqueue
// and removes those entries from the queue as they are fully consumed.
// This means that reads are destructive and the state of the DataQueue
// is mutated as the read proceeds.
class NonIdempotentDataQueueReader final : public DataQueue::Reader {
 public:
  NonIdempotentDataQueueReader(std::shared_ptr<DataQueueImpl> data_queue)
      : data_queue_(std::move(data_queue)) {
    CHECK(!data_queue_->isIdempotent());
  }

  // Disallow moving and copying.
  NonIdempotentDataQueueReader(const NonIdempotentDataQueueReader&) = delete;
  NonIdempotentDataQueueReader(NonIdempotentDataQueueReader&&) = delete;
  NonIdempotentDataQueueReader& operator=(const NonIdempotentDataQueueReader&) = delete;
  NonIdempotentDataQueueReader& operator=(NonIdempotentDataQueueReader&&) = delete;

  int Pull(
      Next next,
      int options,
      DataQueue::Vec* data,
      size_t count,
      size_t max_count_hint = bob::kMaxCountHint) override {
    // If ended is true, this reader has already reached the end and cannot
    // provide any more data.
    if (ended_) {
      std::move(next)(bob::Status::STATUS_EOS, nullptr, 0, [](size_t) {});
      return bob::Status::STATUS_EOS;
    }

    // If the collection of entries is empty, there's nothing currently left to
    // read. How we respond depends on whether the data queue has been capped
    // or not.
    if (data_queue_->entries_.empty()) {
      // If the data_queue_ is empty, and not capped, then we can reasonably
      // expect more data to be provided later, but we don't know exactly when
      // that'll happe, so the proper response here is to return a blocked
      // status.
      if (!data_queue_->isCapped()) {
        std::move(next)(bob::Status::STATUS_BLOCK, nullptr, 0, [](size_t) {});
        return bob::STATUS_BLOCK;
      }

      // However, if we are capped, the status will depend on whether the size
      // of the data_queue_ is known or not.

      size_t size;
      if (data_queue_->size().To(&size)) {
        // If the size is known, and it is still less than the cap, then we still
        // might get more data. We just don't know exactly when that'll come, so
        // let's return a blocked status.
        if (size < data_queue_->capped_size_.FromJust()) {
          std::move(next)(bob::Status::STATUS_BLOCK, nullptr, 0, [](size_t) {});
          return bob::STATUS_BLOCK;
        }

        // Otherwise, if size is equal to or greater than capped, we are done.
        // Fall through to allow the end handling to run.
      }

      // If the size is not known, and the data queue is capped, no additional
      // entries are going to be added to the queue. Since we are all out of
      // entries, we're done. There's nothing left to read.
      current_reader_ = nullptr;
      ended_ = true;
      std::move(next)(bob::Status::STATUS_END, nullptr, 0, [](size_t) {});
      return bob::STATUS_END;
    }

    // If we got here, we have an entry to read from.
    CHECK(!pull_pending_);
    pull_pending_ = true;
    int status = getCurrentReader().Pull(
        [this, next = std::move(next)]
        (int status, const DataQueue::Vec* vecs, size_t count, Done done) {
      pull_pending_ = false;
      last_status_ = status;

      // In each of these cases, we do not expect that the source will
      // actually have provided any actual data.
      CHECK_IMPLIES(status == bob::Status::STATUS_BLOCK ||
                    status == bob::Status::STATUS_WAIT ||
                    status == bob::Status::STATUS_EOS,
                    vecs == nullptr && count == 0);

      // Technically, receiving a STATUS_EOS is really an error because
      // we've read past the end of the data, but we are going to treat
      // it the same as end.
      if (status == bob::Status::STATUS_END ||
          status == bob::Status::STATUS_EOS) {
        data_queue_->entries_.erase(data_queue_->entries_.begin());

        // We have reached the end of this entry. If this is the last entry,
        // then we are done. Otherwise, we advance the current_index_, clear
        // the current_reader_ and wait for the next read.
        if (data_queue_->entries_.empty()) {
          // Yes, this was the final entry. We're all done.
          ended_ = true;
          status = bob::Status::STATUS_END;
        } else {
          // This was not the final entry, so we update the index and
          // continue on.
          status = bob::Status::STATUS_CONTINUE;
        }
        current_reader_ = nullptr;
      }

      // Now that we have updated this readers state, we can forward
      // everything on to the outer next.
      std::move(next)(status, vecs, count, std::move(done));
    }, options, data, count, max_count_hint);

    if (!pull_pending_) {
      // The callback was resolved synchronously. Let's check our status.

      // Just as a double check, when next is called synchronous, the status
      // provided there should match the status returned.
      CHECK(status == last_status_);

      if (ended_) {
        // Awesome, we read everything. Return status end here and we're done.

        // Let's just make sure we've removed all of the entries.
        CHECK(data_queue_->entries_.empty());

        return bob::Status::STATUS_END;
      }

      if (status == bob::Status::STATUS_END ||
          status == bob::Status::STATUS_EOS) {
        // If we got here and ended_ is not true, there's more to read.
        return bob::Status::STATUS_CONTINUE;
      }

      // For all other status, we just fall through and return it straightaway.
    }

    // The other statuses that can be returned by the pull are:
    //  bob::Status::STATUS_CONTINUE - means that the entry has more data
    //                                 to pull.
    //  bob::Status::STATUS_BLOCK - means that the entry has more data to
    //                              pull but it is not available yet. The
    //                              caller should not keep calling pull for
    //                              now but may check again later.
    //  bob::Status::STATUS_WAIT - means that the entry has more data to
    //                             pull but it won't be provided
    //                             synchronously, instead the next() callback
    //                             will be called when the data is available.
    //
    // For any of these statuses, we want to keep the current index and
    // current_reader_ set for the next pull.

    return status;
  }

  DataQueue::Reader& getCurrentReader() {
    CHECK(!ended_);
    CHECK(!data_queue_->entries_.empty());
    if (current_reader_ == nullptr) {
      auto& entry = data_queue_->entries_.front();
      current_reader_ = static_cast<EntryBase&>(*entry).getReader();
    }
    return *current_reader_;
  }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(NonIdempotentDataQueueReader);
  SET_SELF_SIZE(NonIdempotentDataQueueReader);

 private:
  std::shared_ptr<DataQueueImpl> data_queue_;
  std::unique_ptr<DataQueue::Reader> current_reader_ = nullptr;
  bool ended_ = false;
  bool pull_pending_ = false;
  int last_status_ = 0;
};

std::unique_ptr<DataQueue::Reader> DataQueueImpl::getReader() {
  if (isIdempotent()) {
    return std::make_unique<IdempotentDataQueueReader>(shared_from_this());
  }

  if (lockedToReader_) return nullptr;
  lockedToReader_ = true;

  return std::make_unique<NonIdempotentDataQueueReader>(shared_from_this());
}

// ============================================================================

// An empty, always idempotent entry.
class EmptyEntry final : public EntryBase {
 public:
  class EmptyReader final : public DataQueue::Reader {
    public:

    int Pull(
        Next next,
        int options,
        DataQueue::Vec* data,
        size_t count,
        size_t max_count_hint = bob::kMaxCountHint) override {
      if (ended_) {
        std::move(next)(bob::Status::STATUS_EOS, nullptr, 0, [](size_t) {});
        return bob::Status::STATUS_EOS;
      }

      ended_ = true;
      std::move(next)(bob::Status::STATUS_END, nullptr, 0, [](size_t) {});
      return bob::Status::STATUS_END;
    }

    SET_NO_MEMORY_INFO()
    SET_MEMORY_INFO_NAME(EmptyReader);
    SET_SELF_SIZE(EmptyReader);

    private:
    bool ended_ = false;
  };

  EmptyEntry() = default;

  // Disallow moving and copying.
  EmptyEntry(const EmptyEntry&) = delete;
  EmptyEntry(EmptyEntry&&) = delete;
  EmptyEntry& operator=(const EmptyEntry&) = delete;
  EmptyEntry& operator=(EmptyEntry&&) = delete;

  std::unique_ptr<DataQueue::Reader> getReader() override {
    return std::make_unique<EmptyReader>();
  }

  std::unique_ptr<Entry> slice(
      size_t start,
      Maybe<size_t> maybeEnd = Nothing<size_t>()) override {
    if (start != 0) return nullptr;
    size_t end;
    if (maybeEnd.To(&end)) {
      if (end != 0) return nullptr;
    }
    return std::make_unique<EmptyEntry>();
  }

  Maybe<size_t> size() const override { return Just<size_t>(0UL); }

  bool isIdempotent() const override { return true; }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(EmptyEntry);
  SET_SELF_SIZE(EmptyEntry);
};

// ============================================================================

// An entry that consists of a single memory resident v8::BackingStore.
// These are always idempotent and always a fixed, known size.
class InMemoryEntry final : public EntryBase {
 public:
  struct InMemoryFunctor final {
    std::shared_ptr<BackingStore> backing_store;
    void operator()(size_t) {
      backing_store = nullptr;
    };
  };

  class InMemoryReader final : public DataQueue::Reader {
   public:
    InMemoryReader(InMemoryEntry& entry)
        : entry_(entry) {}

    int Pull(
        Next next,
        int options,
        DataQueue::Vec* data,
        size_t count,
        size_t max_count_hint = bob::kMaxCountHint) override {
      if (ended_) {
        std::move(next)(bob::Status::STATUS_EOS, nullptr, 0, [](size_t) {});
        return bob::Status::STATUS_EOS;
      }

      ended_ = true;
      DataQueue::Vec vec {
        reinterpret_cast<uint8_t*>(entry_.backing_store_->Data()) + entry_.offset_,
        entry_.byte_length_,
      };
      std::move(next)(bob::Status::STATUS_END, &vec, 1, InMemoryFunctor({
        entry_.backing_store_
      }));
      return bob::Status::STATUS_END;
    }

    SET_NO_MEMORY_INFO()
    SET_MEMORY_INFO_NAME(InMemoryReader);
    SET_SELF_SIZE(InMemoryReader);

   private:
    InMemoryEntry& entry_;
    bool ended_ = false;
  };

  InMemoryEntry(std::shared_ptr<BackingStore> backing_store,
                size_t offset,
                size_t byte_length)
      : backing_store_(std::move(backing_store)),
        offset_(offset),
        byte_length_(byte_length) {
    // The offset_ + byte_length_ cannot extend beyond the size of the
    // backing store, because that would just be silly.
    CHECK_LE(offset_ + byte_length_, backing_store_->ByteLength());
  }

  // Disallow moving and copying.
  InMemoryEntry(const InMemoryEntry&) = delete;
  InMemoryEntry(InMemoryEntry&&) = delete;
  InMemoryEntry& operator=(const InMemoryEntry&) = delete;
  InMemoryEntry& operator=(InMemoryEntry&&) = delete;

  std::unique_ptr<DataQueue::Reader> getReader() override {
    return std::make_unique<InMemoryReader>(*this);
  }

  std::unique_ptr<Entry> slice(
      size_t start,
      Maybe<size_t> maybeEnd = Nothing<size_t>()) override {
    const auto makeEntry = [&](size_t start, size_t len) -> std::unique_ptr<Entry> {
      if (len == 0) {
        return std::make_unique<EmptyEntry>();
      }

      return std::make_unique<InMemoryEntry>(backing_store_, start, len);
    };

    start += offset_;

    // The start cannot extend beyond the maximum end point of this entry.
    start = std::min(start, offset_ + byte_length_);

    size_t end;
    if (maybeEnd.To(&end)) {
      // The end cannot extend beyond the maximum end point of this entry,
      // and the end must be equal to or greater than the start.
      end = std::max(start, std::min(offset_ + end, offset_ + byte_length_));

      return makeEntry(start, end - start);
    }

    // If no end is given, then the new length is the current length
    // minus the adjusted start.
    return makeEntry(start, byte_length_ - start);
  }

  Maybe<size_t> size() const override { return Just(byte_length_); }

  bool isIdempotent() const override { return true; }

  void MemoryInfo(node::MemoryTracker* tracker) const override {
    tracker->TrackField("store", backing_store_);
  }
  SET_MEMORY_INFO_NAME(InMemoryEntry);
  SET_SELF_SIZE(InMemoryEntry);

 private:
  std::shared_ptr<BackingStore> backing_store_;
  size_t offset_;
  size_t byte_length_;

  friend class InMemoryReader;
};

// ============================================================================

// An entry that wraps a DataQueue. The entry takes on the characteristics
// of the wrapped dataqueue.
class DataQueueEntry : public EntryBase {
 public:
  DataQueueEntry(std::shared_ptr<DataQueue> data_queue)
      : data_queue_(std::move(data_queue)) {
    CHECK(data_queue_);
  }

  // Disallow moving and copying.
  DataQueueEntry(const DataQueueEntry&) = delete;
  DataQueueEntry(DataQueueEntry&&) = delete;
  DataQueueEntry& operator=(const DataQueueEntry&) = delete;
  DataQueueEntry& operator=(DataQueueEntry&&) = delete;

  std::unique_ptr<DataQueue::Reader> getReader() override {
    return data_queue_->getReader();
  }

  std::unique_ptr<Entry> slice(
      size_t start,
      Maybe<size_t> end = Nothing<size_t>()) override {
    std::shared_ptr<DataQueue> sliced = data_queue_->slice(start, end);
    if (!sliced) return nullptr;

    return std::make_unique<DataQueueEntry>(std::move(sliced));
  }

  // Returns the number of bytes represented by this Entry if it is
  // known. Certain types of entries, such as those backed by streams
  // might not know the size in advance and therefore cannot provide
  // a value. In such cases, size() must return v8::Nothing<size_t>.
  //
  // If the entry is idempotent, a size should always be available.
  Maybe<size_t> size() const override { return data_queue_->size(); }

  // When true, multiple reads on the object must produce the exact
  // same data or the reads will fail. Some sources of entry data,
  // such as streams, may not be capable of preserving idempotency
  // and therefore must not claim to be. If an entry claims to be
  // idempotent and cannot preserve that quality, subsequent reads
  // must fail with an error when a variance is detected.
  bool isIdempotent() const override { return data_queue_->isIdempotent(); }

  void MemoryInfo(node::MemoryTracker* tracker) const override {
    tracker->TrackField("data_queue", data_queue_);
  }

  DataQueue& getDataQueue() { return *data_queue_; }

  SET_MEMORY_INFO_NAME(DataQueueEntry);
  SET_SELF_SIZE(DataQueueEntry);

 private:
  std::shared_ptr<DataQueue> data_queue_;
};

// ============================================================================

// Essentially an entry that exists to give the Javascript side
// control of what happens when data is read. Always non-idempotent.
class StreamEntry final : public EntryBase {
 public:
  StreamEntry(Environment* env,
              Local<Function> pull_callback,
              Local<Object> wrap)
      : env_(env),
        pull_callback_(env->isolate(), pull_callback),
        wrap_(env->isolate(), wrap) {}

  std::unique_ptr<DataQueue::Reader> getReader() override {
    return std::make_unique<Reader>(this);
  }

  std::unique_ptr<Entry> slice(
      size_t start,
      Maybe<size_t> end = Nothing<size_t>()) final {
    // Stream entries cannot be sliced.
    return nullptr;
  }

  Maybe<size_t> size() const override {
    // We cannot know the size in advanced.
    return Nothing<size_t>();
  }

  bool isIdempotent() const override {
    // Always non-idempotent for streams
    return false;
  }

  Environment* env() const { return env_; }

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackField("callback", pull_callback_);
  }

  SET_MEMORY_INFO_NAME(StreamEntry)
  SET_SELF_SIZE(StreamEntry)

  class Wrap final : public BaseObject {
   public:
    static void New(const FunctionCallbackInfo<Value>& args) {
      CHECK(args.IsConstructCall());
      Environment* env = Environment::GetCurrent(args);

      CHECK(args.Length() == 1);

      CHECK(args[0]->IsFunction());

      new Wrap(env, args.This(), args[0]);
    }

    static Local<FunctionTemplate> GetConstructorTemplate(
      Environment* env) {
      Local<FunctionTemplate> tmpl = env->streamentry_ctor_template();
      if (tmpl.IsEmpty()) {
        Isolate* isolate = env->isolate();
        tmpl = NewFunctionTemplate(isolate, New);

        tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "StreamEntry"));
        tmpl->Inherit(BaseObject::GetConstructorTemplate(env));

        env->set_streamentry_ctor_template(tmpl);
      }

      return tmpl;
    }

    static void Initialize(Environment* env, Local<Object> target) {
      SetConstructorFunction(
        env->context(), target, "StreamEntry", GetConstructorTemplate(env));
    }

    static void RegisterExternalReferences(
        ExternalReferenceRegistry* registry) {
      registry->Register(New);
    }

    static BaseObjectPtr<StreamEntry> Create(Environment* env) {
      Local<Object> obj;
      if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context())
          .ToLocal(&obj)) {
        return BaseObjectPtr<StreamEntry>();
      }

      return MakeBaseObject<Wrap>(env, obj);
    }

    Wrap(Environment* env, Local<Object> obj, Local<Function> pull_callback)
        : BaseObject(env, obj),
          inner_(std::make_unique<StreamEntry>(env, pull_callback, obj)) {
      MakeWeak();
    }

    std::unique_ptr<DataQueue::Entry> detach() {
      return std::move(inner_);
    }

    bool isDetached() const { return inner_ == nullptr; }

    void MemoryInfo(MemoryTracker* tracker) const override {
      tracker->TrackField("entry", inner_);
    }

    SET_MEMORY_INFO_NAME(StreamEntry::Wrap)
    SET_SELF_SIZE(StreamEntry::Wrap)

   private:
    std::unique_ptr<StreamEntry> inner_;
  };

 private:
  Environment* env_;
  Global<Function> pull_callback_;
  Global<Object> wrap_;

  class Reader final : public DataQueue::Reader {
    // TODO(@jasnell, @flakey5)
    // * Currently with this, it would be possible to call the pull callbacks
    //   out of order. Should we enforce a sequencing order on the callbacks?
    // * It is also possible to call to callbacks after the reader has ended
    //   or even been freed, which will cause a crash. We shouldn't allow that.
   public:
    Reader(StreamEntry* entry) : entry_(entry) {}

    int Pull(
        bob::Next<DataQueue::Vec> next,
        int options,
        DataQueue::Vec* data,
        size_t count,
        size_t max_count_hint = bob::kMaxCountHint) override {
      if (ended_) {
        return bob::STATUS_EOS;
      }

      Environment* env = entry_->env();
      v8::Isolate* isolate = env->isolate();
      Local<Context> context = isolate->GetCurrentContext();

      HandleScope handleScope(isolate);

      Local<Object> wrap = entry_->wrap_.Get(isolate);
      Local<Function> pull = entry_->pull_callback_.Get(isolate);

      // TODO(@jasnell, @flakey5): Use an appropriate callbackscope here.
      // The StreamEntry::Wrap really ought to be an AsyncWrap here.
      CallbackScope scope(isolate, wrap, {0, 0});

      Local<Function> callback;
      if (!Function::New(context, NextCallback,
              OpaqueWrapper::Create(env, std::move(next))).ToLocal(&callback)) {
        // Creating the callback failed for whatever reason. The error will propagate
        // thank to the callback scope, but let's end the reader and fail this read.
        ended_ = true;
        std::move(next)(bob::STATUS_FAILED, nullptr, 0, [](size_t) {});
        return bob::STATUS_FAILED;
      }

      Local<Value> argv[] = { callback };

      Local<Value> ret;
      if (!pull->Call(isolate->GetCurrentContext(), wrap, arraysize(argv), argv).ToLocal(&ret)) {
        // The call failed for whatever reason. The error will propagate thanks to the
        // callback scope, but let's end the reader and fail this read.
        ended_ = true;
        std::move(next)(bob::STATUS_FAILED, nullptr, 0, [](size_t) {});
        return bob::STATUS_FAILED;
      }

      return bob::STATUS_WAIT;
    }

    SET_NO_MEMORY_INFO()
    SET_MEMORY_INFO_NAME(SteamEntryReader)
    SET_SELF_SIZE(Reader)

   private:
    StreamEntry* entry_;
    bool ended_ = false;

    class OpaqueWrapper final : public BaseObject {
     public:
      static bool HasInstance(Environment* env, Local<Value> value) {
        return GetConstructorTemplate(env)->HasInstance(value);
      }
      static Local<FunctionTemplate> GetConstructorTemplate(
        Environment* env) {
        Local<FunctionTemplate> tmpl = env->streamentry_opaque_ctor_template();
        if (tmpl.IsEmpty()) {
          Isolate* isolate = env->isolate();
          tmpl = FunctionTemplate::New(isolate);
          tmpl->Inherit(BaseObject::GetConstructorTemplate(env));

          env->set_streamentry_opaque_ctor_template(tmpl);
        }

        return tmpl;
      }
      static Local<Object> Create(Environment* env, Next next) {
        Local<Object> obj;
        if (!GetConstructorTemplate(env)
            ->InstanceTemplate()
            ->NewInstance(env->context())
            .ToLocal(&obj)) {
          return Local<Object>();
        }

        return MakeBaseObject<OpaqueWrapper>(env, obj, std::move(next))->object();
      }

      OpaqueWrapper(Environment* env, Local<Object> wrap, Next next)
          : BaseObject(env, wrap), next_(std::move(next)) {
        MakeWeak();
      }

      SET_NO_MEMORY_INFO()
      SET_MEMORY_INFO_NAME(StreamEntry::Reader::OpaqueWrapper)
      SET_SELF_SIZE(OpaqueWrapper)
     private:
      Next next_;
      bool used_ = false;

      friend class Reader;
    };

    static void NextCallback(const FunctionCallbackInfo<Value>& args) {
      Environment* env = Environment::GetCurrent(args);
      CHECK(OpaqueWrapper::HasInstance(env, args.Data()));
      OpaqueWrapper* wrapper;
      ASSIGN_OR_RETURN_UNWRAP(&wrapper, args.Data().As<v8::Object>());

      if (wrapper->used_) {
        return node::THROW_ERR_INVALID_STATE(env, "The pull callback was already called");
      }
      wrapper->used_ = true;

      // The arguments must be an int, for status, and if there is
      // data, an ArrayBufferView.

      CHECK(args[0]->IsInt32());
      int status = args[0]->Int32Value(env->context()).FromJust();

      // Neither the block or wait statuses are valid here.
      CHECK_NE(status, bob::STATUS_BLOCK);
      CHECK_NE(status, bob::STATUS_WAIT);

      CHECK_IMPLIES(status == bob::STATUS_EOS, args[1]->IsUndefined());
      CHECK_IMPLIES(!args[1]->IsUndefined(), args[1]->IsArrayBufferView());

      if (status == bob::STATUS_EOS) {
        std::move(wrapper->next_)(status, nullptr, 0, [](size_t) {});
      } else {
        Local<ArrayBufferView> view = args[1].As<v8::ArrayBufferView>();
        size_t length = view->ByteLength();
        size_t offset = view->ByteOffset();
        std::shared_ptr<BackingStore> store = view->Buffer()->GetBackingStore();
        view->Buffer()->Detach();
        DataQueue::Vec vec = {
          reinterpret_cast<uint8_t*>(store->Data()) + offset,
          length
        };
        std::move(wrapper->next_)(status, &vec, 1, [store=std::move(store)](size_t) {});
      }
    }
  };

  friend class Reader;
};

// ============================================================================

// A StreamBaseEntry is a non-idempotent entry for a DataQueue whose data
// is provided by an underlying StreamBase implementation. Data is never
// buffered and the size is never known in advance.
class StreamBaseEntry final : public EntryBase {
 public:
  explicit StreamBaseEntry(
      Environment* env,
      StreamBase* stream_base,
      BaseObjectPtr<AsyncWrap> strong_ptr)
      : env_(env),
        stream_base_(stream_base),
        strong_ptr_(strong_ptr) {}

  std::unique_ptr<DataQueue::Reader> getReader() override {
    return std::make_unique<Reader>(BaseObjectPtr<StreamBaseEntry>(this));
  }

  std::unique_ptr<Entry> slice(
      size_t start,
      Maybe<size_t> end = Nothing<size_t>()) override {
    // StreamBaseEntry, as a non-idempotent type, does not support slicing.
    return nullptr;
  }

  Maybe<size_t> size() const override {
    // We cannot know the overall size of the entry in advance.
    return Nothing<size_t>();
  }

  bool isIdempotent() const final {
    // Always non-idempotent for streams
    return false;
  }

  Environment* env() const { return env_; }

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackField("stream", strong_ptr_);
  }
  SET_MEMORY_INFO_NAME(StreamBaseEntry)
  SET_SELF_SIZE(StreamBaseEntry)

  class Wrap final : public BaseObject {
   public:
    static void New(const FunctionCallbackInfo<Value>& args) {
      CHECK(args.IsConstructCall());
      Environment* env = Environment::GetCurrent(args);

      CHECK(args.Length() == 1);
      StreamBase* wrap = StreamBase::FromObject(args[0].As<Object>());
      CHECK_NOT_NULL(wrap);
      new Wrap(env, args.This(), wrap,
          BaseObjectPtr<AsyncWrap>(wrap->GetAsyncWrap()));
    }

    static Local<FunctionTemplate> GetConstructorTemplate(
      Environment* env) {
      Local<FunctionTemplate> tmpl = env->streambaseentry_ctor_template();
      if (tmpl.IsEmpty()) {
        Isolate* isolate = env->isolate();
        tmpl = NewFunctionTemplate(isolate, New);

        tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "StreamBaseEntry"));
        tmpl->Inherit(BaseObject::GetConstructorTemplate(env));

        env->set_streambaseentry_ctor_template(tmpl);
      }

      return tmpl;
    }

    static void Initialize(Environment* env, Local<Object> target) {
      SetConstructorFunction(
        env->context(), target, "StreamBaseEntry", GetConstructorTemplate(env));
    }

    static void RegisterExternalReferences(
        ExternalReferenceRegistry* registry) {
      registry->Register(New);
    }

    static BaseObjectPtr<StreamBaseEntry> Create(
        Environment* env,
        StreamBase* stream_base,
        BaseObjectPtr<BaseObject> strong_ptr) {
      Local<Object> obj;
      if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context())
          .ToLocal(&obj)) {
        return BaseObjectPtr<StreamBaseEntry>();
      }

      return MakeBaseObject<Wrap>(env, obj, stream_base, strong_ptr);
    }

    Wrap(Environment* env,
         Local<Object> obj,
         StreamBase* stream_base,
         BaseObjectPtr<BaseObject> strong_ptr)
        : BaseObject(env, obj),
          inner_(std::make_unique<StreamBaseEntry>(env, stream_base, strong_ptr)) {
      MakeWeak();
    }

    std::unique_ptr<DataQueue::Entry> detach() {
      return std::move(inner_);
    }

    bool isDetached() const { return inner_ == nullptr; }

    void MemoryInfo(MemoryTracker* tracker) const override {
      tracker->TrackField("entry", inner_);
    }

    SET_MEMORY_INFO_NAME(StreamBaseEntry::Wrap)
    SET_SELF_SIZE(StreamBaseEntry::Wrap)

   private:
    std::unique_ptr<StreamBaseEntry> inner_;
  };

 private:
  Environment* env_;
  StreamBase* stream_base_;
  BaseObjectPtr<AsyncWrap> strong_ptr_;

  class Reader final : public DataQueue::Reader,
                       public StreamListener {
   public:
    Reader(BaseObjectPtr<StreamBaseEntry> entry) : entry_(entry) {
      entry_->stream_base_->PushStreamListener(this);
    }

    ~Reader() override {
      entry_->stream_base_->RemoveStreamListener(this);
    }

    uv_buf_t OnStreamAlloc(size_t suggested_size) override {
      return entry_->env()->allocate_managed_buffer(suggested_size);
    }

    void OnStreamRead(ssize_t nread, const uv_buf_t& buf_) override {
      CHECK(!ended_);
      Next next = std::move(pending_reads_.front());
      pending_reads_.pop_front();
      if (nread == UV_EOF) {
        std::move(next)(bob::STATUS_EOS, nullptr, 0, [](size_t) {});
        Done();
      } else if (nread < 0) {
        std::move(next)(nread, nullptr, 0, [](size_t) {});
        Done();
      } else {
        std::unique_ptr<BackingStore> bs =
            entry_->env()->release_managed_buffer(buf_);
        DataQueue::Vec vec = {
          reinterpret_cast<uint8_t*>(bs->Data()),
          static_cast<size_t>(nread),
        };
        std::move(next)(bob::STATUS_CONTINUE, &vec, 1,
            [dropped = std::move(bs)](size_t) {});
      }
      if (pending_reads_.empty())
        ReadStop();
    }

    int Pull(
        Next next,
        int options,
        DataQueue::Vec* data,
        size_t count,
        size_t max_count_hint = bob::kMaxCountHint) override {
      if (!entry_->stream_base_->IsAlive() ||
          entry_->stream_base_->IsClosing() ||
          ended_) {
        std::move(next)(bob::STATUS_EOS, nullptr, 0, [](size_t) {});
        return bob::STATUS_EOS;
      }
      if (options == bob::OPTIONS_SYNC) {
        // We do not support sync pulls in this entry.
        std::move(next)(UV_EINVAL, nullptr, 0, [](size_t) {});
        return UV_EINVAL;
      }
      // We ignore the data, count, and max_count_hint here because we're
      // going to read into a single managed buffer instead.
      pending_reads_.push_back(std::move(next));
      if (pending_reads_.size() == 1)
        ReadStart();
      return bob::STATUS_WAIT;
    }

    SET_NO_MEMORY_INFO()
    SET_MEMORY_INFO_NAME(StreamBaseEntry::Reader)
    SET_SELF_SIZE(Reader)

   private:
    void ReadStop() { entry_->stream_base_->ReadStop(); }
    void ReadStart() { entry_->stream_base_->ReadStart(); }
    void Done() {
      ended_ = true;
      entry_->stream_base_->RemoveStreamListener(this);
      while (!pending_reads_.empty()) {
        std::move(pending_reads_.front())(bob::STATUS_EOS, nullptr, 0, [](size_t) {});
        pending_reads_.pop_front();
      }
    }

    BaseObjectPtr<StreamBaseEntry> entry_;
    std::deque<Next> pending_reads_;
    bool ended_ = false;
  };

  friend class Reader;
};

// ============================================================================

// A FdEntry reads from a file descriptor. A check is made before each read
// to determine if the fd has changed on disc. This is a best-effort check
// that only looks at file size, creation, and modification times. The stat
// check is also async, so there's a natural race condition there where the
// file could be modified between the stat and actual read calls. That's
// a tolerable risk here. While FdEntry is considered idempotent, this race
// means that it is indeed possible for multiple reads to return different
// results if the file just happens to get modified.
class FdEntry final : public EntryBase {
  // TODO(@jasnell, @flakey5):
  // * This should only allow reading from regular files. No directories, no pipes, etc.
  // * The reader should support accepting the buffer(s) from the pull, if any. It should
  //   only allocate a managed buffer if the pull doesn't provide any.
  // * We might want to consider making the stat on each read sync to eliminate the race
  //   condition described in the comment above.
 public:
  FdEntry(Environment* env,
          int fd,
          size_t start,
          v8::Maybe<size_t> end,
          BaseObjectPtr<fs::FileHandle> maybe_file_handle =
              BaseObjectPtr<fs::FileHandle>())
      : env_(env),
        fd_(fd),
        start_(0),
        maybe_file_handle_(maybe_file_handle) {
    CHECK(fd);
    if (GetStat(stat_) == 0) {
      if (end.IsNothing()) {
        end_ = stat_.st_size;
      } else {
        end_ = std::min(stat_.st_size, end.FromJust());
      }
    }
  }

  FdEntry(Environment* env, BaseObjectPtr<fs::FileHandle> handle)
      : FdEntry(env, handle->GetFD(), 0, Nothing<size_t>(), handle) {}

  FdEntry(Environment* env,
          int fd,
          uv_stat_t stat,
          size_t start,
          size_t end,
          BaseObjectPtr<fs::FileHandle> maybe_file_handle =
             BaseObjectPtr<fs::FileHandle>())
      : env_(env),
        fd_(end),
        start_(start),
        end_(end),
        stat_(stat),
        maybe_file_handle_(maybe_file_handle){}

  std::unique_ptr<DataQueue::Reader> getReader() override {
    return std::make_unique<Reader>(this);
  }

  std::unique_ptr<Entry> slice(
      size_t start,
      Maybe<size_t> end = Nothing<size_t>()) override {
    size_t new_start = start_ + start;
    size_t new_end = end_;
    if (end.IsJust()) {
      new_end = std::min(end.FromJust() + start, new_end);
    }

    CHECK(new_start >= start_);
    CHECK(new_end <= end_);

    return std::make_unique<FdEntry>(env_, fd_, stat_, new_start, new_end, maybe_file_handle_);
  }

  Maybe<size_t> size() const override {
    return Just(end_ - start_);
  }

  bool isIdempotent() const override {
    return true;
  }

  Environment* env() const { return env_; }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(FdEntry)
  SET_SELF_SIZE(FdEntry)

  class Wrap : public BaseObject {
   public:
    static void New(const FunctionCallbackInfo<Value>& args) {
      CHECK(args.IsConstructCall());
      Environment* env = Environment::GetCurrent(args);

      CHECK(args[0]->IsInt32());
      CHECK(args[1]->IsUint32());
      CHECK(args[2]->IsUint32());

      int fd = args[0].As<Int32>()->Value();
      size_t start = args[1].As<Uint32>()->Value();
      size_t end = args[1].As<Uint32>()->Value();

      new Wrap(env, args.This(), fd, start, Just(end));
    }

    static Local<FunctionTemplate> GetConstructorTemplate(Environment* env) {
      Local<FunctionTemplate> tmpl = env->fdentry_constructor_template();
      if (tmpl.IsEmpty()) {
        Isolate* isolate = env->isolate();
        tmpl = NewFunctionTemplate(isolate, New);

        tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "FdEntry"));
        tmpl->Inherit(BaseObject::GetConstructorTemplate(env));

        env->set_fdentry_constructor_template(tmpl);
      }

      return tmpl;
    }

    static void Initialize(Environment* env, Local<Object> target) {
      SetConstructorFunction(
        env->context(), target, "FdEntry", GetConstructorTemplate(env));
    }

    static void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
      registry->Register(New);
    }

    static BaseObjectPtr<StreamBaseEntry> Create(
        Environment* env,
        int fd,
        size_t start = 0,
        Maybe<size_t> end = Nothing<size_t>()) {
      Local<Object> obj;
      if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(env->context())
          .ToLocal(&obj)) {
        return BaseObjectPtr<Wrap>();
      }

      return MakeBaseObject<Wrap>(env, obj, fd, start, end);
    }

    Wrap(Environment* env, Local<Object> obj, int fd, size_t start, v8::Maybe<size_t> end)
        : BaseObject(env, obj),
          inner_(std::make_unique<FdEntry>(env, fd, start, end)) {
      MakeWeak();
    }

    std::unique_ptr<DataQueue::Entry> detach() {
      return std::move(inner_);
    }

    bool isDetached() const { return inner_ == nullptr; }

    void MemoryInfo(MemoryTracker* tracker) const override {
      tracker->TrackField("entry", inner_);
    }
    SET_MEMORY_INFO_NAME(FdEntry::Wrap)
    SET_SELF_SIZE(Wrap)

   private:
    std::unique_ptr<FdEntry> inner_;
  };

 private:
  Environment* env_;
  int fd_;
  size_t start_ = 0;
  size_t end_ = 0;
  uv_stat_t stat_;
  uv_fs_t req;
  BaseObjectPtr<fs::FileHandle> maybe_file_handle_;

  int GetStat(uv_stat_t& stat) {
    int err = uv_fs_fstat(env_->event_loop(), &req, fd_, nullptr);
    stat = req.statbuf;
    return err;
  }

  class Reader : public DataQueue::Reader {
   public:
    Reader(FdEntry* entry)
        : entry_(entry),
          offset_(entry->start_),
          end_(entry_->end_) {}

    int Pull(
        Next next,
        int options,
        DataQueue::Vec* data,
        size_t count,
        size_t max_count_hint = bob::kMaxCountHint) override {
      // TODO(@jasnell): For now, we're going to ignore data and count.
      // Later, we can support these to allow the caller to allocate the
      // buffers we read into. To keep things easier for now, we're going
      // to read into a pre-allocated buffer.
      if (ended_ || offset_ == end_) {
        std::move(next)(bob::STATUS_EOS, nullptr, 0, [](size_t) {});
        return bob::STATUS_EOS;
      }
      // offset_ should always be less than end_ here
      CHECK_LT(offset_, end_);
      new PendingRead(this, std::move(next));
      return bob::STATUS_WAIT;
    }

    SET_NO_MEMORY_INFO()
    SET_MEMORY_INFO_NAME(FdEntry::Reader)
    SET_SELF_SIZE(Reader)

   private:
    FdEntry* entry_;
    bool ended_ = false;
    size_t offset_;
    size_t end_;

    struct PendingRead {
      static constexpr size_t DEFAULT_BUFFER_SIZE = 4096;
      Reader* reader;
      Next next;
      uv_fs_t req_;
      uv_buf_t uvbuf;

      PendingRead(Reader* reader, Next next)
          : reader(reader),
            next(std::move(next)),
            uvbuf(reader->entry_->env()->allocate_managed_buffer(
              std::min(DEFAULT_BUFFER_SIZE, reader->end_ - reader->offset_)
            )) {
        req_.data = this;
        uv_fs_fstat(reader->entry_->env()->event_loop(), &req_,
                    reader->entry_->fd_, &PendingRead::OnStat);
      }

      void Done() {
        delete this;
      }

      bool checkEnded() {
        if (reader->ended_) {
          // A previous read ended this readable. Let's stop here.
          std::move(next)(bob::STATUS_EOS, nullptr, 0, [](size_t) {});
          return true;
        }
        if (req_.result < 0) {
          std::move(next)(req_.result, nullptr, 0, [](size_t) {});
          return true;
        }
        return false;
      }

      void OnStat() {
        if (checkEnded()) return Done();
        uv_stat_t current_stat = req_.statbuf;
        uv_stat_t& orig = reader->entry_->stat_;
        if (current_stat.st_size != orig.st_size ||
            current_stat.st_ctim.tv_nsec != orig.st_ctim.tv_nsec ||
            current_stat.st_mtim.tv_nsec != orig.st_mtim.tv_nsec) {
          // The fd was modified. Fail the read.
          std::move(next)(UV_EINVAL, nullptr, 0, [](size_t) {});
          return;
        }

        // Now we read from the file.
        uv_fs_read(reader->entry_->env()->event_loop(), &req_,
                   reader->entry_->fd_,
                   &uvbuf, 1,
                   reader->offset_,
                   OnRead);
      }

      void OnRead() {
        auto on_exit = OnScopeLeave([this] { Done(); });
        if (checkEnded()) return;
        std::unique_ptr<BackingStore> store =
            reader->entry_->env()->release_managed_buffer(uvbuf);
        size_t amountRead = req_.result;
        // We should never read past end_
        CHECK_LE(amountRead + reader->offset_, reader->end_);
        reader->offset_ += amountRead;
        if (reader->offset_ == reader->end_)
          reader->ended_ = true;
        DataQueue::Vec vec = {
          reinterpret_cast<uint8_t*>(store->Data()),
          amountRead
        };
        std::move(next)(
          reader->ended_ ? bob::STATUS_END : bob::STATUS_CONTINUE,
          &vec, 1, [buf=std::move(store)](size_t) {});
      }

      static void OnStat(uv_fs_t* req) {
        PendingRead* read = ContainerOf(&PendingRead::req_, req);
        read->OnStat();
      }

      static void OnRead(uv_fs_t* req) {
        PendingRead* read = ContainerOf(&PendingRead::req_, req);
        read->OnRead();
      }
    };

    friend struct PendingRead;
    friend class FdEntry;
  };

  friend class Reader;
  friend struct Reader::PendingRead;
};

// ============================================================================

class CrossThreadReaderImpl final : public DataQueue::CrossThreadReader {
 public:
  CrossThreadReaderImpl(
      Environment* env,
      std::unique_ptr<DataQueue::Reader> reader)
      : inner_(std::move(reader)) {
    uv_async_init(env->event_loop(), &inner_signal_, InnerSignalCallback);
    uv_async_init(env->event_loop(), &done_signal_, DoneSignalCallback);
  }

  void Bind(Environment* env) override {
    CHECK(!bound_);
    uv_async_init(env->event_loop(), &outer_signal_, OuterSignalCallback);
  }

  int Pull(
      Next next,
      int options,
      DataQueue::Vec* data,
      size_t count,
      size_t max_count_hint = bob::kMaxCountHint) override {
    CHECK(bound_);
    if (ended_) {
      std::move(next)(bob::STATUS_EOS, nullptr, 0, [](size_t) {});
      return bob::STATUS_EOS;
    }

    // We cannot pull while there is an outstanding pull.
    pull_queue_.push_back(std::make_unique<PendingPull>(
      std::move(next),
      options,
      data,
      count,
      max_count_hint));
    CHECK_EQ(uv_async_send(&inner_signal_), 0);

    return bob::STATUS_WAIT;
  }

  void MemoryInfo(node::MemoryTracker* tracker) const override {
    tracker->TrackField("reader", inner_);
    tracker->TrackField("pull_queue", pull_queue_);
    tracker->TrackField("result_queue", result_queue_);
    tracker->TrackField("done_queue", done_queue_);
  }

  SET_MEMORY_INFO_NAME(CrossThreadReaderImpl);
  SET_SELF_SIZE(CrossThreadReaderImpl);

 private:
  static void InnerSignalCallback(uv_async_t* signal) {
    CrossThreadReaderImpl* reader =
        ContainerOf(&CrossThreadReaderImpl::inner_signal_, signal);

    while(!reader->pull_queue_.empty()) {
      auto pending = std::move(reader->pull_queue_.front());
      reader->pull_queue_.pop_front();

      auto options = pending->options;
      auto data = pending->data;
      auto count = pending->count;
      auto max_count_hint = pending->max_count_hint;

      reader->Pull(
          [pending = std::move(pending), &reader]
          (int status, const DataQueue::Vec* vecs, size_t count, auto done) {
        pending->result =
            std::make_unique<PendingResult>(
                status, vecs, count, std::move(done));
        reader->result_queue_.push_back(std::move(pending));
        uv_async_send(&reader->outer_signal_);
      }, options, data, count, max_count_hint);
    }
  }

  static void OuterSignalCallback(uv_async_t* signal) {
    CrossThreadReaderImpl* reader =
        ContainerOf(&CrossThreadReaderImpl::outer_signal_, signal);

    while (!reader->result_queue_.empty()) {
      auto pending = std::move(reader->result_queue_.front());
      reader->result_queue_.pop_front();
      CHECK_NOT_NULL(pending->result);
      auto& result = pending->result;
      std::move(pending->next)(
          result->status,
          result->data,
          result->count,
          [&reader, done = std::move(result->done)](size_t status) mutable {
        reader->done_queue_.push_back(std::make_unique<PendingDone>(
            std::move(done), status));
        uv_async_send(&reader->done_signal_);
      });
    }
  }

  static void DoneSignalCallback(uv_async_t* signal) {
    CrossThreadReaderImpl* reader =
        ContainerOf(&CrossThreadReaderImpl::done_signal_, signal);
    while (!reader->done_queue_.empty()) {
      auto pending = std::move(reader->done_queue_.front());
      reader->done_queue_.pop_front();
      std::move(pending->done)(pending->status);
    }
  }

  struct PendingResult : public MemoryRetainer {
    int status;
    const DataQueue::Vec* data;
    size_t count;
    Done done;
    PendingResult(int status,
                  const DataQueue::Vec* data,
                  size_t count,
                  Done done)
        : status(status),
          data(data),
          count(count),
          done(std::move(done)) {}

    void MemoryInfo(node::MemoryTracker* tracker) const override {
      size_t size = 0;
      for (size_t n = 0; n < count; n++) {
        size += data[n].len;
      }
      tracker->TrackFieldWithSize("data", size);
    }
    SET_MEMORY_INFO_NAME(CrossThreadReaderImpl::PendingResult);
    SET_SELF_SIZE(PendingResult);
  };

  struct PendingPull : public MemoryRetainer {
    Next next;
    int options;
    DataQueue::Vec* data;
    size_t count;
    size_t max_count_hint;
    std::unique_ptr<PendingResult> result = nullptr;
    PendingPull(Next next,
                int options,
                DataQueue::Vec* data,
                size_t count,
                size_t max_count_hint)
        : next(std::move(next)),
          options(options),
          data(data),
          count(count),
          max_count_hint((max_count_hint)) {}

    void MemoryInfo(node::MemoryTracker* tracker) const override {
      size_t size = 0;
      for (size_t n = 0; n < count; n++) {
        size += data[n].len;
      }
      tracker->TrackFieldWithSize("data", size);
      if (result) {
        tracker->TrackField("result", result);
      }
    }
    SET_MEMORY_INFO_NAME(CrossThreadReaderImpl::PendingPull);
    SET_SELF_SIZE(PendingPull);
  };

  struct PendingDone : public MemoryRetainer {
    Done done;
    int status;
    PendingDone(Done done, int status) : done(std::move(done)), status(status) {}

    SET_NO_MEMORY_INFO();
    SET_MEMORY_INFO_NAME(CrossThreadReaderImpl::PendingDone);
    SET_SELF_SIZE(PendingDone);
  };

  std::unique_ptr<DataQueue::Reader> inner_;
  uv_async_t inner_signal_;
  uv_async_t outer_signal_;
  uv_async_t done_signal_;
  std::deque<std::unique_ptr<PendingPull>> pull_queue_;
  std::deque<std::unique_ptr<PendingPull>> result_queue_;
  std::deque<std::unique_ptr<PendingDone>> done_queue_;
  bool ended_ = false;
  bool bound_ = false;
};

}  // namespace

std::unique_ptr<DataQueue::CrossThreadReader> DataQueue::CreateCrossThreadReader(
    Environment* env,
    std::unique_ptr<DataQueue::Reader> reader) {
  return std::make_unique<CrossThreadReaderImpl>(env, std::move(reader));
}

std::shared_ptr<DataQueue> DataQueue::CreateIdempotent(
    std::vector<std::unique_ptr<Entry>> list) {
  // Any entry is invalid for an idempotent DataQueue if any of the entries
  // are nullptr or is not idempotent.
  size_t size = 0;
  const auto isInvalid = [&size](auto& item) {
    if (item == nullptr || !item->isIdempotent()) {
      return true;  // true means the entry is not valid here.
    }

    // To keep from having to iterate over the entries
    // again, we'll try calculating the size. If any
    // of the entries are unable to provide a size, then
    // we assume we cannot safely treat this entry as
    // idempotent even if it claims to be.
    size_t itemSize;
    if (item->size().To(&itemSize)) { size += itemSize; }
    else return true;  // true means the entry is not valid here.

    return false;
  };

  if (std::any_of(list.begin(), list.end(), isInvalid)) {
    return nullptr;
  }

  return std::make_shared<DataQueueImpl>(std::move(list), size);
}

std::shared_ptr<DataQueue> DataQueue::Create(Maybe<size_t> capped) {
  return std::make_shared<DataQueueImpl>(capped);
}

std::unique_ptr<DataQueue::Entry> DataQueue::CreateInMemoryEntryFromView(
    Local<ArrayBufferView> view) {
  // If the view is not detachable, we do not want to create an InMemoryEntry
  // from it. Why? Because if we're not able to detach the backing store from
  // the underlying buffer, something else could modify the buffer while we're
  // holding the reference, which means we cannot guarantee that reads will be
  // idempotent.
  if (!view->Buffer()->IsDetachable()) {
    return nullptr;
  }
  auto store = view->Buffer()->GetBackingStore();
  auto offset = view->ByteOffset();
  auto length = view->ByteLength();
  view->Buffer()->Detach();
  return CreateInMemoryEntryFromBackingStore(std::move(store), offset, length);
}

std::unique_ptr<DataQueue::Entry>
DataQueue::CreateInMemoryEntryFromBackingStore(
    std::shared_ptr<BackingStore> store,
    size_t offset,
    size_t length) {
  CHECK(store);
  if (offset + length > store->ByteLength()) {
    return nullptr;
  }
  return std::make_unique<InMemoryEntry>(std::move(store), offset, length);
}

std::unique_ptr<DataQueue::Entry> DataQueue::CreateDataQueueEntry(
    std::shared_ptr<DataQueue> data_queue) {
  return std::make_unique<DataQueueEntry>(std::move(data_queue));
}

std::unique_ptr<DataQueue::Entry> DataQueue::CreateStreamBaseEntry(
    StreamBase* stream_base,
    BaseObjectPtr<BaseObject> strong_ref) {
  return nullptr;
}

std::unique_ptr<DataQueue::Entry> DataQueue::CreateStreamEntry(
    Environment* env,
    Local<Object> obj) {
  return nullptr;
}

std::unique_ptr<DataQueue::Entry> DataQueue::CreateFdEntry(
    BaseObjectPtr<fs::FileHandle> handle) {
  return std::make_unique<FdEntry>(handle->env(), handle);
}

void DataQueue::Initialize(Environment* env, v8::Local<v8::Object> target) {
  StreamEntry::Wrap::Initialize(env, target);
  StreamBaseEntry::Wrap::Initialize(env, target);
  FdEntry::Wrap::Initialize(env, target);
}

void DataQueue::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  StreamEntry::Wrap::RegisterExternalReferences(registry);
  StreamBaseEntry::Wrap::RegisterExternalReferences(registry);
  FdEntry::Wrap::RegisterExternalReferences(registry);
}

}  // namespace node
