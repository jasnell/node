#include "quic/quic_buffer.h"
#include "base_object-inl.h"
#include "async_wrap-inl.h"
#include "node_bob-inl.h"
#include "util-inl.h"
#include "uv.h"
#include "v8.h"

#include "gtest/gtest.h"
#include <memory>
#include <vector>

using node::quic::QuicBuffer;
using node::quic::QuicBufferChunk;
using node::bob::Status;
using node::bob::Options;
using node::bob::Done;
using ::testing::AssertionSuccess;
using ::testing::AssertionFailure;

TEST(QuicBuffer, Simple) {
  char data[100];
  memset(&data, 0, node::arraysize(data));
  bool deleter_called = false;
  std::shared_ptr<v8::BackingStore> store =
      v8::ArrayBuffer::NewBackingStore(
          data,
          sizeof(data),
          [](void* data, size_t len, void* deleter_data) {
            bool* deleter_called = static_cast<bool*>(deleter_data);
            *deleter_called = true;
          },
          &deleter_called);

  QuicBuffer buffer;
  buffer.Push(std::move(store), sizeof(data));
  ASSERT_EQ(buffer.length(), 100U);

  buffer.Acknowledge(100);

  ASSERT_EQ(buffer.length(), 0U);
  ASSERT_TRUE(deleter_called);
}

TEST(QuicBuffer, ConsumeMore) {
  char data[100];
  memset(&data, 0, node::arraysize(data));
  bool deleter_called = false;
  std::shared_ptr<v8::BackingStore> store =
      v8::ArrayBuffer::NewBackingStore(
          data,
          sizeof(data),
          [](void* data, size_t len, void* deleter_data) {
            bool* deleter_called = static_cast<bool*>(deleter_data);
            *deleter_called = true;
          },
          &deleter_called);

  QuicBuffer buffer;
  buffer.Push(std::move(store), sizeof(data));
  ASSERT_EQ(buffer.length(), 100U);

  // Consume more than what was buffered
  ASSERT_EQ(buffer.Acknowledge(150), 100U);

  ASSERT_EQ(buffer.length(), 0U);
  ASSERT_TRUE(deleter_called);
}

TEST(QuicBuffer, MultipleBuffers) {
  char one[] = "abcdefghijklmnopqrstuvwxyz";
  char two[] = "zyxwvutsrqponmlkjihgfedcba";
  bool one_deleted = false;
  bool two_deleted = false;

  auto deleter_fn = [](void* data, size_t len, void* deleter_data) {
    bool* deleted = static_cast<bool*>(deleter_data);
    *deleted = true;
  };

  std::shared_ptr<v8::BackingStore> store_one =
      v8::ArrayBuffer::NewBackingStore(
          one,
          26,
          deleter_fn,
          &one_deleted);

  std::shared_ptr<v8::BackingStore> store_two =
      v8::ArrayBuffer::NewBackingStore(
          two,
          26,
          deleter_fn,
          &two_deleted);

  QuicBuffer buf;
  buf.Push(std::move(store_one), store_two->ByteLength());
  buf.Push(std::move(store_two), store_two->ByteLength());

  ASSERT_EQ(buf.remaining(), 52U);
  ASSERT_EQ(buf.length(), 52U);

  buf.Seek(2);
  ASSERT_EQ(buf.remaining(), 50U);
  ASSERT_EQ(buf.length(), 52U);

  buf.Acknowledge(25);
  ASSERT_EQ(buf.length(), 27U);

  buf.Acknowledge(25);
  ASSERT_EQ(buf.length(), 2U);

  ASSERT_TRUE(one_deleted);
  ASSERT_FALSE(two_deleted);

  buf.Acknowledge(2);
  ASSERT_EQ(buf.length(), 0U);

  ASSERT_TRUE(two_deleted);
}

TEST(QuicBuffer, Cancel) {
  char one[] = "abcdefghijklmnopqrstuvwxyz";
  char two[] = "zyxwvutsrqponmlkjihgfedcba";
  bool one_deleted = false;
  bool two_deleted = false;

  auto deleter_fn = [](void* data, size_t len, void* deleter_data) {
    bool* deleted = static_cast<bool*>(deleter_data);
    *deleted = true;
  };

  std::shared_ptr<v8::BackingStore> store_one =
      v8::ArrayBuffer::NewBackingStore(
          one,
          26,
          deleter_fn,
          &one_deleted);

  std::shared_ptr<v8::BackingStore> store_two =
      v8::ArrayBuffer::NewBackingStore(
          two,
          26,
          deleter_fn,
          &two_deleted);

  QuicBuffer buf;
  buf.Push(std::move(store_one), store_two->ByteLength());
  buf.Push(std::move(store_two), store_two->ByteLength());

  ASSERT_FALSE(one_deleted);
  ASSERT_FALSE(two_deleted);

  ASSERT_EQ(buf.length(), 52U);
  ASSERT_EQ(buf.remaining(), 52U);

  buf.Clear();

  ASSERT_TRUE(one_deleted);
  ASSERT_TRUE(two_deleted);
  ASSERT_EQ(buf.length(), 0U);
  ASSERT_EQ(buf.remaining(), 0U);
}
