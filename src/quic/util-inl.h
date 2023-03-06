#pragma once

#include "ngtcp2/ngtcp2.h"
#include "quic/defs.h"
#include "util.h"
#include <node_sockaddr-inl.h>

namespace node {
namespace quic {

Path::Path(const SocketAddress& local, const SocketAddress& remote) {
  ngtcp2_addr_init(&this->local, local.data(), local.length());
  ngtcp2_addr_init(&this->remote, remote.data(), remote.length());
}

inline PathStorage::PathStorage() { ngtcp2_path_storage_zero(this); }
inline PathStorage::operator ngtcp2_path() { return path; }

const SocketAddress& Packet::destination() const { return destination_; }
bool Packet::is_pending() const { return !!handle_; }
size_t Packet::length() const { return data_ ? data_->length() : 0; }

Packet::operator uv_buf_t() const {
  CHECK(data_);
  uv_buf_t buf;
  buf.base = reinterpret_cast<char*>(data_->data());
  buf.len = data_->length();
  return buf;
}

Packet::operator ngtcp2_vec() const {
  CHECK(data_);
  ngtcp2_vec vec;
  vec.base = data_->data();
  vec.len = data_->length();
  return vec;
}

void Packet::Truncate(size_t len) {
  CHECK(data_);
  CHECK_LE(len, data_->length());
  data_->data_.SetLength(len);
}

void Packet::Attach(BaseObjectPtr<BaseObject> handle) {
  handle_ = std::move(handle);
}

Store::operator bool() const { return store_ != nullptr; }
size_t Store::length() const { return length_; }

Store::operator uv_buf_t() const {
  uv_buf_t buf;
  buf.base = store_ != nullptr ?
      static_cast<char*>(store_->Data()) + offset_ :
      nullptr;
  buf.len = length_;
  return buf;
}

Store::operator ngtcp2_vec() const {
  ngtcp2_vec vec;
  vec.base = store_ != nullptr ?
      static_cast<uint8_t*>(store_->Data()) + offset_ :
      nullptr;
  vec.len = length_;
  return vec;
}

Store::operator nghttp3_vec() const {
  nghttp3_vec vec;
  vec.base = store_ != nullptr ?
      static_cast<uint8_t*>(store_->Data()) + offset_ :
      nullptr;
  vec.len = length_;
  return vec;
}

template <typename View>
inline v8::Local<View> Store::ToArrayBufferView(Environment* env) const {
  return !store_ ?
      View::New(v8::ArrayBuffer::New(env->isolate(), 0), 0, 0) :
      View::New(v8::ArrayBuffer::New(env->isolate(), store_),
                offset_, length_);
}

QuicError::operator bool() const {
  if ((code() == NGTCP2_NO_ERROR && type() == QUIC_ERROR_TYPE_TRANSPORT) ||
      (code() == NGTCP2_APP_NOERROR && type() == QUIC_ERROR_TYPE_APPLICATION)) {
    return false;
  }
  return true;
}

bool QuicError::operator!=(const QuicError& other) const {
  return !(*this == other);
}

bool QuicError::operator==(const QuicError& other) const {
  return type() == other.type() &&
         code() == other.code() &&
         frameType() == other.frameType();
}

QuicError::Type QuicError::type() const {
  return static_cast<Type>(ptr_->type);
}

error_code QuicError::code() const { return ptr_->error_code; }

uint64_t QuicError::frameType() const { return ptr_->frame_type; }

const std::string_view QuicError::reason() const { return reason_; }

const ngtcp2_connection_close_error& QuicError::operator*() const {
  return *ptr_;
}

const ngtcp2_connection_close_error* QuicError::operator->() const {
  return ptr_;
}

QuicError::operator const ngtcp2_connection_close_error*() const {
  return ptr_;
}

}  // namespace quic
}  // namespace node
