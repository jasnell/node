#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "bindingdata.h"
#include "env-inl.h"
#include "node_realm-inl.h"

namespace node {
namespace quic {

BindingData& BindingData::Get(Environment* env) {
  return *Realm::GetBindingData<BindingData>(env->context());
}

BindingData::operator ngtcp2_mem() const {
  return BindingData::Get(env()).MakeAllocator();
}

BindingData::operator nghttp3_mem() const {
  ngtcp2_mem allocator = *this;
  nghttp3_mem http3_allocator = {
      allocator.user_data,
      allocator.malloc,
      allocator.free,
      allocator.calloc,
      allocator.realloc,
  };
  return http3_allocator;
}

void BindingData::CheckAllocatedSize(size_t previous_size) const {
  CHECK_GE(current_ngtcp2_memory_, previous_size);
}

void BindingData::IncreaseAllocatedSize(size_t size) {
  current_ngtcp2_memory_ += size;
}

void BindingData::DecreaseAllocatedSize(size_t size) {
  current_ngtcp2_memory_ -= size;
}

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
