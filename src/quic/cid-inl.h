#pragma once

#include "ngtcp2/ngtcp2.h"
#include "quic/defs.h"
#include "util.h"
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "cid.h"

namespace node {
namespace quic {

CID::CID() : ptr_(&cid_) { cid_.datalen = 0; }
CID::CID(const ngtcp2_cid& cid) : ptr_(&cid_) {
  ngtcp2_cid_init(&cid_, cid.data, cid.datalen);
}
CID::CID(const uint8_t* data, size_t len) {
  CHECK_GE(len, QUIC_MIN_CIDLEN);
  CHECK_LE(len, QUIC_MAX_CIDLEN);
  ngtcp2_cid_init(&cid_, data, len);
}
CID::CID(const ngtcp2_cid* cid) : ptr_(cid) {
  CHECK_NOT_NULL(cid);
}
CID::CID(const CID& other) : ptr_(&cid_) { *this = other; }

bool CID::operator!=(const CID& other) const noexcept {
  return !(*this == other);
}

CID::operator const uint8_t*() const { return ptr_->data; }
CID::operator const ngtcp2_cid&() const { return *ptr_; }
CID::operator const ngtcp2_cid*() const { return ptr_; }

CID::operator bool() const { return ptr_->datalen >= QUIC_MIN_CIDLEN; }
size_t CID::length() const { return ptr_->datalen; }

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
