#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "statelessresettoken.h"
#include "cid-inl.h"
#include <string_bytes.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

namespace node {
namespace quic {

StatelessResetToken::StatelessResetToken(
  const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN]) : ptr_(token) {}

StatelessResetToken::StatelessResetToken(const uint8_t* secret,
                                         const CID& cid)
  : ptr_(buf_) {
  CHECK(NGTCP2_OK(ngtcp2_crypto_generate_stateless_reset_token(
      buf_, secret, length(), cid)));
}

StatelessResetToken::StatelessResetToken(
    uint8_t* token,
    const uint8_t* secret,
    const CID& cid) : ptr_(token) {
  CHECK(NGTCP2_OK(ngtcp2_crypto_generate_stateless_reset_token(
      token, secret, length(), cid)));
}

StatelessResetToken::operator const uint8_t*() const { return ptr_; }

StatelessResetToken::operator const char*() const {
  return reinterpret_cast<const char*>(ptr_);
}

inline size_t StatelessResetToken::length() const {
  return NGTCP2_STATELESS_RESET_TOKENLEN;
}

bool StatelessResetToken::operator==(const StatelessResetToken& other) const {
  CHECK_EQ(other.length(), NGTCP2_STATELESS_RESET_TOKENLEN);
  return memcmp(ptr_, other.ptr_, NGTCP2_STATELESS_RESET_TOKENLEN) == 0;
}

bool StatelessResetToken::operator!=(const StatelessResetToken& other) const {
  return !(*this == other);
}

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
