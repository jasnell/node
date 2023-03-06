#include "statelessresettoken-inl.h"

namespace node {
namespace quic {

std::string StatelessResetToken::ToString() const {
  char dest[NGTCP2_STATELESS_RESET_TOKENLEN * 2 + 1];
  dest[arraysize(dest) - 1] = '\0';
  size_t written = StringBytes::hex_encode(*this,
                                           length(),
                                           dest,
                                           arraysize(dest));
  return std::string(dest, written);
}

size_t StatelessResetToken::Hash::operator()(
    const StatelessResetToken& token) const {
  size_t hash = 0;
  for (size_t n = 0; n < NGTCP2_STATELESS_RESET_TOKENLEN; n++)
    hash ^= std::hash<uint8_t>{}(token.ptr_[n]) + 0x9e3779b9 + (hash << 6) +
            (hash >> 2);
  return hash;
}

}  // namespace quic
}  // namespace node
