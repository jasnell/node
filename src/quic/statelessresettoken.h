#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "defs.h"
#include "cid.h"
#include <node_internals.h>
#include <memory_tracker.h>

namespace node {
namespace quic {

// A stateless reset token is used when a QUIC endpoint receives a QUIC packet
// with a short header but the associated connection ID cannot be matched to any
// known Session. In such cases, the receiver may choose to send a subtle opaque
// indication to the sending peer that state for the Session has apparently been
// lost. For any on- or off- path attacker, a stateless reset packet resembles
// any other QUIC packet with a short header. In order to be successfully
// handled as a stateless reset, the peer must have already seen a reset token
// issued to it associated with the given CID. The token itself is opaque to the
// peer that receives is but must be possible to statelessly recreate by the
// peer that originally created it. The actual implementation is Node.js
// specific but we currently defer to a utility function provided by ngtcp2.
//
// QUIC leaves the generation of stateless session tokens up to the
// implementation to figure out. The idea, however, is that it ought to be
// possible to generate a stateless reset token reliably even when all state
// for a connection has been lost. We use the cid as it's the only reliably
// consistent bit of data we have when a session is destroyed.
class StatelessResetToken final : public MemoryRetainer {
 public:

  // Generates a stateless reset token using HKDF with the cid and token secret
  // as input. The token secret is either provided by user code when an Endpoint
  // is created or is generated randomly.
  inline StatelessResetToken(const uint8_t* secret, const CID& cid);

  // Generates a stateless reset token using the given token storage.
  // The StatelessResetToken wraps the token and does not take ownership
  // of it.
  inline StatelessResetToken(uint8_t* token,
                             const uint8_t* secret,
                             const CID& cid);

  // Wraps the given token. Does not take over ownership of the token storage.
  explicit inline StatelessResetToken(
      const uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN]);

  std::string ToString() const;

  inline operator const uint8_t*() const;
  inline operator const char*() const;
  inline size_t length() const;

  inline bool operator==(const StatelessResetToken& other) const;
  inline bool operator!=(const StatelessResetToken& other) const;

  struct Hash {
    size_t operator()(const StatelessResetToken& token) const;
  };

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(StatelessResetToken)
  SET_SELF_SIZE(StatelessResetToken)

  template <typename T>
  using Map =
      std::unordered_map<StatelessResetToken, T, StatelessResetToken::Hash>;

 private:
  const uint8_t* ptr_;
  uint8_t buf_[NGTCP2_STATELESS_RESET_TOKENLEN];
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
