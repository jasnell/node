#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "cid.h"
#include "defs.h"
#include "statelessresettoken.h"
#include <env.h>
#include <ngtcp2/ngtcp2.h>
#include <optional>

namespace node {
namespace quic {

// =============================================================================

// PreferredAddress is a helper class used only when a client Session receives
// an advertised preferred address from a server. The helper provides
// information about the servers advertised preferred address. Call Use() to let
// ngtcp2 know which preferred address to use (if any).
//
// Per section 9.6 of RFC 9000:
//   QUIC allows servers to accept connections on one IP address and attempt
//   to transfer these connections to a more preferred address shortly after
//   the handshake. This is particularly useful when clients initially connect
//   to an address shared by multiple servers but would prefer to use a unicast
//   address to ensure connection stability.
class PreferredAddress final {
 public:
  static void Initialize(Environment* env, v8::Local<v8::Object> target);

  enum class Policy {
    // Ignore the server-advertised preferred address.
    IGNORE_PREFERED,
    // Use the server-advertised preferred address.
    USE,
  };

  static constexpr uint32_t QUIC_PREFERRED_ADDRESS_USE =
      static_cast<uint32_t>(Policy::USE);
  static constexpr uint32_t QUIC_PREFERRED_ADDRESS_IGNORE =
      static_cast<uint32_t>(Policy::IGNORE_PREFERED);

  static v8::Maybe<Policy> GetPolicy(Environment* env, v8::Local<v8::Value> value);

  struct AddressInfo final {
    int family;
    uint16_t port;
    std::string address;
  };

  PreferredAddress(ngtcp2_path* dest,
                   const ngtcp2_preferred_addr* paddr);

  QUIC_NO_COPY_OR_MOVE(PreferredAddress)

  // When a preferred address is advertised by a server, the advertisement also
  // includes a new CID and (optionally) a stateless reset token. If the
  // preferred address is selected, then the client Session will make use of
  // these new values. Access to the cid and reset token are provided via the
  // PreferredAddress class only as a convenience.
  CID cid() const;

  // The stateless reset token associated with the preferred address CID
  StatelessResetToken stateless_reset_token() const;

  // A preferred address advertisement may include neither or both an IPv4 and
  // IPv6 address. Only one of which will be used.
  std::optional<AddressInfo> ipv4() const;
  std::optional<AddressInfo> ipv6() const;

  // Instructs the Session to use the given AddressInfo.
  // If the given address cannot be successfully resolved using uv_getaddrinfo
  // it is ignored.
  void Use(const AddressInfo& address) const;

  // Copy the given socket address into the transport params as the preferred
  // address advertisement. The family is automatically detected from the
  // address.
  static void CopyToTransportParams(ngtcp2_transport_params* params,
                                    const sockaddr* addr);

 private:
  mutable ngtcp2_path* dest_;
  const ngtcp2_preferred_addr* paddr_;
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
