#include "preferredaddress.h"
#include "cid-inl.h"
#include "statelessresettoken-inl.h"
#include <util.h>
#include <env-inl.h>
#include <node_sockaddr-inl.h>
#include <v8.h>

namespace node {

using v8::Just;
using v8::Maybe;
using v8::Nothing;

namespace quic {

namespace {
template <int FAMILY>
std::optional<PreferredAddress::AddressInfo> get_address_info(const ngtcp2_preferred_addr& paddr) {
  if constexpr (FAMILY == AF_INET) {
    if (!paddr.ipv4_present) return std::nullopt;
  } else {
    if (!paddr.ipv6_present) return std::nullopt;
  }

  PreferredAddress::AddressInfo address;
  address.family = FAMILY;
  if constexpr (FAMILY == AF_INET) {
    address.port = paddr.ipv4_port;
  } else {
    address.port = paddr.ipv6_port;
  }

  char host[NI_MAXHOST];
  // Return an empty string if unable to convert...
  if constexpr (FAMILY == AF_INET) {
    if (uv_inet_ntop(FAMILY, paddr.ipv4_addr, host, sizeof(host)) == 0)
      address.address = std::string(host);
  } else {
    if (uv_inet_ntop(FAMILY, paddr.ipv6_addr, host, sizeof(host)) == 0)
      address.address = std::string(host);
  }

  return address;
}

using AddrInfoPtr = DeleteFnPtr<addrinfo, uv_freeaddrinfo>;

bool resolve(const PreferredAddress::AddressInfo& address,
             uv_getaddrinfo_t* req) {
  addrinfo hints{};
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  hints.ai_family = address.family;
  hints.ai_socktype = SOCK_DGRAM;

  // Unfortunately ngtcp2 requires the selection of the
  // preferred address to be synchronous, which means we
  // have to do a sync resolve using uv_getaddrinfo here.
  return uv_getaddrinfo(nullptr,
                        req,
                        nullptr,
                        address.address.c_str(),
                        std::to_string(address.port).c_str(),
                        &hints) == 0 &&
         req->addrinfo != nullptr;
}
}  // namespace

Maybe<PreferredAddress::Policy> PreferredAddress::GetPolicy(
    Environment* env,
    v8::Local<v8::Value> value) {
  CHECK(value->IsUint32());
  uint32_t val = 0;
  if (!value->Uint32Value(env->context()).To(&val)) return Nothing<Policy>();
  switch (value->Uint32Value(env->context()).FromJust()) {
    case QUIC_PREFERRED_ADDRESS_IGNORE: return Just(Policy::IGNORE_PREFERED);
    case QUIC_PREFERRED_ADDRESS_USE: return Just(Policy::USE);
  }
  return Nothing<Policy>();
}

PreferredAddress::PreferredAddress(ngtcp2_path* dest,
                                   const ngtcp2_preferred_addr* paddr)
      : dest_(dest), paddr_(paddr) {}

std::optional<PreferredAddress::AddressInfo> PreferredAddress::ipv4() const {
  return get_address_info<AF_INET>(*paddr_);
}

std::optional<PreferredAddress::AddressInfo> PreferredAddress::ipv6() const {
  return get_address_info<AF_INET6>(*paddr_);
}

CID PreferredAddress::cid() const { return CID(paddr_->cid); }

void PreferredAddress::Use(const AddressInfo& address) const {
  uv_getaddrinfo_t req;
  AddrInfoPtr info(req.addrinfo);
  if (!resolve(address, &req)) return;
  dest_->remote.addrlen = req.addrinfo->ai_addrlen;
  memcpy(dest_->remote.addr, req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);
}

void PreferredAddress::CopyToTransportParams(ngtcp2_transport_params* params,
                                             const sockaddr* addr) {
  CHECK_NOT_NULL(params);
  CHECK_NOT_NULL(addr);
  params->preferred_address_present = 1;
  switch (addr->sa_family) {
    case AF_INET: {
      const sockaddr_in* src = reinterpret_cast<const sockaddr_in*>(addr);
      memcpy(params->preferred_address.ipv4_addr,
             &src->sin_addr,
             sizeof(params->preferred_address.ipv4_addr));
      params->preferred_address.ipv4_port = SocketAddress::GetPort(addr);
      return;
    }
    case AF_INET6: {
      const sockaddr_in6* src = reinterpret_cast<const sockaddr_in6*>(addr);
      memcpy(params->preferred_address.ipv6_addr,
             &src->sin6_addr,
             sizeof(params->preferred_address.ipv6_addr));
      params->preferred_address.ipv6_port = SocketAddress::GetPort(addr);
      return;
    }
  }
  UNREACHABLE();
}

void PreferredAddress::Initialize(Environment* env,
                                  v8::Local<v8::Object> target) {
  NODE_DEFINE_CONSTANT(target, QUIC_PREFERRED_ADDRESS_IGNORE);
  NODE_DEFINE_CONSTANT(target, QUIC_PREFERRED_ADDRESS_USE);
}

// The stateless reset token associated with the preferred address CID
StatelessResetToken PreferredAddress::stateless_reset_token() const {
  return StatelessResetToken(paddr_->stateless_reset_token);
}


}  // namespace quic
}  // namespace node
