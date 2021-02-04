#ifndef SRC_QUIC_QUIC_H_
#define SRC_QUIC_QUIC_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "base_object-inl.h"
#include "env.h"
#include "memory_tracker.h"
#include "node_sockaddr.h"
#include "string_bytes.h"
#include "util.h"
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
#include <v8.h>
#include <uv.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace node {
namespace quic {

using QuicConnectionPointer = DeleteFnPtr<ngtcp2_conn, ngtcp2_conn_del>;
using Http3ConnectionPointer = DeleteFnPtr<nghttp3_conn, nghttp3_conn_del>;

#define stream_id int64_t

constexpr uint64_t NGTCP2_APP_NOERROR = 0xff00;

#define QUIC_CONSTRUCTORS(V)                                                   \
  V(endpoint)                                                                  \
  V(session)                                                                   \
  V(stream)

#define QUIC_JS_CALLBACKS(V)                                                   \
  V(socket_close, onSocketClose)                                               \
  V(socket_server_busy, onSocketServerBusy)                                    \
  V(session_cert, onSessionCert)                                               \
  V(session_client_hello, onSessionClientHello)                                \
  V(session_close, onSessionClose)                                             \
  V(session_handshake, onSessionHandshake)                                     \
  V(session_keylog, onSessionKeylog)                                           \
  V(session_path_validation, onSessionPathValidation)                          \
  V(session_use_preferred_address, onSessionUsePreferredAddress)               \
  V(session_qlog, onSessionQlog)                                               \
  V(session_ready, onSessionReady)                                             \
  V(session_status, onSessionStatus)                                           \
  V(session_ticket, onSessionTicket)                                           \
  V(session_version_negotiation, onSessionVersionNegotiation)                  \
  V(stream_close, onStreamClose)                                               \
  V(stream_error, onStreamError)                                               \
  V(stream_ready, onStreamReady)                                               \
  V(stream_reset, onStreamReset)                                               \
  V(stream_headers, onStreamHeaders)                                           \
  V(stream_blocked, onStreamBlocked)

class Session;
class Stream;
class BindingState final : public BaseObject {
 public:
  static constexpr FastStringKey binding_data_name { "quic" };
  BindingState(Environment* env, v8::Local<v8::Object> object);

  inline void check_initialized() { CHECK(!initialized_); }

  inline void set_initialized() { initialized_ = true; }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(BindingState);
  SET_SELF_SIZE(BindingState);

#define V(name)                                                               \
  void set_ ## name ## _constructor_template(                                 \
      Environment* env,                                                       \
      v8::Local<v8::FunctionTemplate> tmpl);                                  \
  v8::Local<v8::FunctionTemplate> name ## _constructor_template(              \
      Environment* env) const;
  QUIC_CONSTRUCTORS(V)
#undef V

#define V(name, _)                                                             \
  void set_ ## name ## _callback(Environment* env, v8::Local<v8::Function> fn);\
  v8::Local<v8::Function> name ## _callback(Environment* env) const;
  QUIC_JS_CALLBACKS(V)
#undef V

 private:
#define V(name)                                                                \
  v8::Global<v8::FunctionTemplate> name ## _constructor_template_;
  QUIC_CONSTRUCTORS(V)
#undef V

#define V(name, _) v8::Global<v8::Function> name ## _callback_;
  QUIC_JS_CALLBACKS(V)
#undef V

  bool initialized_ = false;
};

// CIDs are used to identify QUIC sessions and may
// be between 0 and 20 bytes in length.
class CID final : public MemoryRetainer {
 public:
  // Empty constructor
  inline CID() : ptr_(&cid_) {}

  // Copy constructor
  inline CID(const CID& cid) noexcept : CID(cid->data, cid->datalen) {}

  // Copy constructor
  inline explicit CID(const ngtcp2_cid& cid) : CID(cid.data, cid.datalen) {}

  // Wrap constructor
  inline explicit CID(const ngtcp2_cid* cid) : ptr_(cid) {}

  inline CID(const uint8_t* cid, size_t len) : CID() {
    ngtcp2_cid* ptr = this->cid();
    ngtcp2_cid_init(ptr, cid, len);
    ptr_ = ptr;
  }

  CID(CID&&cid) = delete;

  struct Hash {
    inline size_t operator()(const CID& cid) const {
      size_t hash = 0;
      for (size_t n = 0; n < cid->datalen; n++) {
        hash ^= std::hash<uint8_t>{}(cid->data[n]) + 0x9e3779b9 +
                (hash << 6) + (hash >> 2);
      }
      return hash;
    }
  };

  inline bool operator==(const CID& other) const noexcept {
    return memcmp(cid()->data, other.cid()->data, cid()->datalen) == 0;
  }

  inline bool operator!=(const CID& other) const noexcept {
    return !(*this == other);
  }

  inline CID& operator=(const CID& cid) noexcept {
    if (this == &cid) return *this;
    this->~CID();
    return *new(this) CID(cid);
  }

  const ngtcp2_cid& operator*() const { return *ptr_; }

  const ngtcp2_cid* operator->() const { return ptr_; }

  inline std::string ToString() const {
    std::vector<char> dest(ptr_->datalen * 2 + 1);
    dest[dest.size() - 1] = '\0';
    size_t written = StringBytes::hex_encode(
        reinterpret_cast<const char*>(ptr_->data),
        ptr_->datalen,
        dest.data(),
        dest.size());
    return std::string(dest.data(), written);
  }

  const ngtcp2_cid* cid() const { return ptr_; }

  const uint8_t* data() const { return ptr_->data; }

  operator bool() const { return ptr_->datalen > 0; }

  size_t length() const { return ptr_->datalen; }

  ngtcp2_cid* cid() {
    CHECK_EQ(ptr_, &cid_);
    return &cid_;
  }

  unsigned char* data() {
    return reinterpret_cast<unsigned char*>(cid()->data);
  }

  void set_length(size_t length) {
    cid()->datalen = length;
  }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(CID)
  SET_SELF_SIZE(CID)

  template <typename T>
  using Map = std::unordered_map<CID, T, CID::Hash>;

 private:
  ngtcp2_cid cid_{};
  const ngtcp2_cid* ptr_;
};

// A utility class that wraps ngtcp2_path to adapt it to work with SocketAddress
struct Path final : public ngtcp2_path {
  inline Path(const SocketAddress& local, const SocketAddress& remote);
};

struct PathStorage final : public ngtcp2_path_storage {
  inline PathStorage() { ngtcp2_path_storage_zero(this); }
};

// PreferredAddress is a helper class used only when a client QuicSession
// receives an advertised preferred address from a server. The helper provides
// information about the servers advertised preferred address. Call Use()
// to let ngtcp2 know which preferred address to use (if any).
  class PreferredAddress final {
 public:
  enum class Policy {
    IGNORE,
    USE
  };

  struct Address {
    int family;
    uint16_t port;
    std::string address;
  };

  inline PreferredAddress(
      Environment* env,
      ngtcp2_addr* dest,
      const ngtcp2_preferred_addr* paddr)
      : env_(env),
        dest_(dest),
        paddr_(paddr) {}

  PreferredAddress(const PreferredAddress& other) = delete;
  PreferredAddress(PreferredAddress&& other) = delete;
  PreferredAddress* operator=(const PreferredAddress& other) = delete;
  PreferredAddress* operator=(PreferredAddress&& other) = delete;

  // When a preferred address is advertised by a server, the
  // advertisement also includes a new CID and (optionally)
  // a stateless reset token. If the preferred address is
  // selected, then the client QuicSession will make use of
  // these new values. Access to the cid and reset token
  // are provided via the PreferredAddress class only as a
  // convenience.
  inline const ngtcp2_cid* cid() const {
    return &paddr_->cid;
  }

  // The stateless reset token associated with the preferred
  // address CID
  inline const uint8_t* stateless_reset_token() const {
    return paddr_->stateless_reset_token;
  }

  // A preferred address advertisement may include both an
  // IPv4 and IPv6 address. Only one of which will be used.

  inline Address ipv4() const {
    Address address;
    address.family = AF_INET;
    address.port = paddr_->ipv4_port;

    char host[NI_MAXHOST];
    // Return an empty string if unable to convert...
    if (uv_inet_ntop(AF_INET, paddr_->ipv4_addr, host, sizeof(host)) == 0)
      address.address = std::string(host);

    return address;
  }

  inline Address ipv6() const {
    Address address;
    address.family = AF_INET6;
    address.port = paddr_->ipv6_port;

    char host[NI_MAXHOST];
    // Return an empty string if unable to convert...
    if (uv_inet_ntop(AF_INET6, paddr_->ipv6_addr, host, sizeof(host)) == 0)
      address.address = std::string(host);

    return address;
  }

  // Instructs the QuicSession to use the advertised
  // preferred address matching the given family. If
  // the advertisement does not include a matching
  // address, the preferred address is ignored. If
  // the given address cannot be successfully resolved
  // using uv_getaddrinfo it is ignored.
  inline bool Use(const Address& address) const {
    uv_getaddrinfo_t req;

    if (!Resolve(address, &req))
      return false;

    dest_->addrlen = req.addrinfo->ai_addrlen;
    memcpy(dest_->addr, req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);
    uv_freeaddrinfo(req.addrinfo);
    return true;
  }

  inline void CopyToTransportParams(
      ngtcp2_transport_params* params,
      const sockaddr* addr) {
    CHECK_NOT_NULL(params);
    CHECK_NOT_NULL(addr);
    params->preferred_address_present = 1;
    switch (addr->sa_family) {
      case AF_INET: {
        const sockaddr_in* src = reinterpret_cast<const sockaddr_in*>(addr);
        memcpy(
            params->preferred_address.ipv4_addr,
            &src->sin_addr,
            sizeof(params->preferred_address.ipv4_addr));
        params->preferred_address.ipv4_port = SocketAddress::GetPort(addr);
        break;
      }
      case AF_INET6: {
        const sockaddr_in6* src = reinterpret_cast<const sockaddr_in6*>(addr);
        memcpy(
            params->preferred_address.ipv6_addr,
            &src->sin6_addr,
            sizeof(params->preferred_address.ipv6_addr));
        params->preferred_address.ipv6_port = SocketAddress::GetPort(addr);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

 private:
  inline bool Resolve(const Address& address, uv_getaddrinfo_t* req) const {
    addrinfo hints{};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = address.family;
    hints.ai_socktype = SOCK_DGRAM;

    // Unfortunately ngtcp2 requires the selection of the
    // preferred address to be synchronous, which means we
    // have to do a sync resolve using uv_getaddrinfo here.
    return
        uv_getaddrinfo(
            env_->event_loop(),
            req,
            nullptr,
            address.address.c_str(),
            std::to_string(address.port).c_str(),
            &hints) == 0 &&
        req->addrinfo != nullptr;
  }

  Environment* env_;
  mutable ngtcp2_addr* dest_;
  const ngtcp2_preferred_addr* paddr_;
};

// A Stateless Reset Token is a mechanism by which a QUIC
// endpoint can discreetly signal to a peer that it has
// lost all state associated with a connection. This
// helper class is used to both store received tokens and
// provide storage when creating new tokens to send.
class StatelessResetToken final : public MemoryRetainer {
 public:
  inline StatelessResetToken(
      uint8_t* token,
      const uint8_t* secret,
      const CID& cid) {
    // TODO(@jasnell): Uncomment when crypto added
    // GenerateResetToken(token, secret, cid);
    // memcpy(buf_, token, sizeof(buf_));
  }

  inline StatelessResetToken(const uint8_t* secret, const CID& cid) {
    // TODO(@jasnell): Uncomment when crypto added
    // GenerateResetToken(buf_, secret, cid);
  }

  explicit inline StatelessResetToken(const uint8_t* token) {
    memcpy(buf_, token, sizeof(buf_));
  }

  StatelessResetToken(const StatelessResetToken& other)
      : StatelessResetToken(other.buf_) {}

  StatelessResetToken(StatelessResetToken&& other) = delete;
  StatelessResetToken& operator=(StatelessResetToken&& other) = delete;

  StatelessResetToken& operator=(const StatelessResetToken& other) {
    if (this == &other) return *this;
    this->~StatelessResetToken();
    return *new(this) StatelessResetToken(other);
  }

  inline std::string ToString() const {
    std::vector<char> dest(NGTCP2_STATELESS_RESET_TOKENLEN * 2 + 1);
    dest[dest.size() - 1] = '\0';
    size_t written = StringBytes::hex_encode(
        reinterpret_cast<const char*>(buf_),
        NGTCP2_STATELESS_RESET_TOKENLEN,
        dest.data(),
        dest.size());
    return std::string(dest.data(), written);
  }

  inline const uint8_t* data() const { return buf_; }

  struct Hash {
    inline size_t operator()(const StatelessResetToken& token) const {
      size_t hash = 0;
      for (size_t n = 0; n < NGTCP2_STATELESS_RESET_TOKENLEN; n++)
        hash ^= std::hash<uint8_t>{}(token.buf_[n]) + 0x9e3779b9 +
                (hash << 6) + (hash >> 2);
      return hash;
    }
  };

  inline bool operator==(const StatelessResetToken& other) const {
    return memcmp(data(), other.data(), NGTCP2_STATELESS_RESET_TOKENLEN) == 0;
  }

  inline bool operator!=(const StatelessResetToken& other) const {
    return !(*this == other);
  }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(StatelessResetToken)
  SET_SELF_SIZE(StatelessResetToken)

  template <typename T>
  using Map =
      std::unordered_map<
          StatelessResetToken,
          BaseObjectPtr<T>,
          StatelessResetToken::Hash>;

 private:
  uint8_t buf_[NGTCP2_STATELESS_RESET_TOKENLEN]{};
};
}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_QUIC_H_
