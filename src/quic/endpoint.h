#ifndef SRC_QUIC_ENDPOINT_H_
#define SRC_QUIC_ENDPOINT_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "quic/buffer.h"
#include "quic/crypto.h"
#include "quic/quic.h"
#include "quic/stats.h"
#include "quic/session.h"
#include "crypto/crypto_context.h"
#include "crypto/crypto_util.h"
#include "aliased_struct.h"
#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "node_sockaddr.h"
#include "udp_wrap.h"

#include <ngtcp2/ngtcp2.h>
#include <v8.h>

#include <string>

namespace node {
namespace quic {

#define ENDPOINT_STATS(V)                                                      \
  V(CREATED_AT, created_at, "Created At")                                      \
  V(BOUND_AT, bound_at, "Bound At")                                            \
  V(LISTEN_AT, listen_at, "Listen At")                                         \
  V(DESTROYED_AT, destroyed_at, "Destroyed At")                                \
  V(BYTES_RECEIVED, bytes_received, "Bytes Received")                          \
  V(BYTES_SENT, bytes_sent, "Bytes Sent")                                      \
  V(PACKETS_RECEIVED, packets_received, "Packets Received")                    \
  V(PACKETS_IGNORED, packets_ignored, "Packets Ignored")                       \
  V(PACKETS_SENT, packets_sent, "Packets Sent")                                \
  V(SERVER_SESSIONS, server_sessions, "Server Sessions")                       \
  V(CLIENT_SESSIONS, client_sessions, "Client Sessions")                       \
  V(STATELESS_RESET_COUNT, stateless_reset_count, "Stateless Reset Count")     \
  V(SERVER_BUSY_COUNT, server_busy_count, "Server Busy Count")

#define ENDPOINT_STATE(V)                                                      \
  V(LISTENING, listening, uint8_t)                                             \
  V(BUSY, busy, uint8_t)                                                       \
  V(STATELESS_RESET_DISABLED, stateless_reset_disabled, uint8_t)               \
  V(WAITING_FOR_CALLBACKS, waiting_for_callbacks, uint8_t)                     \
  V(PENDING_CALLBACKS, pending_callbacks, size_t)

class Endpoint;

#define V(name, _, __) IDX_STATS_ENDPOINT_##name,
enum class EndpointStatsIdx : int {
  ENDPOINT_STATS(V)
  IDX_STATS_ENDPOINT_COUNT
};
#undef V

#define V(_, name, __) uint64_t name;
struct EndpointStats {
  ENDPOINT_STATS(V)
};
#undef V

struct EndpointStatsTraits {
  using Stats = EndpointStats;
  using Base = Endpoint;

  static void ToString(const Base& ptr, AddStatsField add_field);
};

using EndpointStatsBase = StatsBase<EndpointStatsTraits>;
using UdpSendWrap = ReqWrap<uv_udp_send_t>;

class SendWrap : public UdpSendWrap {
 public:
  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);

  static SendWrap* Create(Environment* env, size_t length);

  SendWrap(
      Environment* env,
      v8::Local<v8::Object> object,
      size_t length);

  inline size_t length() const { return length_; }

  inline void set_session(BaseObjectPtr<Session> session) {
    session_ = session;
  }

  inline void set_packet(std::unique_ptr<Packet> packet) {
    packet_ = std::move(packet);
  }

  Packet* packet() const { return packet_.get(); }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(SendWrap)
  SET_SELF_SIZE(SendWrap)

 private:
  size_t length_;
  BaseObjectPtr<Session> session_;
  std::unique_ptr<Packet> packet_;
};

class Endpoint final : public AsyncWrap,
                       public UDPListener,
                       public EndpointStatsBase {
 public:  // UDPListener
  uv_buf_t OnAlloc(size_t suggested_size) override;
  void OnRecv(ssize_t nread,
              const uv_buf_t& buf,
              const sockaddr* addr,
              unsigned int flags) override;
  UdpSendWrap* CreateSendWrap(size_t msg_size) override;
  void OnAfterBind() override;

 public:
  struct State {
#define V(_, name, type) type name;
    ENDPOINT_STATE(V)
#undef V
  };

  struct Config {
    uint64_t retry_token_expiration = DEFAULT_RETRYTOKEN_EXPIRATION;
    uint64_t max_window_override = 0;
    uint64_t max_stream_window_override = 0;
    uint64_t max_connections_per_host = DEFAULT_MAX_CONNECTIONS_PER_HOST;
    uint64_t max_connections_total = DEFAULT_MAX_CONNECTIONS;
    uint64_t max_stateless_resets = DEFAULT_MAX_STATELESS_RESETS;
    uint64_t address_lru_size = DEFAULT_MAX_SOCKETADDRESS_LRU_SIZE;
    uint64_t retry_limit = DEFAULT_MAX_RETRY_LIMIT;
    uint64_t max_payload_size = NGTCP2_DEFAULT_MAX_PKTLEN;
    uint64_t unacknowledged_packet_threshold = 0;
    bool qlog = false;
    bool validate_address = true;
    bool disable_stateless_reset = false;
    double rx_loss = 0.0;
    double tx_loss = 0.0;
    ngtcp2_cc_algo cc_algorithm = NGTCP2_CC_ALGO_CUBIC;
    uint8_t reset_token_secret[NGTCP2_STATELESS_RESET_TOKENLEN];

    Config() = default;
    inline Config(const Config& other)
        : retry_token_expiration(other.retry_token_expiration),
          max_connections_per_host(other.max_connections_per_host),
          max_connections_total(other.max_connections_total),
          max_stateless_resets(other.max_stateless_resets),
          address_lru_size(other.address_lru_size),
          qlog(other.qlog),
          validate_address(other.validate_address),
          disable_stateless_reset(other.disable_stateless_reset),
          rx_loss(other.rx_loss),
          tx_loss(other.tx_loss) {
      memcpy(
          reset_token_secret,
          other.reset_token_secret,
          NGTCP2_STATELESS_RESET_TOKENLEN);
      GenerateResetTokenSecret();
    }

    Config(Config&& other) = delete;
    Config& operator=(Config&& other) = delete;

    inline Config& operator=(const Config& other) {
      if (this == &other) return *this;
      this->~Config();
      return *new(this) Config(other);
    }

    inline void GenerateResetTokenSecret() {
      crypto::EntropySource(
          reinterpret_cast<unsigned char*>(&reset_token_secret),
          NGTCP2_STATELESS_RESET_TOKENLEN);
    }
  };

  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);

  static void Initialize(Environment* env);

  static BaseObjectPtr<Endpoint> Create(
      Environment* env,
      v8::Local<v8::Object> udp_wrap,
      const Config& config);

  Endpoint(
      Environment* env,
      v8::Local<v8::Object> object,
      v8::Local<v8::Object> udp_wrap,
      const Config& config);
  ~Endpoint() override;

  explicit Endpoint(const Endpoint& other) = delete;
  explicit Endpoint(const Endpoint&& other) = delete;
  Endpoint& operator=(const Endpoint& other) = delete;
  Endpoint& operator=(const Endpoint&& other) = delete;

  const Config& config() const { return config_; }
  const Session::Options& server_config() const { return server_options_; }
  State* state() { return state_.Data(); }

  // Waits for any currently pending callbacks to be completed
  // then triggers the immediate close/destruction of the QuicSocket
  void WaitForPendingCallbacks();

  // The local UDP address to which the QuicSocket is bound.
  SocketAddress local_address() const;

  void AssociateCID(const CID& cid, const CID& scid);

  void DisassociateCID(const CID& cid);

  void AssociateStatelessResetToken(
      const StatelessResetToken& token,
      BaseObjectPtr<Session> session);

  void DisassociateStatelessResetToken(const StatelessResetToken& token);

  void Listen(const Session::Options& options);

  void ReceiveStart();

  void ReceiveStop();

  void AddSession(const CID& cid, BaseObjectPtr<Session> session);

  void RemoveSession(const CID& cid, const SocketAddress& addr);

  // Sends the given packet to the remote_addr for the given session
  int SendPacket(
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      std::unique_ptr<Packet> packet,
      BaseObjectPtr<Session> session = BaseObjectPtr<Session>());

  // Generates and sends a retry packet. This is terminal
  // for the connection. Retry packets are used to force
  // explicit path validation by issuing a token to the
  // peer that it must thereafter include in all subsequent
  // initial packets. Upon receiving a retry packet, the
  // peer must termination it's initial attempt to
  // establish a connection and start a new attempt.
  //
  // Retry packets will only ever be generated by QUIC servers,
  // and only if the QuicSocket is configured for explicit path
  // validation. There is no way for a client to force a retry
  // packet to be created. However, once a client determines that
  // explicit path validation is enabled, it could attempt to
  // DOS by sending a large number of malicious initial packets
  // to intentionally ellicit retry packets (It can do so by
  // intentionally sending initial packets that ignore the retry
  // token). To help mitigate that risk, we limit the number of
  // retries we send to a given remote endpoint.
  bool SendRetry(
      uint32_t version,
      const CID& dcid,
      const CID& scid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr);

  // Possibly generates and sends a stateless reset packet.
  // This is terminal for the connection. It is possible
  // that a malicious packet triggered this so we need to
  // be careful not to commit too many resources.
  bool SendStatelessReset(
      const CID& cid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      size_t source_len);

  // Sends a version negotiation packet. This is terminal for
  // the connection and is sent only when a QUIC packet is
  // received for an unsupported Node.js version.
  // It is possible that a malicious packet triggered this
  // so we need to be careful not to commit too many resources.
  // Currently, we only support one QUIC version at a time.
  void SendVersionNegotiation(
      uint32_t version,
      const CID& dcid,
      const CID& scid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr);

// Shutdown a connection prematurely, before a QuicSession is created.
// This should only be called at the start of a session before the crypto
// keys have been established.
  void ImmediateConnectionClose(
      uint32_t version,
      const CID& scid,
      const CID& dcid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      int64_t reason = NGTCP2_INVALID_TOKEN);

  uint32_t GetFlowLabel(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    const CID& cid);

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(Endpoint)
  SET_SELF_SIZE(Endpoint)

 private:
  void OnSendDone(UdpSendWrap* wrap, int status) override;

  void OnError(ssize_t status);

  void OnEndpointDone();

  void OnServerBusy();
  void OnSessionReady(BaseObjectPtr<Session> session);

  // When a packet is received here, we do not yet know if we can
  // process it successfully as a QUIC packet or not. Given the
  // nature of UDP, we may receive a great deal of garbage here
  // so it is extremely important not to commit resources until
  // we're certain we can process the data we received as QUIC
  // packet. Any packet we choose not to process must be ignored.
  void OnReceive(
      ssize_t nread,
      AllocatedBuffer buf,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      unsigned int flags);

  int Send(
      uv_buf_t* buf,
      size_t len,
      const sockaddr* addr);

  // When a received packet contains a QUIC short header but cannot be
  // matched to a known Session, it is either (a) garbage,
  // (b) a valid packet for a connection we no longer have state
  // for, or (c) a stateless reset. Because we do not yet know if
  // we are going to process the packet, we need to try to quickly
  // determine -- with as little cost as possible -- whether the
  // packet contains a reset token. We do so by checking the final
  // NGTCP2_STATELESS_RESET_TOKENLEN bytes in the packet to see if
  // they match one of the known reset tokens previously given by
  // the remote peer. If there's a match, then it's a reset token,
  // if not, we move on the to the next check. It is very important
  // that this check be as inexpensive as possible to avoid a DOS
  // vector.
  bool MaybeStatelessReset(
      const CID& dcid,
      const CID& scid,
      ssize_t nread,
      const uint8_t* data,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      unsigned int flags);

  // Inspects the packet and possibly accepts it as a new
  // initial packet creating a new Session instance.
  // If the packet is not acceptable, it is very important
  // not to commit resources.
  BaseObjectPtr<Session> AcceptInitialPacket(
      uint32_t version,
      const CID& dcid,
      const CID& scid,
      ssize_t nread,
      const uint8_t* data,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      unsigned int flags);

  BaseObjectPtr<Session> FindSession(const CID& cid);

  void IncrementPendingCallbacks();
  void DecrementPendingCallbacks();
  bool is_done_waiting_for_callbacks() const;

  void set_validated_address(const SocketAddress& addr);
  bool is_validated_address(const SocketAddress& addr) const;
  void IncrementSocketAddressCounter(const SocketAddress& addr);
  void DecrementSocketAddressCounter(const SocketAddress& addr);
  void IncrementStatelessResetCounter(const SocketAddress& addr);
  size_t current_socket_address_count(const SocketAddress& addr) const;
  size_t current_stateless_reset_count(const SocketAddress& addr) const;

  // Returns true if, and only if, diagnostic packet loss is enabled
  // and the current packet should be artificially considered lost.
  bool is_diagnostic_packet_loss(double prob) const;

  Config config_;
  Session::Options server_options_;
  AliasedStruct<State> state_;
  BaseObjectPtr<SocketAddressBlockListWrap> block_list_;
  UDPWrapBase* udp_;
  BaseObjectPtr<AsyncWrap> udp_strong_ptr_;
  uint8_t token_secret_[kTokenSecretLen];

  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;

  struct SocketAddressInfoTraits {
    struct Type {
      size_t active_connections;
      size_t reset_count;
      size_t retry_count;
      uint64_t timestamp;
      bool validated;
    };

    static bool CheckExpired(const SocketAddress& address, const Type& type);
    static void Touch(const SocketAddress& address, Type* type);
  };

  SocketAddressLRU<SocketAddressInfoTraits> addrLRU_;
  StatelessResetToken::Map<Session> token_map_;

  CID::Map<BaseObjectPtr<Session>> sessions_;
  CID::Map<CID> dcid_to_scid_;
  SendWrap* last_created_send_wrap_ = nullptr;
};

class ConfigObject : public BaseObject {
 public:
  static bool HasInstance(Environment* env, v8::Local<v8::Value> value);
  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static void Initialize(Environment* env, v8::Local<v8::Object> target);
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void GenerateResetTokenSecret(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void SetResetTokenSecret(
      const v8::FunctionCallbackInfo<v8::Value>& args);


  Endpoint::Config* data() { return config_.get(); }

  // TODO(@jasnell): This is a lie
  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(ConfigObject)
  SET_SELF_SIZE(ConfigObject)

 private:
  v8::Maybe<bool> SetOption(
      v8::Local<v8::Object> object,
      v8::Local<v8::String> name,
      uint64_t Endpoint::Config::*member);

  v8::Maybe<bool> SetOption(
      v8::Local<v8::Object> object,
      v8::Local<v8::String> name,
      double Endpoint::Config::*member);

  v8::Maybe<bool> SetOption(
      v8::Local<v8::Object> object,
      v8::Local<v8::String> name,
      ngtcp2_cc_algo Endpoint::Config::*member);

  v8::Maybe<bool> SetOption(
      v8::Local<v8::Object> object,
      v8::Local<v8::String> name,
      bool Endpoint::Config::*member);

  ConfigObject(
      Environment* env,
      v8::Local<v8::Object> object,
      std::shared_ptr<Endpoint::Config> config =
          std::make_shared<Endpoint::Config>());
  std::shared_ptr<Endpoint::Config> config_;
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_ENDPOINT_H_
