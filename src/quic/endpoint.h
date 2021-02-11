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
#include "handle_wrap.h"
#include "node_sockaddr.h"
#include "node_worker.h"
#include "udp_wrap.h"

#include <ngtcp2/ngtcp2.h>
#include <v8.h>

#include <deque>
#include <string>

namespace node {
namespace quic {

#define ENDPOINT_STATS(V)                                                      \
  V(CREATED_AT, created_at, "Created at")                                      \
  V(DESTROYED_AT, destroyed_at, "Destroyed at")                                \
  V(BYTES_RECEIVED, bytes_received, "Bytes received")                          \
  V(BYTES_SENT, bytes_sent, "Bytes sent")                                      \
  V(PACKETS_RECEIVED, packets_received, "Packets received")                    \
  V(PACKETS_SENT, packets_sent, "Packets sent")                                \
  V(SERVER_SESSIONS, server_sessions, "Server sessions")                       \
  V(CLIENT_SESSIONS, client_sessions, "Client sessions")                       \
  V(STATELESS_RESET_COUNT, stateless_reset_count, "Stateless reset count")     \
  V(SERVER_BUSY_COUNT, server_busy_count, "Server busy count")

#define ENDPOINT_STATE(V)                                                      \
  V(LISTENING, listening, uint8_t)                                             \
  V(WAITING_FOR_CALLBACKS, waiting_for_callbacks, uint8_t)                     \
  V(PENDING_CALLBACKS, pending_callbacks, size_t)

class Endpoint;
class EndpointWrap;

#define V(name, _, __) IDX_STATS_ENDPOINT_##name,
enum EndpointStatsIdx {
  ENDPOINT_STATS(V)
  IDX_STATS_ENDPOINT_COUNT
};
#undef V

#define V(name, _, __) IDX_STATE_ENDPOINT_##name,
enum EndpointStateIdx {
  ENDPOINT_STATE(V)
  IDX_STATE_ENDPOINT_COUNT
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

class Endpoint final : public MemoryRetainer,
                       public EndpointStatsBase {
 public:
  struct Config : public MemoryRetainer {
      SocketAddress local_address;
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
          : local_address(other.local_address),
            retry_token_expiration(other.retry_token_expiration),
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

      SET_NO_MEMORY_INFO()
      SET_MEMORY_INFO_NAME(Endpoint::Config)
      SET_SELF_SIZE(Config)
    };

  class SendWrap : public UdpSendWrap {
   public:
    static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);

    static BaseObjectPtr<SendWrap> Create(
        Environment* env,
        const SocketAddress& destination,
        std::unique_ptr<Packet> packet,
        BaseObjectPtr<EndpointWrap> endpoint = BaseObjectPtr<EndpointWrap>());

    SendWrap(
      Environment* env,
      v8::Local<v8::Object> object,
      const SocketAddress& destination,
      std::unique_ptr<Packet> packet,
      BaseObjectPtr<EndpointWrap> endpoint);

    inline void Attach(const BaseObjectPtr<BaseObject>& strong_ptr) {
      strong_ptr_ = strong_ptr;
    }

    inline const SocketAddress& destination() const { return destination_; }
    inline EndpointWrap* endpoint() const { return endpoint_.get(); }
    inline Packet* packet() const { return packet_.get(); }

    void Done(int status);

    void MemoryInfo(MemoryTracker* tracker) const override;
    SET_MEMORY_INFO_NAME(Endpoint::SendWrap)
    SET_SELF_SIZE(SendWrap)

    using Queue = std::deque<BaseObjectPtr<SendWrap>>;

   private:
    SocketAddress destination_;
    std::unique_ptr<Packet> packet_;
    BaseObjectPtr<EndpointWrap> endpoint_;
    BaseObjectPtr<BaseObject> strong_ptr_;
    BaseObjectPtr<SendWrap> self_ptr_;
  };

  class UDP : public HandleWrap {
   public:
    static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
        Environment* env);

    static BaseObjectPtr<UDP> Create(
        Environment* env,
        Endpoint* endpoint);

    UDP(Environment* env,
        v8::Local<v8::Object> object,
        Endpoint* endpoint);

    UDP(const UDP&) = delete;
    UDP(UDP&&) = delete;

    int Bind(const SocketAddress& address, int flags);

    void Ref();
    void Unref();
    void Close();
    int StartReceiving();
    int StopReceiving();
    SocketAddress local_address() const;

    int SendPacket(BaseObjectPtr<SendWrap> req);

    SET_NO_MEMORY_INFO()
    SET_MEMORY_INFO_NAME(Endpoint::UDP)
    SET_SELF_SIZE(UDP)

   private:
    static void ClosedCb(uv_handle_t* handle);
    static void OnAlloc(
        uv_handle_t* handle,
        size_t suggested_size,
        uv_buf_t* buf);

    static void OnReceive(
        uv_udp_t* handle,
        ssize_t nread,
        const uv_buf_t* buf,
        const sockaddr* addr,
        unsigned int flags);

    void MaybeClose();

    uv_udp_t handle_;
    Endpoint* endpoint_;
  };

  class UDPHandle : public MemoryRetainer {
   public:
    UDPHandle(Environment* env, Endpoint* endpoint);

    inline ~UDPHandle() { Close(); }

    inline int Bind(const SocketAddress& address, int flags) {
      return udp_->Bind(address, flags);
    }

    inline void Ref() { udp_->Ref(); }
    inline void Unref() { udp_->Unref();}
    inline int StartReceiving() { return udp_->StartReceiving(); }
    inline int StopReceiving() { return udp_->StopReceiving(); }
    inline SocketAddress local_address() const { return udp_->local_address(); }
    void Close();

    inline int SendPacket(BaseObjectPtr<SendWrap> req) {
      return udp_->SendPacket(std::move(req));
    }

    void MemoryInfo(node::MemoryTracker* tracker) const override;
    SET_MEMORY_INFO_NAME(Endpoint::UDPHandle)
    SET_SELF_SIZE(UDPHandle)

   private:
    static void CleanupHook(void* data);
    Environment* env_;
    BaseObjectPtr<UDP> udp_;
  };

  struct InitialPacketListener {
    virtual bool Accept(
        const Session::Config& config,
        std::shared_ptr<v8::BackingStore> store,
        size_t nread,
        const SocketAddress& local_addr,
        const SocketAddress& remote_addr) = 0;

    using List = std::deque<InitialPacketListener*>;
  };

  struct PacketListener {
    enum class Flags {
      NONE,
      STATELESS_RESET
    };

    virtual bool Receive(
        const CID& dcid,
        const CID& scid,
        std::shared_ptr<v8::BackingStore> store,
        size_t nread,
        const SocketAddress& local_address,
        const SocketAddress& remote_address,
        Flags flags = Flags::NONE) = 0;
  };

  Endpoint(Environment* env, const Config& config);

  ~Endpoint() override;

  void AddInitialPacketListener(InitialPacketListener* listener);
  void RemoveInitialPacketListener(InitialPacketListener* listener);

  void AssociateCID(const CID& cid, PacketListener* session);
  void DisassociateCID(const CID& cid);

  void IncrementSocketAddressCounter(const SocketAddress& addr);
  void DecrementSocketAddressCounter(const SocketAddress& addr);

  void AssociateStatelessResetToken(
      const StatelessResetToken& token,
      PacketListener* session);

  void DisassociateStatelessResetToken(const StatelessResetToken& token);

  // This version of SendPacket is used to send packets that are not
  // affiliated with a Session (Retry, Version Negotiation, and Early
  // Connection Close packets, for instance).
  bool SendPacket(
    const SocketAddress& remote_address,
    std::unique_ptr<Packet> packet);

  // This version of SendPacket is used to send packets that are
  // affiliated with a Session.
  void SendPacket(BaseObjectPtr<SendWrap> packet);

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

  // Bind the UDP port if necessary and start listening for
  // inbound QUIC packets.
  int StartReceiving();

  int StopReceiving();

  void Ref();
  void Unref();

  inline void set_busy(bool on = true) { busy_ = on; }

  uint32_t GetFlowLabel(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    const CID& cid);

  const Config& config() const { return config_; }
  Environment* env() const { return env_; }
  SocketAddress local_address() const;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(Endpoint);
  SET_SELF_SIZE(Endpoint);

 private:
  static void OnOutbound(uv_async_t* handle);

  // Inspects the packet and possibly accepts it as a new
  // initial packet creating a new Session instance.
  // If the packet is not acceptable, it is very important
  // not to commit resources.
  bool AcceptInitialPacket(
      uint32_t version,
      const CID& dcid,
      const CID& scid,
      std::shared_ptr<v8::BackingStore> store,
      size_t nread,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr);

  int MaybeBind();

  PacketListener* FindSession(const CID& cid);

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
      std::shared_ptr<v8::BackingStore> store,
      size_t nread,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr);

  uv_buf_t OnAlloc(size_t suggested_size);
  void OnReceive(
      size_t nread,
      const uv_buf_t& buf,
      const SocketAddress& addr);

  void ProcessOutbound();
  void ProcessSendFailure(int status);
  void ProcessReceiveFailure(int status);

  // Possibly generates and sends a stateless reset packet.
  // This is terminal for the connection. It is possible
  // that a malicious packet triggered this so we need to
  // be careful not to commit too many resources.
  bool SendStatelessReset(
      const CID& cid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      size_t source_len);

  void set_validated_address(const SocketAddress& addr);
  bool is_validated_address(const SocketAddress& addr) const;
  void IncrementStatelessResetCounter(const SocketAddress& addr);
  size_t current_socket_address_count(const SocketAddress& addr) const;
  size_t current_stateless_reset_count(const SocketAddress& addr) const;
  bool is_diagnostic_packet_loss(double prob) const;

  Environment* env_;
  UDPHandle udp_;
  Config config_;

  SendWrap::Queue outbound_;
  uv_async_t outbound_signal_;
  size_t pending_outbound_ = 0;

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
  StatelessResetToken::Map<PacketListener*> token_map_;
  CID::Map<PacketListener*> sessions_;

  InitialPacketListener::List listeners_;

  bool busy_ = false;
  bool bound_ = false;

  Mutex session_mutex_;
  Mutex outbound_mutex_;
  Mutex listener_mutex_;
};

class EndpointWrap final : public AsyncWrap,
                           public Endpoint::InitialPacketListener,
                           public Endpoint::PacketListener {
 public:
  struct State {
#define V(_, name, type) type name;
    ENDPOINT_STATE(V)
#undef V
  };

  struct InboundPacket {
    CID dcid;
    CID scid;
    std::shared_ptr<v8::BackingStore> store;
    size_t nread;
    SocketAddress local_address;
    SocketAddress remote_address;
    Endpoint::PacketListener::Flags flags;

    using Queue = std::deque<InboundPacket>;
  };

  struct InitialPacket {
    Session::Config config;
    std::shared_ptr<v8::BackingStore> store;
    size_t nread;
    SocketAddress local_address;
    SocketAddress remote_address;

    using Queue = std::deque<InitialPacket>;
  };

  static bool HasInstance(Environment* env, v8::Local<v8::Value> value);
  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static void Initialize(Environment* env, v8::Local<v8::Object> target);

  static BaseObjectPtr<EndpointWrap> Create(
      Environment* env,
      const Endpoint::Config& config);

  static BaseObjectPtr<EndpointWrap> Create(
      Environment* env,
      std::shared_ptr<Endpoint> endpoint);

  static void CreateEndpoint(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void StartListen(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void StartWaitForPendingCallbacks(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  EndpointWrap(
      Environment* env,
      v8::Local<v8::Object> object,
      const Endpoint::Config& config);

  EndpointWrap(
      Environment* env,
      v8::Local<v8::Object> object,
      std::shared_ptr<Endpoint> inner);

  ~EndpointWrap() override;

  explicit EndpointWrap(const EndpointWrap& other) = delete;
  explicit EndpointWrap(const EndpointWrap&& other) = delete;
  EndpointWrap& operator=(const Endpoint& other) = delete;
  EndpointWrap& operator=(const Endpoint&& other) = delete;

  // Returns the default Session::Options used for new server
  // sessions accepted by this EndpointWrap.
  const Session::Options& server_config() const { return server_options_; }

  State* state() { return state_.Data(); }
  const Endpoint::Config& config() const { return inner_->config(); }

  // The local UDP address to which the inner Endpoint is bound.
  inline SocketAddress local_address() const {
    return inner_->local_address();
  }

  // Called by the inner Endpoint when a new initial packet is received.
  // Accept() will return true if the EndpointWrap will handle the initial
  // packet, false otherwise.
  bool Accept(
      const Session::Config& config,
      std::shared_ptr<v8::BackingStore> store,
      size_t nread,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr) override;

  // Adds a new Session to this EndpointWrap, associating the
  // session with the given CID. The inner Endpoint is also
  // notified to associate the CID with this EndpointWrap.
  void AddSession(const CID& cid, BaseObjectPtr<Session> session);

  // A single session may be associated with multiple CIDs
  // The AssociateCID registers the neceesary mapping both in the
  // EndpointWrap and the inner Endpoint.
  void AssociateCID(const CID& cid, const CID& scid);

  // Associates a given stateless reset token with the session.
  // This allows stateless reset tokens to be recognized and
  // dispatched to the proper EndpointWrap and Session for
  // processing.
  void AssociateStatelessResetToken(
      const StatelessResetToken& token,
      BaseObjectPtr<Session> session);

  // Removes the associated CID from this EndpointWrap and the
  // inner Endpoint.
  void DisassociateCID(const CID& cid);

  // Removes the associated stateless reset token from this EndpointWrap
  // and the inner Endpoint.
  void DisassociateStatelessResetToken(const StatelessResetToken& token);

  // Looks up an existing session by the associated CID. If no matching
  // session is found, returns an empty BaseObjectPtr<Session>.
  BaseObjectPtr<Session> FindSession(const CID& cid);

  // Generates an IPv6 flow label for the given local_address, remote_address,
  // and CID. Both the local_address and remote_address must be IPv6.
  uint32_t GetFlowLabel(
    const SocketAddress& local_address,
    const SocketAddress& remote_address,
    const CID& cid);

  // Shutdown a connection prematurely, before a Session is created.
  // This should only be called at the start of a session before the crypto
  // keys have been established.
  void ImmediateConnectionClose(
      uint32_t version,
      const CID& scid,
      const CID& dcid,
      const SocketAddress& local_addr,
      const SocketAddress& remote_addr,
      int64_t reason = NGTCP2_INVALID_TOKEN);

  // Registers this EndpointWrap as able to accept incoming initial
  // packets. Whenever an Endpoint receives an initial packet for which
  // there is no associated Session, the Endpoint will iterate through
  // it's registered listening EndpointWrap instances to find one willing
  // to accept the packet.
  void Listen(const Session::Options& options);

  void OnSendDone(int status);

  // Receives a packet intended for a session owned by this EndpointWrap
  bool Receive(
      const CID& dcid,
      const CID& scid,
      std::shared_ptr<v8::BackingStore> store,
      size_t nread,
      const SocketAddress& local_address,
      const SocketAddress& remote_address,
      PacketListener::Flags flags) override;

  // Removes the given session from from EndpointWrap and removes the
  // registered associations on the inner Endpoint.
  void RemoveSession(const CID& cid, const SocketAddress& addr);

  // Sends a serialized QUIC packet to the remote_addr on behalf of the
  // given session.
  void SendPacket(
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
  // and only if the Endpoint is configured for explicit path
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

  inline void set_busy(bool on = true) { inner_->set_busy(on); }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(EndpointWrap);
  SET_SELF_SIZE(EndpointWrap);

  // An EndpointWrap instance is cloneable over MessagePort.
  // Clones will share the same inner Endpoint instance but
  // will maintain their own state and their own collection
  // of associated sessions.
  class TransferData final : public worker::TransferData {
   public:
    inline TransferData(std::shared_ptr<Endpoint> inner)
        : inner_(inner) {}

    BaseObjectPtr<BaseObject> Deserialize(
        Environment* env,
        v8::Local<v8::Context> context,
        std::unique_ptr<worker::TransferData> self);

    void MemoryInfo(MemoryTracker* tracker) const override;
    SET_MEMORY_INFO_NAME(EndpointWrap::TransferData)
    SET_SELF_SIZE(TransferData)

   private:
    std::shared_ptr<Endpoint> inner_;
  };

  TransferMode GetTransferMode() const override {
    return TransferMode::kCloneable;
  }
  std::unique_ptr<worker::TransferData> CloneForMessaging() const override;

 private:
   static void OnInboundSignal(uv_async_t* handle);
   static void OnInitialSignal(uv_async_t* handle);

  // Called after the endpoint has been closed and the final
  // pending send callback has been received. Signals to the
  // JavaScript side that the endpoint is ready to be destroyed.
  void OnEndpointDone();

  // Called when the Endpoint has encountered an error condition
  // Signals to the JavaScript side.
  void OnError();

  // Called when a new Session has been created. Passes the
  // reference to the new session on the JavaScript side for
  // additional processing.
  void OnNewSession(const BaseObjectPtr<Session>& session);

  void ProcessInbound();
  void ProcessInitial();
  void ProcessInitialFailure();

  inline void DecrementPendingCallbacks() { state_->pending_callbacks--; }
  inline void IncrementPendingCallbacks() { state_->pending_callbacks++; }
  inline bool is_done_waiting_for_callbacks() const {
    return state_->waiting_for_callbacks && !state_->pending_callbacks;
  }
  void WaitForPendingCallbacks();

  AliasedStruct<State> state_;
  std::shared_ptr<Endpoint> inner_;

  Session::Options server_options_;

  StatelessResetToken::Map<BaseObjectPtr<Session>> token_map_;
  CID::Map<BaseObjectPtr<Session>> sessions_;
  CID::Map<CID> dcid_to_scid_;

  InboundPacket::Queue inbound_;
  InitialPacket::Queue initial_;

  uv_async_t inbound_signal_;
  uv_async_t initial_signal_;
  Mutex inbound_mutex_;
};

// The ConfigObject is a persistent, cloneable Endpoint::Config.
// It is used to encapsulate all of the fairly complex configuration
// options for an Endpoint.
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
  static void SetLocalAddress(const v8::FunctionCallbackInfo<v8::Value>& args);

  ConfigObject(
      Environment* env,
      v8::Local<v8::Object> object,
      std::shared_ptr<Endpoint::Config> config =
          std::make_shared<Endpoint::Config>());

  Endpoint::Config* data() { return config_.get(); }
  const Endpoint::Config& config() { return *config_.get(); }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(ConfigObject)
  SET_SELF_SIZE(ConfigObject)

  class TransferData : public worker::TransferData {
   public:
    explicit TransferData(std::shared_ptr<Endpoint::Config> config);

    BaseObjectPtr<BaseObject> Deserialize(
        Environment* env,
        v8::Local<v8::Context> context,
        std::unique_ptr<worker::TransferData> self);

    void MemoryInfo(MemoryTracker* tracker) const override;
    SET_MEMORY_INFO_NAME(ConfigObject::TransferData)
    SET_SELF_SIZE(TransferData)

   private:
    std::shared_ptr<Endpoint::Config> config_;
  };

  TransferMode GetTransferMode() const override {
    return TransferMode::kCloneable;
  }

  std::unique_ptr<worker::TransferData> CloneForMessaging() const override;

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

  std::shared_ptr<Endpoint::Config> config_;
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_ENDPOINT_H_
