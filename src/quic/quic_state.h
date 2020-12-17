#ifndef SRC_QUIC_QUIC_STATE_H_
#define SRC_QUIC_QUIC_STATE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_buffer.h"
#include "aliased_struct.h"

namespace node {
namespace quic {

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

#define QUIC_CONSTRUCTORS(V)                                                   \
  V(quicclientsession)                                                         \
  V(quicserversession)                                                         \
  V(quicserverstream)                                                          \
  V(quicsocketsendwrap)

// Configuration options that are passed to the peer via transport parameters.
// The first name is used as part of the index we use internally to reference
// it in the aliased array. The second name is the property name from ngtcp2's
// transport param struct.
#define QUIC_SESSION_TRANSPORT_PARAMS(V)                                       \
  V(ACTIVE_CONNECTION_ID_LIMIT, active_connection_id_limit, uint64_t)          \
  V(MAX_STREAM_DATA_BIDI_LOCAL, initial_max_stream_data_bidi_local, uint64_t)  \
  V(MAX_STREAM_DATA_BIDI_REMOTE, initial_max_stream_data_bidi_remote, uint64_t)\
  V(MAX_STREAM_DATA_UNI, initial_max_stream_data_uni, uint64_t)                \
  V(MAX_DATA, initial_max_data, uint64_t)                                      \
  V(MAX_STREAMS_BIDI, initial_max_streams_bidi, uint64_t)                      \
  V(MAX_STREAMS_UNI, initial_max_streams_uni, uint64_t)                        \
  V(MAX_IDLE_TIMEOUT, max_idle_timeout, uint64_t)                              \
  V(MAX_UDP_PAYLOAD_SIZE, max_udp_payload_size, uint64_t)                      \
  V(MAX_ACK_DELAY, max_ack_delay, uint64_t)

// Configuration options that set locally for the session.
// The first name is used as part of the index we use internally to reference
// it in the aliased array. The second name is the property name from ngtcp2's
// options struct.
#define QUIC_SESSION_CONFIG_PARAMS(V)                                          \
  V(CC_ALGO, cc_algo, ngtcp2_cc_algo)

// The quicsessionconfig_buffer AliasedArray is created when the quic module
// is loaded, and is set at module scope on the JavaScript side. The array
// contains IDX_QUIC_SESSION_CONFIG_COUNT double entries (double because the
// actual configuration options generally need to allow for uint64_t values).
// The QuicSessionConfigIndex defines the index positions of each field in
// the array (see the QUIC_SESSION_TRANSPORT_PARAMS and
// QUIC_SESSION_CONFIG_PARAMS) defines above. When a new QuicSession is created,
// the values in the AliasedArray are set in JavaScript then read out
// synchronously in C++ (See QuicSessionConfig::Set in quic_session.cc)
// To add a new configuration option at the C++ side, simply add it to the
// relevant define above. There must be a matching field in the
// ngtcp2_settings struct or the QuicSessionConfig class.
enum QuicSessionConfigIndex : int {
#define V(name, _, __) IDX_QUIC_SESSION_##name,
  QUIC_SESSION_TRANSPORT_PARAMS(V)
  QUIC_SESSION_CONFIG_PARAMS(V)
#undef V
  IDX_QUIC_SESSION_CONFIG_COUNT
};

enum Http3ConfigIndex : int {
  IDX_HTTP3_QPACK_MAX_TABLE_CAPACITY,
  IDX_HTTP3_QPACK_BLOCKED_STREAMS,
  IDX_HTTP3_MAX_HEADER_LIST_SIZE,
  IDX_HTTP3_MAX_PUSHES,
  IDX_HTTP3_MAX_HEADER_PAIRS,
  IDX_HTTP3_MAX_HEADER_LENGTH,
  IDX_HTTP3_CONFIG_COUNT
};

// Configuration settings for the QuicSocket.
#define QUIC_SOCKET_CONFIG_PARAMS(V)                                           \
  V(RETRY_TOKEN_EXPIRATION, retry_token_expiration, uint64_t)                  \
  V(MAX_CONNECTIONS_PER_HOST, max_connections_per_host, size_t)                \
  V(MAX_STATELESS_RESETS_PER_HOST, max_stateless_resets_per_host, size_t)      \
  V(DISABLE_STATELESS_RESET, disable_stateless_reset, bool)

struct QuicSocketConfig {
#define V(_, key, type) type key;
  QUIC_SOCKET_CONFIG_PARAMS(V)
#undef V
};

#define V(id, name, _)                                                         \
  IDX_QUICSOCKET_CONFIG_##id = offsetof(QuicSocketConfig, name),
enum QuicSocketConfigFields {
  QUIC_SOCKET_CONFIG_PARAMS(V)
  IDX_QUICSOCKET_CONFIG_END
};
#undef V

class QuicState : public BaseObject {
 public:
  explicit QuicState(Environment* env, v8::Local<v8::Object> obj)
    : BaseObject(env, obj),
      root_buffer(
        env->isolate(),
        sizeof(quic_state_internal)),
      quicsessionconfig_buffer(
        env->isolate(),
        offsetof(quic_state_internal, quicsessionconfig_buffer),
        IDX_QUIC_SESSION_CONFIG_COUNT + 1,
        root_buffer),
      http3config_buffer(
        env->isolate(),
        offsetof(quic_state_internal, http3config_buffer),
        IDX_HTTP3_CONFIG_COUNT + 1,
        root_buffer),
      quicsocketconfig_buffer(env->isolate()) {
  }

  AliasedUint8Array root_buffer;
  AliasedFloat64Array quicsessionconfig_buffer;
  AliasedFloat64Array http3config_buffer;
  AliasedStruct<QuicSocketConfig> quicsocketconfig_buffer;

  bool warn_trace_tls = true;

  static constexpr FastStringKey binding_data_name { "quic" };

#define V(name, _)                                                             \
  inline v8::Local<v8::Function> on_ ## name() const {                         \
    return PersistentToLocal::Strong(on_ ## name ## _);                        \
  }                                                                            \
  inline void set_on_ ## name(v8::Local<v8::Function> value) {                 \
    on_ ## name ## _.Reset(env()->isolate(), value);                           \
  }
  QUIC_JS_CALLBACKS(V)
#undef V

#define V(name)                                                                \
  inline v8::Local<v8::FunctionTemplate> name() const {                        \
    return PersistentToLocal::Strong(name ## _);                               \
  }                                                                            \
  inline void set_## name(v8::Local<v8::FunctionTemplate> value) {             \
    name ## _.Reset(env()->isolate(), value);                                  \
  }
  QUIC_CONSTRUCTORS(V)
#undef V

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_SELF_SIZE(QuicState)
  SET_MEMORY_INFO_NAME(QuicState)

 private:
  struct quic_state_internal {
    // doubles first so that they are always sizeof(double)-aligned
    double quicsessionconfig_buffer[IDX_QUIC_SESSION_CONFIG_COUNT + 1];
    double http3config_buffer[IDX_HTTP3_CONFIG_COUNT + 1];
    QuicSocketConfig quicsocketconfig;
  };

#define V(name, _) v8::Global<v8::Function> on_ ## name ## _;
  QUIC_JS_CALLBACKS(V)
#undef V
#define V(name) v8::Global<v8::FunctionTemplate> name ## _;
  QUIC_CONSTRUCTORS(V)
#undef V
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_QUIC_QUIC_STATE_H_
