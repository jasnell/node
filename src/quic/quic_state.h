#ifndef SRC_QUIC_QUIC_STATE_H_
#define SRC_QUIC_QUIC_STATE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "aliased_buffer.h"

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

enum QuicSessionConfigIndex : int {
  IDX_QUIC_SESSION_ACTIVE_CONNECTION_ID_LIMIT,
  IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL,
  IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE,
  IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI,
  IDX_QUIC_SESSION_MAX_DATA,
  IDX_QUIC_SESSION_MAX_STREAMS_BIDI,
  IDX_QUIC_SESSION_MAX_STREAMS_UNI,
  IDX_QUIC_SESSION_MAX_IDLE_TIMEOUT,
  IDX_QUIC_SESSION_MAX_UDP_PAYLOAD_SIZE,
  IDX_QUIC_SESSION_ACK_DELAY_EXPONENT,
  IDX_QUIC_SESSION_DISABLE_MIGRATION,
  IDX_QUIC_SESSION_MAX_ACK_DELAY,
  IDX_QUIC_SESSION_CC_ALGO,
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
        root_buffer) {
  }

  AliasedUint8Array root_buffer;
  AliasedFloat64Array quicsessionconfig_buffer;
  AliasedFloat64Array http3config_buffer;

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
