#ifndef OPENSSL_NO_QUIC

#include "crypto/crypto_common.h"
#include "crypto/x509.h"
#include "quic/session.h"
#include "quic/endpoint.h"
#include "quic/qlog.h"
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_sockaddr-inl.h"
#include "v8.h"

#include <ngtcp2/ngtcp2_crypto_openssl.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::BackingStore;
using v8::Context;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::PropertyAttribute;
using v8::String;
using v8::Value;

namespace quic {

namespace {
// Forwards detailed(verbose) debugging information from ngtcp2. Enabled using
// the NODE_DEBUG_NATIVE=NGTCP2_DEBUG category.
void Ngtcp2DebugLog(void* user_data, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  std::string format(fmt, strlen(fmt) + 1);
  format[strlen(fmt)] = '\n';
  // Debug() does not work with the va_list here. So we use vfprintf
  // directly instead. Ngtcp2DebugLog is only enabled when the debug
  // category is enabled.
  vfprintf(stderr, format.c_str(), ap);
  va_end(ap);
}

void OnQlogWrite(
    void* user_data,
    uint32_t flags,
    const void* data,
    size_t len) {
  Session* session = static_cast<Session*>(user_data);
  Environment* env = session->env();

  // Fun fact... ngtcp2 does not emit the final qlog statement until the
  // ngtcp2_conn object is destroyed. Ideally, destroying is explicit,
  // but sometimes the Session object can be garbage collected without
  // being explicitly destroyed. During those times, we cannot call out
  // to JavaScript. Because we don't know for sure if we're in in a GC
  // when this is called, it is safer to just defer writes to immediate.
  BaseObjectPtr<QLogStream> ptr = session->qlogstream();
  std::vector<uint8_t> buffer(len);
  memcpy(buffer.data(), data, len);
  env->SetImmediate([ptr = std::move(ptr),
                     buffer = std::move(buffer),
                     flags](Environment*) {
    ptr->Emit(buffer.data(), buffer.size(), flags);
  });
}
}  // namespace

Session::Config::Config(
    Endpoint* endpoint) {
  ngtcp2_settings_default(this);
  initial_ts = uv_hrtime();
  if (UNLIKELY(is_ngtcp2_debug_enabled(endpoint->env())))
    log_printf = Ngtcp2DebugLog;

  auto config = endpoint->config();

  cc_algo = config.cc_algorithm;
  max_udp_payload_size = config.max_payload_size;

  if (config.max_window_override > 0)
    max_window = config.max_window_override;

  if (config.max_stream_window_override > 0)
    max_stream_window = config.max_stream_window_override;

  if (config.unacknowledged_packet_threshold > 0)
    ack_thresh = config.unacknowledged_packet_threshold;
}

void Session::Config::EnableQLog(const CID& ocid) {
  qlog = { *ocid, OnQlogWrite };
}

Session::TransportParams::TransportParams(
    const Options& options,
    const CID& scid,
    const CID& ocid) {
  ngtcp2_transport_params_default(this);
  active_connection_id_limit = options.active_connection_id_limit;
  initial_max_stream_data_bidi_local =
      options.initial_max_stream_data_bidi_local;
  initial_max_stream_data_bidi_remote =
      options.initial_max_stream_data_bidi_remote;
  initial_max_stream_data_uni = options.initial_max_stream_data_uni;
  initial_max_streams_bidi = options.initial_max_streams_bidi;
  initial_max_streams_uni = options.initial_max_streams_uni;
  initial_max_data = options.initial_max_data;
  max_idle_timeout = options.max_idle_timeout;
  max_ack_delay = options.max_ack_delay;
  ack_delay_exponent = options.ack_delay_exponent;
  max_datagram_frame_size = options.max_datagram_frame_size;
  disable_active_migration = options.disable_active_migration ? 1 : 0;
  preferred_address_present = 0;
  stateless_reset_token_present = 0;
  retry_scid_present = 0;

  if (ocid) {
    original_dcid = *ocid;
    if (scid) {
      retry_scid = *scid;
      retry_scid_present = 1;
    }
  } else {
    original_dcid = *scid;
  }

  if (options.preferred_address_ipv4)
    SetPreferredAddress(options.preferred_address_ipv4);

  if (options.preferred_address_ipv6)
    SetPreferredAddress(options.preferred_address_ipv6);
}

void Session::TransportParams::SetPreferredAddress(
    const SocketAddress& address) {
  preferred_address_present = 1;
  switch (address.family()) {
    case AF_INET: {
      const sockaddr_in* src =
          reinterpret_cast<const sockaddr_in*>(address.data());
      memcpy(preferred_address.ipv4_addr,
             &src->sin_addr,
             sizeof(preferred_address.ipv4_addr));
      preferred_address.ipv4_port = address.port();
      break;
    }
    case AF_INET6: {
      const sockaddr_in6* src =
          reinterpret_cast<const sockaddr_in6*>(address.data());
      memcpy(preferred_address.ipv6_addr,
             &src->sin6_addr,
             sizeof(preferred_address.ipv6_addr));
      preferred_address.ipv6_port = address.port();
      break;
    }
    default:
      UNREACHABLE();
  }

}

void Session::TransportParams::GenerateStatelessResetToken(
    Endpoint* endpoint,
    const CID& cid) {
  CHECK(cid);
  stateless_reset_token_present = 1;
  StatelessResetToken token(
    stateless_reset_token,
    endpoint->config().reset_token_secret,
    cid);
}

void Session::TransportParams::GeneratePreferredAddressToken(
    ConnectionIDStrategy connection_id_strategy,
    Endpoint* endpoint,
    CID* pscid) {
  CHECK(pscid);
  connection_id_strategy(endpoint, pscid->cid(), NGTCP2_MAX_CIDLEN);
  preferred_address.cid = **pscid;
  StatelessResetToken(
    preferred_address.stateless_reset_token,
    endpoint->config().reset_token_secret,
    *pscid);
}

template <typename Fn>
void SessionStatsTraits::ToString(const Session& ptr, Fn&& add_field) {
#define V(n, name, label) add_field(label, ptr.GetStat(&SessionStats::name));
  SESSION_STATS(V)
#undef V
}

Session::CryptoContext::CryptoContext(
    Session* session,
    const Options& options,
    ngtcp2_crypto_side side) :
    session_(session),
    secure_context_(options.context),
    side_(side),
    reject_unauthorized_(options.reject_unauthorized),
    enable_tls_trace_(options.enable_tls_trace),
    request_peer_certificate_(options.request_peer_certificate),
    request_ocsp_(options.request_ocsp),
    verify_hostname_identity_(options.verify_hostname_identity) {
  ssl_.reset(SSL_new(secure_context_->ctx_.get()));
  CHECK(ssl_);
  if (side == NGTCP2_CRYPTO_SIDE_CLIENT)
    MaybeSetEarlySession(options);
}

Session::CryptoContext::~CryptoContext() {
  USE(Cancel());
}

void Session::CryptoContext::MaybeSetEarlySession(const Options& options) {
  if (session()->is_server() ||
      options.early_transport_params == nullptr ||
      !options.early_session_ticket) {
    return;
  }

  early_data_ =
      SSL_SESSION_get_max_early_data(options.early_session_ticket.get())
          == 0xffffffffUL;

  if (!early_data)
    return;

  ngtcp2_conn_set_early_remote_transport_params(
      session()->connection(),
      options.early_transport_params);

  // We don't care about the return value here. The early
  // data will just be ignored if it's invalid.
  USE(crypto::SetTLSSession(ssl_, options.early_session_ticket));
}

void Session::CryptoContext::AcknowledgeCryptoData(
    ngtcp2_crypto_level level,
    uint64_t datalen) {
  // It is possible for the QuicSession to have been destroyed but not yet
  // deconstructed. In such cases, we want to ignore the callback as there
  // is nothing to do but wait for further cleanup to happen.
  if (UNLIKELY(session_->is_destroyed()))
    return;
  Debug(session(),
        "Acknowledging %" PRIu64 " crypto bytes for %s level",
        datalen,
        crypto_level_name(level));

  // Consumes (frees) the given number of bytes in the handshake buffer.
  // TODO(@jasnell)
  // handshake_[level].Acknowledge(static_cast<size_t>(datalen));
}

size_t Session::CryptoContext::Cancel() {
  return 0;
  // TODO(@jasnell)
  // size_t len =
  //     handshake_[0].remaining() +
  //     handshake_[1].remaining() +
  //     handshake_[2].remaining();
  // handshake_[0].Clear();
  // handshake_[1].Clear();
  // handshake_[2].Clear();
  // return len;
}

void Session::CryptoContext::Initialize() {
  InitializeTLS(session(), ssl_);
}

void Session::CryptoContext::EnableTrace() {
#if HAVE_SSL_TRACE
  if (!bio_trace_) {
    bio_trace_.reset(BIO_new_fp(stderr,  BIO_NOCLOSE | BIO_FP_TEXT));
    SSL_set_msg_callback(
        ssl_.get(),
        [](int write_p,
           int version,
           int content_type,
           const void* buf,
           size_t len,
           SSL* ssl,
           void* arg) -> void {
        crypto::MarkPopErrorOnReturn mark_pop_error_on_return;
        SSL_trace(write_p,  version, content_type, buf, len, ssl, arg);
    });
    SSL_set_msg_callback_arg(ssl_.get(), bio_trace_.get());
  }
#endif
}

std::shared_ptr<v8::BackingStore>
Session::CryptoContext::ocsp_response() const {
  return ocsp_response_;
}

ngtcp2_crypto_level Session::CryptoContext::read_crypto_level() const {
  return from_ossl_level(SSL_quic_read_level(ssl_.get()));
}

ngtcp2_crypto_level Session::CryptoContext::write_crypto_level() const {
  return from_ossl_level(SSL_quic_write_level(ssl_.get()));
}

void Session::CryptoContext::Keylog(const char* line) {
  Environment* env = session_->env();
  BindingState* state = env->GetBindingData<BindingState>(env->context());

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Session::CallbackScope cb_scope(session());

  Local<Value> line_buf;
  if (!Buffer::Copy(env, line, 1 + strlen(line)).ToLocal(&line_buf))
    return;

  char* data = Buffer::Data(line_buf);
  data[strlen(line)] = '\n';

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(session_);
  USE(state->session_keylog_callback()->Call(
      env->context(),
      session()->object(),
      1,
      &line_buf));
}

int Session::CryptoContext::OnClientHello() {
  if (LIKELY(session_->state_->client_hello_enabled == 0))
    return 0;

  Environment* env = session_->env();
  CallbackScope callback_scope(this);
  if (in_client_hello_)
    return -1;
  in_client_hello_ = true;

  CryptoContext* ctx = session_->crypto_context();

  BindingState* state = env->GetBindingData<BindingState>(env->context());
  HandleScope scope(env->isolate());
  Context::Scope context_scope(env->context());

  // Why this instead of using MakeCallback? We need to catch any
  // errors that happen both when preparing the arguments and
  // invoking the callback so that we can properly signal a failure
  // to the peer.
  Session::CallbackScope cb_scope(session());

  Local<Value> argv[3];

  Session::CryptoContext* crypto_context = session()->crypto_context();

  if (!crypto_context->hello_alpn(env).ToLocal(&argv[0]) ||
      !crypto_context->hello_servername(env).ToLocal(&argv[1]) ||
      !crypto_context->hello_ciphers(env).ToLocal(&argv[2])) {
    return;
  }

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(session());
  USE(state->session_client_hello_callback(env)->Call(
      env->context(),
      session()->object(),
      arraysize(argv),
      argv));

  // Returning -1 here will keep the TLS handshake paused until the
  // client hello callback is invoked. Returning 0 means that the
  // handshake is ready to proceed. When the OnClientHello callback
  // is called above, it may be resolved synchronously or asynchronously.
  // In case it is resolved synchronously, we need the check below.
  return in_client_hello_ ? -1 : 0;
}

void Session::CryptoContext::OnClientHelloDone(
    BaseObjectPtr<crypto::SecureContext> context) {
  Debug(session(),
        "ClientHello completed. Context Provided? %s\n",
        context ? "Yes" : "No");

  // Continue the TLS handshake when this function exits
  // otherwise it will stall and fail.
  HandshakeScope handshake_scope(
      this,
      [this]() { in_client_hello_ = false; });

  // Disable the callback at this point so we don't loop continuously
  session_->state_->client_hello_enabled = 0;

  if (context) {
    int err = crypto::UseSNIContext(ssl_, context);
    if (!err) {
      unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
      return !err ?
          THROW_ERR_QUIC_FAILURE_SETTING_SNI_CONTEXT(session_->env()) :
          crypto::ThrowCryptoError(session_->env(), err);
    }
    secure_context_ = context;
  }
}

int Session::CryptoContext::OnOCSP() {
  if (LIKELY(session_->state_->ocsp_enabled == 0)) {
    Debug(session(), "No OCSPRequest handler registered");
    return 1;
  }

  if (!session_->is_server())
    return 1;

  Debug(session(), "Client is requesting an OCSP Response");
  CallbackScope callback_scope(this);

  // As in node_crypto.cc, this is not an error, but does suspend the
  // handshake to continue when OnOCSP is complete.
  if (in_ocsp_request_)
    return -1;
  in_ocsp_request_ = true;

  Environment* env = session()->env();
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  HandleScope scope(env->isolate());
  Context::Scope context_scope(env->context());
  Session::CallbackScope cb_scope(session());
  BaseObjectPtr<Session> ptr(session());
  USE(state->session_ocsp_request_callback(env)->Call(
      env->context(),
      session()->object(),
      0, nullptr));

  // Returning -1 here means that we are still waiting for the OCSP
  // request to be completed. When the OnCert handler is invoked
  // above, it can be resolve synchronously or asynchonously. If
  // resolved synchronously, we need the check below.
  return in_ocsp_request_ ? -1 : 1;
}

void Session::CryptoContext::OnOCSPDone(
    std::shared_ptr<BackingStore> ocsp_response) {
  Debug(session(), "OCSPRequest completed. Response Provided");
  HandshakeScope handshake_scope(
      this,
      [this]() { in_ocsp_request_ = false; });
  session_->state_->ocsp_enabled = 0;
  ocsp_response_ = std::move(ocsp_response);
}

bool Session::CryptoContext::OnSecrets(
    ngtcp2_crypto_level level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen) {

  Debug(session(),
        "Received secrets for %s crypto level",
        crypto_level_name(level));

  if (!SetSecrets(level, rx_secret, tx_secret, secretlen))
    return false;

  if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
    session_->set_remote_transport_params();
    if (!session()->InitApplication())
      return false;
  }

  return true;
}


int Session::CryptoContext::OnTLSStatus() {
  Environment* env = session_->env();
  HandleScope scope(env->isolate());
  Context::Scope context_scope(env->context());
  switch (side_) {
    case NGTCP2_CRYPTO_SIDE_SERVER: {
      if (!ocsp_response_) {
        Debug(session(), "There is no OCSP response");
        return SSL_TLSEXT_ERR_NOACK;
      }

      size_t len = ocsp_response_->ByteLength();
      Debug(session(), "There is an OCSP response of %d bytes", len);

      unsigned char* data = crypto::MallocOpenSSL<unsigned char>(len);
      memcpy(data, ocsp_response_->Data(), len);

      if (!SSL_set_tlsext_status_ocsp_resp(ssl_.get(), data, len))
        OPENSSL_free(data);

      ocsp_response_.reset();
      return SSL_TLSEXT_ERR_OK;
    }
    case NGTCP2_CRYPTO_SIDE_CLIENT: {
      // Only invoke the callback if the ocsp handler is actually set
      if (LIKELY(session_->state_->ocsp_enabled == 0) || !ocsp_response_)
        return 1;
      Local<Value> res = ArrayBuffer::New(env->isolate(), ocsp_response_);

      BindingState* state = env->GetBindingData<BindingState>(env->context());
      HandleScope scope(env->isolate());
      Context::Scope context_scope(env->context());
      Session::CallbackScope cb_scope(session());
      BaseObjectPtr<Session> ptr(session());
      USE(state->session_ocsp_response_callback(env)->Call(
          env->context(),
          session()->object(),
          1, &res));
      return 1;
    }
    default:
      UNREACHABLE();
  }
}

int Session::CryptoContext::Receive(
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen) {
  if (UNLIKELY(session_->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  // Statistics are collected so we can monitor how long the
  // handshake is taking to operate and complete.
  if (session_->GetStat(&SessionStats::handshake_start_at) == 0)
    session_->RecordTimestamp(&SessionStats::handshake_start_at);
  session_->RecordTimestamp(&SessionStats::handshake_continue_at);

  Debug(session(), "Receiving %d bytes of crypto data", datalen);

  // Internally, this passes the handshake data off to openssl
  // for processing. The handshake may or may not complete.
  int ret = ngtcp2_crypto_read_write_crypto_data(
      session_->connection(),
      crypto_level,
      data,
      datalen);
  switch (ret) {
    case 0:
      return 0;
    // In either of following cases, the handshake is being
    // paused waiting for user code to take action (for instance
    // OCSP requests or client hello modification)
    case NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_X509_LOOKUP:
      Debug(session(), "TLS handshake wants X509 Lookup");
      return 0;
    case NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_CLIENT_HELLO_CB:
      Debug(session(), "TLS handshake wants client hello callback");
      return 0;
    default:
      return ret;
  }
}

MaybeLocal<Object> Session::CryptoContext::cert(Environment* env) const {
  return crypto::X509Certificate::GetCert(env, ssl_);
}

MaybeLocal<Object> Session::CryptoContext::peer_cert(Environment* env) const {
  crypto::X509Certificate::GetPeerCertificateFlag flag = session_->is_server()
      ? crypto::X509Certificate::GetPeerCertificateFlag::SERVER
      : crypto::X509Certificate::GetPeerCertificateFlag::NONE;
  return crypto::X509Certificate::GetPeerCert(env, ssl_, flag);
}

MaybeLocal<Value> Session::CryptoContext::cipher_name(Environment* env) const {
  return crypto::GetCipherName(env, ssl_);
}

MaybeLocal<Value> Session::CryptoContext::cipher_version(
    Environment* env) const {
  return crypto::GetCipherVersion(env, ssl_);
}

MaybeLocal<Object> Session::CryptoContext::ephemeral_key(
    Environment* env) const {
  return crypto::GetEphemeralKey(env, ssl_);
}

MaybeLocal<Array> Session::CryptoContext::hello_ciphers(
    Environment* env) const {
  return crypto::GetClientHelloCiphers(env, ssl_);
}

MaybeLocal<Value> Session::CryptoContext::hello_servername(
    Environment* env) const {
  return OneByteString(env->isolate(), crypto::GetClientHelloServerName(ssl_));
}

MaybeLocal<Value> Session::CryptoContext::hello_alpn(
    Environment* env) const {
  return OneByteString(env->isolate(), crypto::GetClientHelloALPN(ssl_));
}

std::string Session::CryptoContext::servername() const {
  return crypto::GetServerName(ssl_.get());
}

void Session::CryptoContext::set_tls_alert(int err) {
  Debug(session(), "TLS Alert [%d]: %s", err, SSL_alert_type_string_long(err));
  session_->set_last_error(static_cast<uint64_t>(NGTCP2_CRYPTO_ERROR | err));
}

void Session::CryptoContext::WriteHandshake(
    ngtcp2_crypto_level level,
    const uint8_t* data,
    size_t datalen) {
  Debug(session(),
        "Writing %d bytes of %s handshake data.",
        datalen,
        crypto_level_name(level));

  session_->RecordTimestamp(&SessionStats::handshake_send_at);

  std::unique_ptr<BackingStore> store =
      ArrayBuffer::NewBackingStore(
          session()->env()->isolate(),
          datalen);
  memcpy(store->Data(), data, datalen);

  CHECK_EQ(
      ngtcp2_conn_submit_crypto_data(
          session_->connection(),
          level,
          static_cast<uint8_t*>(store->Data()),
          datalen), 0);

  // TODO(@jasnell)
  // handshake_[level].Push(std::move(store), datalen);
}

bool Session::CryptoContext::InitiateKeyUpdate() {
  if (UNLIKELY(session_->is_destroyed()) || in_key_update_)
    return false;

  // There's no user code that should be able to run while UpdateKey
  // is running, but we need to gate on it just to be safe.
  auto leave = OnScopeLeave([this]() { in_key_update_ = false; });
  in_key_update_ = true;
  Debug(session(), "Initiating key update");

  session_->IncrementStat(&SessionStats::keyupdate_count);

  return ngtcp2_conn_initiate_key_update(
      session_->connection(),
      uv_hrtime()) == 0;
}

int Session::CryptoContext::VerifyPeerIdentity() {
  return crypto::VerifyPeerCertificate(ssl_);
}

bool Session::CryptoContext::early_data() const {
  return (early_data_ &&
      SSL_get_early_data_status(ssl_.get()) == SSL_EARLY_DATA_ACCEPTED) ||
      SSL_get_max_early_data(ssl_.get()) == 0xffffffffUL;
}

void Session::CryptoContext::MemoryInfo(MemoryTracker* tracker) const {
  // TODO(@jasnell)
  // tracker->TrackField("initial_crypto", handshake_[0]);
  // tracker->TrackField("handshake_crypto", handshake_[1]);
  // tracker->TrackField("app_crypto", handshake_[2]);
  tracker->TrackFieldWithSize(
      "ocsp_response",
      ocsp_response_ ? ocsp_response_->ByteLength() : 0);
}

bool Session::CryptoContext::SetSecrets(
    ngtcp2_crypto_level level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen) {

  static constexpr int kCryptoKeylen = 64;
  static constexpr int kCryptoIvlen = 64;
  static constexpr char kQuicClientEarlyTrafficSecret[] =
      "QUIC_CLIENT_EARLY_TRAFFIC_SECRET";
  static constexpr char kQuicClientHandshakeTrafficSecret[] =
      "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET";
  static constexpr char kQuicClientTrafficSecret0[] =
      "QUIC_CLIENT_TRAFFIC_SECRET_0";
  static constexpr char kQuicServerHandshakeTrafficSecret[] =
      "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET";
  static constexpr char kQuicServerTrafficSecret[] =
      "QUIC_SERVER_TRAFFIC_SECRET_0";

  uint8_t rx_key[kCryptoKeylen];
  uint8_t rx_hp[kCryptoKeylen];
  uint8_t tx_key[kCryptoKeylen];
  uint8_t tx_hp[kCryptoKeylen];
  uint8_t rx_iv[kCryptoIvlen];
  uint8_t tx_iv[kCryptoIvlen];

  if (NGTCP2_ERR(ngtcp2_crypto_derive_and_install_rx_key(
          session()->connection(),
          rx_key,
          rx_iv,
          rx_hp,
          level,
          rx_secret,
          secretlen))) {
    return false;
  }

  if (NGTCP2_ERR(ngtcp2_crypto_derive_and_install_tx_key(
          session()->connection(),
          tx_key,
          tx_iv,
          tx_hp,
          level,
          tx_secret,
          secretlen))) {
    return false;
  }

  switch (level) {
  case NGTCP2_CRYPTO_LEVEL_EARLY:
    crypto::LogSecret(
        ssl_,
        kQuicClientEarlyTrafficSecret,
        rx_secret,
        secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_HANDSHAKE:
    crypto::LogSecret(
        ssl_,
        kQuicClientHandshakeTrafficSecret,
        rx_secret,
        secretlen);
    crypto::LogSecret(
        ssl_,
        kQuicServerHandshakeTrafficSecret,
        tx_secret,
        secretlen);
    break;
  case NGTCP2_CRYPTO_LEVEL_APPLICATION:
    crypto::LogSecret(
        ssl_,
        kQuicClientTrafficSecret0,
        rx_secret,
        secretlen);
    crypto::LogSecret(
        ssl_,
        kQuicServerTrafficSecret,
        tx_secret,
        secretlen);
    break;
  default:
    UNREACHABLE();
  }

  return true;
}

void Session::IgnorePreferredAddressStrategy(
    Session* session,
    const PreferredAddress& preferred_address) {
  Debug(session, "Ignoring server preferred address");
}

void Session::UsePreferredAddressStrategy(
    Session* session,
    const PreferredAddress& preferred_address) {
  int family = session->endpoint()->local_address().family();
  PreferredAddress::Address address = family == AF_INET
      ? preferred_address.ipv4()
      : preferred_address.ipv6();

  if (!preferred_address.Use(address)) {
    Debug(session, "Not using server preferred address");
    return;
  }

  Debug(session, "Using server preferred address");
  if (UNLIKELY(session->state_->use_preferred_address_enabled == 1))
    session->OnUsePreferredAddress(address);
}

// Generates a new random connection ID.
void Session::RandomConnectionIDStrategy(
    Session* session,
    ngtcp2_cid* cid,
    size_t cidlen) {
  // CID min and max length is determined by the QUIC specification.
  CHECK_LE(cidlen, NGTCP2_MAX_CIDLEN);
  CHECK_GE(cidlen, NGTCP2_MIN_CIDLEN);
  cid->datalen = cidlen;
  // cidlen shouldn't ever be zero here but just in case that
  // behavior changes in ngtcp2 in the future...
  if (LIKELY(cidlen > 0))
    crypto::EntropySource(cid->data, cidlen);
}

Local<FunctionTemplate> Session::GetConstructorTemplate(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  CHECK_NOT_NULL(state);
  Local<FunctionTemplate> tmpl = state->session_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "QuicSession"));
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Session::kInternalFieldCount);
    state->set_session_constructor_template(env, tmpl);
  }
  return tmpl;
}

void Session::Initialize(Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_session_constructor_template(env, GetConstructorTemplate(env));
}

// Static function to create a new server QuicSession instance
BaseObjectPtr<Session> Session::CreateServer(
    Endpoint* endpoint,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Config& config,
    const CID& dcid,
    const CID& scid,
    const CID& ocid,
    uint32_t version) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(endpoint->env());
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(endpoint->env()->context())
          .ToLocal(&obj)) {
    return BaseObjectPtr<Session>();
  }

  return MakeDetachedBaseObject<Session>(
      endpoint,
      obj,
      local_addr,
      remote_addr,
      config,
      endpoint->server_config(),
      dcid,
      scid,
      ocid,
      version);
}

BaseObjectPtr<Session> Session::CreateClient(
    Endpoint* endpoint,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Config& config,
    const Options& options,
    uint32_t version) {
  Local<Object> obj;
  Local<FunctionTemplate> tmpl = GetConstructorTemplate(endpoint->env());
  CHECK(!tmpl.IsEmpty());
  if (!tmpl->InstanceTemplate()->NewInstance(endpoint->env()->context())
          .ToLocal(&obj)) {
    return BaseObjectPtr<Session>();
  }

  return MakeDetachedBaseObject<Session>(
      endpoint,
      obj,
      local_addr,
      remote_addr,
      config,
      options,
      version);
}

Session::Session(
    Endpoint* endpoint,
    v8::Local<v8::Object> object,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Options& options,
    const CID& dcid,
    ngtcp2_crypto_side side)
    : AsyncWrap(endpoint->env(), object, AsyncWrap::PROVIDER_QUICSESSION),
      SessionStatsBase(endpoint->env(), object),
      allocator_(BindingState::GetAllocator(endpoint->env())),
      endpoint_(endpoint),
      state_(endpoint->env()),
      local_address_(local_addr),
      remote_address_(remote_address_),
      application_(SelectApplication(options.alpn)),
      crypto_context_(std::make_unique<CryptoContext>(this, options, side)),
      alpn_(options.alpn),
      hostname_(options.hostname),
      idle_(endpoint->env(), [this]() { OnIdleTimeout(); }),
      retransmit_(endpoint->env(), [this]() { OnRetransmitTimeout(); }),
      dcid_(dcid),
      max_pkt_len_(get_max_pkt_len(remote_addr)),
      preferred_address_strategy_(options.preferred_address_strategy) {
  MakeWeak();

  connection_id_strategy_(this, scid_.cid(), NGTCP2_MAX_CIDLEN);
  ExtendMaxStreamsBidi(DEFAULT_MAX_STREAMS_BIDI);
  ExtendMaxStreamsUni(DEFAULT_MAX_STREAMS_UNI);

  Debug(this, "Initializing session from %s to %s",
        local_address_,
        remote_address_);

  object->DefineOwnProperty(
      env()->context(),
      env()->state_string(),
      state_.GetArrayBuffer(),
      PropertyAttribute::ReadOnly).Check();

  AttachToEndpoint();

  idle_.Unref();
  retransmit_.Unref();
}

Session::Session(
    Endpoint* endpoint,
    Local<Object> object,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Config& config,
    const Options& options,
    const CID& dcid,
    const CID& scid,
    const CID& ocid,
    uint32_t version)
    : Session(
          endpoint,
          object,
          local_addr,
          remote_addr,
          options,
          dcid,
          NGTCP2_CRYPTO_SIDE_SERVER) {
  TransportParams transport_params(options, scid, ocid);
  transport_params.GenerateStatelessResetToken(endpoint, scid_);
  if (transport_params.preferred_address_present) {
    transport_params.GeneratePreferredAddressToken(
        connection_id_strategy_, endpoint, &pscid_);
  }

  Path path(local_addr, remote_addr);

  ngtcp2_conn* conn;
  CHECK_EQ(
      ngtcp2_conn_server_new(
        &conn,
        dcid.cid(),
        scid_.cid(),
        &path,
        version,
        &callbacks[crypto_context_->side()],
        &config,
        &transport_params,
        &allocator_,
        this), 0);
  connection_.reset(conn);
  crypto_context_->Initialize();

  UpdateDataStats();
  UpdateIdleTimer();
}

Session::Session(
    Endpoint* endpoint,
    Local<Object> object,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Config& config,
    const Options& options,
    uint32_t version)
    : Session(endpoint, object, local_addr, remote_addr, options) {
  CID dcid;
  if (options.dcid) {
    dcid = options.dcid;
  } else {
    connection_id_strategy_(this, dcid.cid(), NGTCP2_MAX_CIDLEN);
  }
  CHECK(dcid);

  TransportParams transport_params(options);
  Path path(local_address_, remote_address_);

  ngtcp2_conn* conn;
  CHECK_EQ(
      ngtcp2_conn_client_new(
          &conn,
          dcid.cid(),
          scid_.cid(),
          &path,
          version,
          &callbacks[crypto_context_->side()],
          &config,
          &transport_params,
          &allocator_,
          this), 0);
  connection_.reset(conn);

  crypto_context_->Initialize();

  UpdateIdleTimer();
  UpdateDataStats();
}

Session::~Session() {
  if (qlogstream_) qlogstream_->End();
  idle_.Stop();
  retransmit_.Stop();
  DebugStats();
}

void Session::ExtendMaxStreamsBidi(uint64_t max_streams) {
  state_->max_streams_bidi = max_streams;
}

void Session::ExtendMaxStreamsUni(uint64_t max_streams) {
  state_->max_streams_uni = max_streams;
}

void Session::AttachToEndpoint() {
  CHECK_NOT_NULL(socket);
  Debug(this, "Adding session to %s", endpoint_->diagnostic_name());
   endpoint_->AddSession(scid_, BaseObjectPtr<Session>(this));
  switch (crypto_context_->side()) {
    case NGTCP2_CRYPTO_SIDE_SERVER: {
      endpoint_->AssociateCID(dcid_, scid_);
      endpoint_->AssociateCID(pscid_, scid_);
      break;
    }
    case NGTCP2_CRYPTO_SIDE_CLIENT: {
      std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection()));
      ngtcp2_conn_get_scid(connection(), cids.data());
      for (const ngtcp2_cid& cid : cids)
        endpoint_->AssociateCID(CID(&cid), scid_);
      break;
    }
    default:
      UNREACHABLE();
  }

  std::vector<ngtcp2_cid_token> tokens(
      ngtcp2_conn_get_num_active_dcid(connection()));
  ngtcp2_conn_get_active_dcid(connection(), tokens.data());
  for (const ngtcp2_cid_token& token : tokens) {
    if (token.token_present) {
      endpoint_->AssociateStatelessResetToken(
          StatelessResetToken(token.token),
          BaseObjectPtr<Session>(this));
    }
  }
}

BaseObjectPtr<QLogStream> Session::qlogstream() {
  if (!qlogstream_)
    qlogstream_ = QLogStream::Create(env());
  return qlogstream_;
}

void Session::UpdateIdleTimer() {
  if (state_->closing_timer_enabled)
    return;
  uint64_t now = uv_hrtime();
  uint64_t expiry = ngtcp2_conn_get_idle_expiry(connection());
  // nano to millis
  uint64_t timeout = expiry > now ? (expiry - now) / 1000000ULL : 1;
  if (timeout == 0) timeout = 1;
  Debug(this, "Updating idle timeout to %" PRIu64, timeout);
  idle_.Update(timeout, timeout);
}

void Session::UpdateClosingTimer() {
  if (state_->closing_timer_enabled)
    return;
  state_->closing_timer_enabled = 1;
  uint64_t timeout =
      is_server() ? (ngtcp2_conn_get_pto(connection()) / 1000000ULL) * 3 : 0;
  Debug(this, "Setting closing timeout to %" PRIu64, timeout);
  retransmit_.Stop();
  idle_.Update(timeout, 0);
  idle_.Ref();
}

void Session::UpdateDataStats() {
  if (state_->destroyed)
    return;
  state_->max_data_left = ngtcp2_conn_get_max_data_left(connection());

  ngtcp2_conn_stat stat;
  ngtcp2_conn_get_conn_stat(connection(), &stat);

  SetStat(
      &SessionStats::bytes_in_flight,
      stat.bytes_in_flight);
  SetStat(
      &SessionStats::congestion_recovery_start_ts,
      stat.congestion_recovery_start_ts);
  SetStat(&SessionStats::cwnd, stat.cwnd);
  SetStat(&SessionStats::delivery_rate_sec, stat.delivery_rate_sec);
  SetStat(&SessionStats::first_rtt_sample_ts, stat.first_rtt_sample_ts);
  SetStat(&SessionStats::initial_rtt, stat.initial_rtt);
  SetStat(&SessionStats::last_tx_pkt_ts, stat.last_tx_pkt_ts);
  SetStat(&SessionStats::latest_rtt, stat.latest_rtt);
  SetStat(&SessionStats::loss_detection_timer, stat.loss_detection_timer);
  SetStat(&SessionStats::loss_time, stat.loss_time);
  SetStat(&SessionStats::max_udp_payload_size, stat.max_udp_payload_size);
  SetStat(&SessionStats::min_rtt, stat.min_rtt);
  SetStat(&SessionStats::pto_count, stat.pto_count);
  SetStat(&SessionStats::rttvar, stat.rttvar);
  SetStat(&SessionStats::smoothed_rtt, stat.smoothed_rtt);
  SetStat(&SessionStats::ssthresh, stat.ssthresh);

  // The max_bytes_in_flight is a highwater mark that can be used
  // in performance analysis operations.
  if (stat.bytes_in_flight > GetStat(&SessionStats::max_bytes_in_flight))
    SetStat(&SessionStats::max_bytes_in_flight, stat.bytes_in_flight);
}

bool Session::InitApplication() {
  Debug(this, "Initializing application handler for ALPN %s",
      alpn_.c_str() + 1);
  return application_->Initialize();
}

// Set the transport parameters received from the remote peer
void Session::set_remote_transport_params() {
  DCHECK(!is_destroyed());
  ngtcp2_conn_get_remote_transport_params(connection(), &transport_params_);
  transport_params_set_ = true;
}

bool Session::is_in_closing_period() const {
  return ngtcp2_conn_is_in_closing_period(connection());
}

bool Session::is_in_draining_period() const {
  return ngtcp2_conn_is_in_draining_period(connection());
}

void Session::StartGracefulClose() {
  state_->graceful_closing = 1;
  RecordTimestamp(&SessionStats::closing_at);
}

// Gets the QUIC version negotiated for this QuicSession
uint32_t Session::version() const {
  CHECK(!is_destroyed());
  return ngtcp2_conn_get_negotiated_version(connection());
}

// A client QuicSession can be migrated to a different QuicSocket instance.
bool Session::AttachToNewEndpoint(Endpoint* endpoint, bool nat_rebinding) {
  CHECK(!is_server());
  CHECK(!is_destroyed());

  if (state_->graceful_closing)
    return false;

  if (endpoint == nullptr || endpoint == endpoint_.get())
    return true;

  Debug(this, "Migrating to %s", endpoint_->diagnostic_name());

  // Ensure that we maintain a reference to keep this from being
  // destroyed while we are starting the migration.
  BaseObjectPtr<Session> ptr(this);

  // Step 1: Remove the session from the current socket
  DetachFromEndpoint();

  endpoint_.reset(endpoint);
  // Step 2: Add this Session to the given Socket
  AttachToEndpoint();

  auto local_address = endpoint->local_address();
  endpoint_->ReceiveStart();

  // The nat_rebinding option here should rarely, if ever
  // be used in a real application. It is intended to serve
  // as a way of simulating a silent local address change,
  // such as when the NAT binding changes. Currently, Node.js
  // does not really have an effective way of detecting that.
  // Manual user code intervention to handle the migration
  // to the new QuicSocket is required, which should always
  // trigger path validation using the ngtcp2_conn_initiate_migration.
  if (LIKELY(!nat_rebinding)) {
    SendSessionScope send(this);
    Path path(local_address, remote_address_);
    return ngtcp2_conn_initiate_migration(
        connection(),
        &path,
        uv_hrtime()) == 0;
  } else {
    ngtcp2_addr addr;
    ngtcp2_conn_set_local_addr(
        connection(),
        ngtcp2_addr_init(
            &addr,
            local_address.data(),
            local_address.length(),
            nullptr));
  }

  return true;
}

const ngtcp2_callbacks Session::callbacks[2] = {
  // NGTCP2_CRYPTO_SIDE_CLIENT
  {
    ngtcp2_crypto_client_initial_cb,
    nullptr,
    OnReceiveCryptoData,
    OnHandshakeCompleted,
    OnVersionNegotiation,
    ngtcp2_crypto_encrypt_cb,
    ngtcp2_crypto_decrypt_cb,
    ngtcp2_crypto_hp_mask_cb,
    OnReceiveStreamData,
    OnAckedCryptoOffset,
    OnAckedStreamDataOffset,
    OnStreamOpen,
    OnStreamClose,
    OnStatelessReset,
    ngtcp2_crypto_recv_retry_cb,
    OnExtendMaxStreamsBidi,
    OnExtendMaxStreamsUni,
    OnRand,
    OnGetNewConnectionID,
    OnRemoveConnectionID,
    ngtcp2_crypto_update_key_cb,
    OnPathValidation,
    OnSelectPreferredAddress,
    OnStreamReset,
    OnExtendMaxStreamsRemoteBidi,
    OnExtendMaxStreamsRemoteUni,
    OnExtendMaxStreamData,
    OnConnectionIDStatus,
    OnHandshakeConfirmed,
    nullptr,  // recv_new_token
    ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  },
  // NGTCP2_CRYPTO_SIDE_SERVER
  {
    nullptr,
    ngtcp2_crypto_recv_client_initial_cb,
    OnReceiveCryptoData,
    OnHandshakeCompleted,
    nullptr,  // recv_version_negotiation
    ngtcp2_crypto_encrypt_cb,
    ngtcp2_crypto_decrypt_cb,
    ngtcp2_crypto_hp_mask_cb,
    OnReceiveStreamData,
    OnAckedCryptoOffset,
    OnAckedStreamDataOffset,
    OnStreamOpen,
    OnStreamClose,
    OnStatelessReset,
    nullptr,  // recv_retry
    nullptr,  // extend_max_streams_bidi
    nullptr,  // extend_max_streams_uni
    OnRand,
    OnGetNewConnectionID,
    OnRemoveConnectionID,
    ngtcp2_crypto_update_key_cb,
    OnPathValidation,
    nullptr,  // select_preferred_addr
    OnStreamReset,
    OnExtendMaxStreamsRemoteBidi,
    OnExtendMaxStreamsRemoteUni,
    OnExtendMaxStreamData,
    OnConnectionIDStatus,
    nullptr,  // handshake_confirmed
    nullptr,  // recv_new_token
    ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  }
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
