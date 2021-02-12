#ifndef OPENSSL_NO_QUIC

#include "quic/buffer.h"
#include "quic/crypto.h"
#include "quic/endpoint.h"
#include "quic/qlog.h"
#include "quic/quic.h"
#include "quic/session.h"
#include "quic/stream.h"
#include "crypto/crypto_common.h"
#include "crypto/x509.h"
#include "aliased_struct-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "debug_utils-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_bob-inl.h"
#include "node_http_common-inl.h"
#include "node_process.h"
#include "node_sockaddr-inl.h"
#include "v8.h"

#include <ngtcp2/ngtcp2_crypto_openssl.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::BackingStore;
using v8::BigInt;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Int32;
using v8::Integer;
using v8::Just;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Nothing;
using v8::Number;
using v8::Object;
using v8::PropertyAttribute;
using v8::String;
using v8::Undefined;
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

ConnectionCloseFn SelectCloseFn(QuicError error) {
  switch (error.type) {
    case QuicError::Type::TRANSPORT:
      return ngtcp2_conn_write_connection_close;
    case QuicError::Type::APPLICATION:
      return ngtcp2_conn_write_application_close;
    default:
      UNREACHABLE();
  }
}

void Consume(ngtcp2_vec** pvec, size_t* pcnt, size_t len) {
  ngtcp2_vec* v = *pvec;
  size_t cnt = *pcnt;

  for (; cnt > 0; --cnt, ++v) {
    if (v->len > len) {
      v->len -= len;
      v->base += len;
      break;
    }
    len -= v->len;
  }

  *pvec = v;
  *pcnt = cnt;
}

int IsEmpty(const ngtcp2_vec* vec, size_t cnt) {
  size_t i;
  for (i = 0; i < cnt && vec[i].len == 0; ++i) {}
  return i == cnt;
}

template <typename T>
size_t get_length(const T* vec, size_t count) {
  CHECK_NOT_NULL(vec);
  size_t len = 0;
  for (size_t n = 0; n < count; n++)
    len += vec[n].len;
  return len;
}
}  // namespace

Session::Config::Config(
    Endpoint* endpoint,
    const CID& dcid_,
    const CID& scid_,
    uint32_t version_)
    : version(version_),
      dcid(dcid_),
      scid(scid_) {
  ngtcp2_settings_default(this);
  initial_ts = uv_hrtime();
  if (UNLIKELY(is_ngtcp2_debug_enabled(endpoint->env())))
    log_printf = Ngtcp2DebugLog;

  Endpoint::Config config = endpoint->config();

  cc_algo = config.cc_algorithm;
  max_udp_payload_size = config.max_payload_size;

  if (config.max_window_override > 0)
    max_window = config.max_window_override;

  if (config.max_stream_window_override > 0)
    max_stream_window = config.max_stream_window_override;

  if (config.unacknowledged_packet_threshold > 0)
    ack_thresh = config.unacknowledged_packet_threshold;
}

Session::Config::Config(Endpoint* endpoint, uint32_t version)
    : Config(endpoint, CID(), CID(), version) {}

void Session::Config::EnableQLog(const CID& ocid) {
  qlog = { *ocid, OnQlogWrite };
  this->ocid = ocid;
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
    EndpointWrap* endpoint,
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
    Session* session,
    CID* pscid) {
  CHECK(pscid);
  connection_id_strategy(session, pscid->cid(), NGTCP2_MAX_CIDLEN);
  preferred_address.cid = **pscid;
  StatelessResetToken(
    preferred_address.stateless_reset_token,
    session->endpoint()->config().reset_token_secret,
    *pscid);
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
  crypto::SSLSessionPointer ticket(options.early_session_ticket);

  if (session()->is_server() ||
      options.early_transport_params == nullptr ||
      !ticket) {
    return;
  }

  early_data_ =
      SSL_SESSION_get_max_early_data(ticket.get()) == 0xffffffffUL;

  if (!early_data())
    return;

  ngtcp2_conn_set_early_remote_transport_params(
      session()->connection(),
      options.early_transport_params);

  // We don't care about the return value here. The early
  // data will just be ignored if it's invalid.
  USE(crypto::SetTLSSession(ssl_, ticket));
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
  handshake_[level].Acknowledge(static_cast<size_t>(datalen));
}

size_t Session::CryptoContext::Cancel() {
  size_t len =
      handshake_[0].remaining() +
      handshake_[1].remaining() +
      handshake_[2].remaining();
  handshake_[0].Clear();
  handshake_[1].Clear();
  handshake_[2].Clear();
  return len;
}

void Session::CryptoContext::Initialize() {
  InitializeTLS(session(), ssl_);
}

void Session::CryptoContext::EnableTrace() {
#if HAVE_SSL_TRACE
  if (!bio_trace_) {
    bio_trace_.reset(BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT));
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

std::shared_ptr<BackingStore> Session::CryptoContext::ocsp_response(
    bool release) {
  return LIKELY(release) ? std::move(ocsp_response_) : ocsp_response_;
}

std::string Session::CryptoContext::selected_alpn() const {
  const unsigned char* alpn_buf = nullptr;
  unsigned int alpnlen;
  SSL_get0_alpn_selected(ssl_.get(), &alpn_buf, &alpnlen);
  return alpnlen ?
      std::string(reinterpret_cast<const char*>(alpn_buf), alpnlen) :
      std::string();
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

  size_t len = strlen(line);
  if (len == 0) return;

  std::shared_ptr<BackingStore> buf =
      ArrayBuffer::NewBackingStore(env->isolate(), 1 + strlen(line));
  memcpy(buf->Data(), line, len);
  (reinterpret_cast<char*>(buf->Data()))[len] = '\n';

  Local<Value> ab = ArrayBuffer::New(env->isolate(), buf);

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(session_);
  USE(state->session_keylog_callback(env)->Call(
      env->context(),
      session()->object(),
      1, &ab));
}

int Session::CryptoContext::OnClientHello() {
  if (LIKELY(session_->state_->client_hello_enabled == 0))
    return 0;

  Environment* env = session_->env();
  CallbackScope callback_scope(this);
  if (in_client_hello_)
    return -1;
  in_client_hello_ = true;

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
    return 0;
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

void Session::CryptoContext::ResumeHandshake() {
  Receive(read_crypto_level(), 0, nullptr, 0);
  session_->SendPendingData();
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
  session_->set_last_error({
      QuicError::Type::TRANSPORT,
      static_cast<uint64_t>(NGTCP2_CRYPTO_ERROR | err)
    });
}

void Session::CryptoContext::WriteHandshake(
    ngtcp2_crypto_level level,
    const uint8_t* data,
    size_t datalen) {
  Debug(session(),
        "Writing %d bytes of %s handshake data.",
        datalen,
        crypto_level_name(level));

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

  handshake_[level].Push(std::move(store), datalen);
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
  tracker->TrackField("initial_crypto", handshake_[0]);
  tracker->TrackField("handshake_crypto", handshake_[1]);
  tracker->TrackField("app_crypto", handshake_[2]);
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
    session->UsePreferredAddress(address);
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

bool Session::HasInstance(Environment* env, v8::Local<v8::Value> value) {
  return GetConstructorTemplate(env)->HasInstance(value);
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
    env->SetProtoMethodNoSideEffect(
        tmpl,
        "getRemoteAddress",
        GetRemoteAddress);
    env->SetProtoMethodNoSideEffect(
        tmpl,
        "getCertificate",
        GetCertificate);
    env->SetProtoMethodNoSideEffect(
        tmpl,
        "getPeerCertificate",
        GetPeerCertificate);
    env->SetProtoMethodNoSideEffect(
        tmpl,
        "getEphemeralKeyInfo",
        GetEphemeralKeyInfo);
    env->SetProtoMethod(tmpl, "destroy", DoDestroy);
    env->SetProtoMethod(tmpl, "gracefulClose", GracefulClose);
    env->SetProtoMethod(tmpl, "silentClose", SilentClose);
    env->SetProtoMethod(tmpl, "updateKey", UpdateKey);
    env->SetProtoMethod(tmpl, "attachToEndpoint", DoAttachToEndpoint);
    env->SetProtoMethod(tmpl, "detachFromEndpoint", DoDetachFromEndpoint);
    env->SetProtoMethod(tmpl, "onClientHelloDone", OnClientHelloDone);
    env->SetProtoMethod(tmpl, "onOCSPDone", OnOCSPDone);
    state->set_session_constructor_template(env, tmpl);
  }
  return tmpl;
}

void Session::Initialize(Environment* env, Local<Object> target) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  state->set_session_constructor_template(env, GetConstructorTemplate(env));

  OptionsObject::Initialize(env, target);

#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATS_SESSION_##name);
  SESSION_STATS(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATS_SESSION_COUNT);
#undef V
#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATE_SESSION_##name);
  SESSION_STATE(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATE_SESSION_COUNT);
#undef V
}

BaseObjectPtr<Session> Session::CreateClient(
    EndpointWrap* endpoint,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Config& config,
    const Options& options) {
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
      config.version);
}

// Static function to create a new server QuicSession instance
BaseObjectPtr<Session> Session::CreateServer(
    EndpointWrap* endpoint,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Config& config,
    const Options& options) {
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
      config.dcid,
      config.scid,
      config.ocid,
      config.version);
}

Session::Session(
    EndpointWrap* endpoint,
    v8::Local<v8::Object> object,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr,
    const Options& options,
    const CID& dcid,
    ngtcp2_crypto_side side)
    : AsyncWrap(endpoint->env(), object, AsyncWrap::PROVIDER_QUICSESSION),
      SessionStatsBase(endpoint->env()),
      allocator_(BindingState::GetAllocator(endpoint->env())),
      endpoint_(endpoint),
      state_(endpoint->env()),
      local_address_(local_addr),
      remote_address_(remote_addr),
      alpn_(options.alpn),
      application_(SelectApplication(Application::Config())),
      crypto_context_(std::make_unique<CryptoContext>(this, options, side)),
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

  object->DefineOwnProperty(
      env()->context(),
      env()->stats_string(),
      ToBigUint64Array(env()),
      PropertyAttribute::ReadOnly).Check();

  AttachToEndpoint();

  idle_.Unref();
  retransmit_.Unref();
}

Session::Session(
    EndpointWrap* endpoint,
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
        connection_id_strategy_, this, &pscid_);
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
    EndpointWrap* endpoint,
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
  DebugStats(this);
}

void Session::AckedStreamDataOffset(
    stream_id id,
    uint64_t offset,
    uint64_t datalen) {
  Debug(this,
        "Received acknowledgement for %" PRIu64
        " bytes of stream %" PRId64 " data",
        datalen, id);

  application_->AcknowledgeStreamData(
      id,
      offset,
      static_cast<size_t>(datalen));
}

void Session::AddStream(const BaseObjectPtr<Stream>& stream) {
  Debug(this, "Adding stream %" PRId64 " to session", stream->id());
  streams_.emplace(stream->id(), stream);
  stream->Resume();

  // Update tracking statistics for the number of streams associated with
  // this session.
  switch (stream->origin()) {
    case Stream::Origin::CLIENT:
      if (is_server())
        IncrementStat(&SessionStats::streams_in_count);
      else
        IncrementStat(&SessionStats::streams_out_count);
      break;
    case Stream::Origin::SERVER:
      if (is_server())
        IncrementStat(&SessionStats::streams_out_count);
      else
        IncrementStat(&SessionStats::streams_in_count);
  }
  IncrementStat(&SessionStats::streams_out_count);
  switch (stream->direction()) {
    case Stream::Direction::BIDIRECTIONAL:
      IncrementStat(&SessionStats::bidi_stream_count);
      break;
    case Stream::Direction::UNIDIRECTIONAL:
      IncrementStat(&SessionStats::uni_stream_count);
      break;
  }
}

void Session::AttachToEndpoint() {
  CHECK(endpoint_);
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

// A client QuicSession can be migrated to a different QuicSocket instance.
bool Session::AttachToNewEndpoint(EndpointWrap* endpoint, bool nat_rebinding) {
  CHECK(!is_server());
  CHECK(!is_destroyed());

  // If we're in the process of gracefully closing, attaching the session
  // to a new endpoint is not allowed.
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

void Session::Close(SessionCloseFlags close_flags) {
  if (is_destroyed())
    return;
  bool silent = close_flags == SessionCloseFlags::SILENT;
  bool stateless_reset = silent && state_->stateless_reset;

  // If we're not running within a ngtcp2 callback scope, schedule
  // a CONNECTION_CLOSE to be sent when Close exits. If we are
  // within a ngtcp2 callback scope, sending the CONNECTION_CLOSE
  // will be deferred.
  ConnectionCloseScope close_scope(this, silent);

  // Once Close has been called, we cannot re-enter
  if (UNLIKELY(state_->closing))
    return;

  state_->closing = 1;
  state_->silent_close = silent ? 1 : 0;

  QuicError error = last_error();
  Debug(this, "Closing with code %" PRIu64
              " (family: %s, silent: %s, stateless reset: %s)",
        error.code,
        QuicError::TypeName(error),
        silent ? "Y" : "N",
        stateless_reset ? "Y" : "N");

  if (!state_->wrapped)
    return Destroy();

  // If the Session has been wrapped by a JS object, we have to
  // notify the JavaScript side that the session is being closed.
  // If it hasn't yet been wrapped, we can skip the call and and
  // go straight to destroy.
  BaseObjectPtr<Session> ptr(this);

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env() ->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(error.code)),
    Integer::New(env()->isolate(), static_cast<int32_t>(error.type)),
    silent
        ? v8::True(env()->isolate())
        : v8::False(env()->isolate()),
    stateless_reset
        ? v8::True(env()->isolate())
        : v8::False(env()->isolate())
  };

  USE(state->session_close_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));
}

BaseObjectPtr<Stream> Session::CreateStream(stream_id id) {
  CHECK(!is_destroyed());
  CHECK_EQ(state_->graceful_closing, 0);
  CHECK_EQ(state_->closing, 0);

  BaseObjectPtr<Stream> stream = Stream::Create(env(), this, id);
  CHECK(stream);

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
    stream->object(),
    Number::New(env()->isolate(), static_cast<double>(stream->id()))
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(this);

  USE(state->stream_ready_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));

  return stream;
}

void Session::Datagram(
    uint32_t flags,
    const uint8_t* data,
    size_t datalen) {
  if (LIKELY(state_->datagram_enabled == 0) || UNLIKELY(datalen == 0))
    return;

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  std::shared_ptr<BackingStore> store =
      ArrayBuffer::NewBackingStore(env()->isolate(), datalen);
  if (!store)
    return;
  memcpy(store->Data(), data, datalen);

  Local<Value> argv[] = {
    ArrayBuffer::New(env()->isolate(), store),
    flags & NGTCP2_DATAGRAM_FLAG_EARLY
       ? v8::True(env()->isolate())
       : v8::False(env()->isolate())
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(this);

  USE(state->session_datagram_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));
}

void Session::Destroy() {
  if (is_destroyed())
    return;

  Debug(this, "Destroying the QuicSession");

  // Mark the session destroyed.
  state_->destroyed = 1;
  state_->closing = 0;
  state_->graceful_closing = 0;

  // TODO(@jasnell): Allow overriding the close code

  // If we're not already in a ConnectionCloseScope, schedule
  // sending a CONNECTION_CLOSE when destroy exits. If we are
  // running within an ngtcp2 callback scope, sending the
  // CONNECTION_CLOSE will be deferred.
  ConnectionCloseScope close_scope(this, state_->silent_close);

  // All existing streams should have already been destroyed
  CHECK(streams_.empty());

  // Stop and free the idle and retransmission timers if they are active.
  idle_.Stop();
  retransmit_.Stop();

  // The Session instances are kept alive usingBaseObjectPtr. The
  // only persistent BaseObjectPtr is the map in the associated
  // Endpoint. Removing the Session from the Endpoint will free
  // that pointer, allowing the Session to be deconstructed once
  // the stack unwinds and any remaining BaseObjectPtr<Session>
  // instances fall out of scope.
  DetachFromEndpoint();
}

void Session::DetachFromEndpoint() {
  CHECK(endpoint_);
  Debug(this, "Removing Session from %s", endpoint_->diagnostic_name());
  if (is_server()) {
    endpoint_->DisassociateCID(dcid_);
    endpoint_->DisassociateCID(pscid_);
  }

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(connection()));
  std::vector<ngtcp2_cid_token> tokens(
      ngtcp2_conn_get_num_active_dcid(connection()));
  ngtcp2_conn_get_scid(connection(), cids.data());
  ngtcp2_conn_get_active_dcid(connection(), tokens.data());

  for (const ngtcp2_cid& cid : cids)
    endpoint_->DisassociateCID(CID(&cid));

  for (const ngtcp2_cid_token& token : tokens) {
    if (token.token_present) {
      endpoint_->DisassociateStatelessResetToken(
          StatelessResetToken(token.token));
    }
  }

  Debug(this, "Removed from the endpoint");
  BaseObjectPtr<EndpointWrap> endpoint = std::move(endpoint_);
  endpoint->RemoveSession(scid_, remote_address_);
}

void Session::ExtendMaxStreamData(stream_id id, uint64_t max_data) {
  Debug(this,
        "Extending max stream %" PRId64 " data to %" PRIu64, id, max_data);
  application_->ExtendMaxStreamData(id, max_data);
}

void Session::ExtendMaxStreamsBidi(uint64_t max_streams) {
  state_->max_streams_bidi = max_streams;
}

void Session::ExtendMaxStreamsRemoteUni(uint64_t max_streams) {
  Debug(this, "Extend remote max unidirectional streams: %" PRIu64,
        max_streams);
  application_->ExtendMaxStreamsRemoteUni(max_streams);
}

void Session::ExtendMaxStreamsRemoteBidi(uint64_t max_streams) {
  Debug(this, "Extend remote max bidirectional streams: %" PRIu64, max_streams);
  application_->ExtendMaxStreamsRemoteBidi(max_streams);
}

void Session::ExtendMaxStreamsUni(uint64_t max_streams) {
  state_->max_streams_uni = max_streams;
}

void Session::ExtendOffset(size_t amount) {
  Debug(this, "Extending session offset by %" PRId64 " bytes", amount);
  ngtcp2_conn_extend_max_offset(connection(), amount);
}

void Session::ExtendStreamOffset(stream_id id, size_t amount) {
  Debug(this, "Extending max stream %" PRId64 " offset by %" PRId64 " bytes",
        id, amount);
  ngtcp2_conn_extend_max_stream_offset(connection(), id, amount);
}

BaseObjectPtr<Stream> Session::FindStream(stream_id id) const {
  auto it = streams_.find(id);
  return it == std::end(streams_) ? BaseObjectPtr<Stream>() : it->second;
}

void Session::GetConnectionCloseInfo() {
  ngtcp2_connection_close_error_code close_code;
  ngtcp2_conn_get_connection_close_error_code(connection(), &close_code);
  set_last_error(QuicError::FromNgtcp2(close_code));
}

void Session::GetLocalTransportParams(ngtcp2_transport_params* params) {
  CHECK(!is_destroyed());
  ngtcp2_conn_get_local_transport_params(connection(), params);
}

void Session::GetNewConnectionID(
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen) {
  CHECK_NOT_NULL(connection_id_strategy_);
  connection_id_strategy_(this, cid, cidlen);
  CID cid_(cid);
  StatelessResetToken(
      token,
      endpoint_->config().reset_token_secret,
      cid_);
  endpoint_->AssociateCID(cid_, scid_);
}

SessionTicketAppData::Status Session::GetSessionTicketAppData(
    const SessionTicketAppData& app_data,
    SessionTicketAppData::Flag flag) {
  return application_->GetSessionTicketAppData(app_data, flag);
}

void Session::HandleError() {
  if (is_destroyed())
    return;

  // If the Session is a server, send a CONNECTION_CLOSE. In either
  // case, the closing timer will be set and the QuicSession will be
  // destroyed.
  if (is_server())
    SendConnectionClose();
  else
    UpdateClosingTimer();
}

void Session::HandshakeCompleted() {
  RemoteTransportParamsDebug transport_params(this);
  Debug(this, "Handshake is completed. %s", transport_params);
  RecordTimestamp(&SessionStats::handshake_completed_at);
  if (is_server()) HandshakeConfirmed();

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
    Undefined(env()->isolate()),                   // Server name
    GetALPNProtocol(*this),                        // ALPN
    Undefined(env()->isolate()),                   // Cipher name
    Undefined(env()->isolate()),                   // Cipher version
    Integer::New(env()->isolate(), max_pkt_len_),  // Max packet length
    Undefined(env()->isolate()),                   // Validation error reason
    Undefined(env()->isolate()),                   // Validation error code
    crypto_context_->early_data() ?
        v8::True(env()->isolate()) :
        v8::False(env()->isolate())
  };

  std::string hostname = crypto_context_->servername();
  if (!ToV8Value(env()->context(), hostname).ToLocal(&argv[0]))
    return;

  if (!crypto_context_->cipher_name(env()).ToLocal(&argv[2]) ||
      !crypto_context_->cipher_version(env()).ToLocal(&argv[3])) {
    return;
  }

  int err = crypto_context_->VerifyPeerIdentity();
  if (err != X509_V_OK &&
      (!crypto::GetValidationErrorReason(env(), err).ToLocal(&argv[5]) ||
       !crypto::GetValidationErrorCode(env(), err).ToLocal(&argv[6]))) {
      return;
  }

  BaseObjectPtr<Session> ptr(this);

  USE(state->session_handshake_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));
}

void Session::HandshakeConfirmed() {
  Debug(this, "Handshake is confirmed");
  RecordTimestamp(&SessionStats::handshake_confirmed_at);
  state_->handshake_confirmed = 1;
}

bool Session::HasStream(stream_id id) const {
  return streams_.find(id) != std::end(streams_);
}

bool Session::InitApplication() {
  Debug(this, "Initializing application handler for ALPN %s",
      alpn_.c_str() + 1);
  return application_->Initialize();
}

void Session::OnIdleTimeout() {
  if (!is_destroyed()) {
    if (state_->idle_timeout == 1) {
      Debug(this, "Idle timeout");
      Close(SessionCloseFlags::SILENT);
      return;
    }
    state_->idle_timeout = 1;
    UpdateClosingTimer();
  }
}

void Session::OnRetransmitTimeout() {
  if (is_destroyed()) return;
  uint64_t now = uv_hrtime();

  if (ngtcp2_conn_get_expiry(connection()) <= now) {
    Debug(this, "Retransmitting due to loss detection");
    IncrementStat(&SessionStats::loss_retransmit_count);
  }

  if (ngtcp2_conn_handle_expiry(connection(), now) != 0) {
    Debug(this, "Handling retransmission failed");
    HandleError();
  }

  SendPendingData();
}

Maybe<stream_id> Session::OpenStream(Stream::Direction direction) {
  DCHECK(!is_destroyed());
  DCHECK(!is_closing());
  DCHECK(!is_graceful_closing());
  stream_id id;
  switch (direction) {
    case Stream::Direction::BIDIRECTIONAL:
      if (ngtcp2_conn_open_bidi_stream(connection(), &id, nullptr) == 0)
        return Just(id);
      break;
    case Stream::Direction::UNIDIRECTIONAL:
      if (ngtcp2_conn_open_uni_stream(connection(), &id, nullptr) == 0)
        return Just(id);
      break;
    default:
      UNREACHABLE();
  }
  return Nothing<stream_id>();
}

void Session::PathValidation(
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res) {
  if (LIKELY(state_->path_validated_enabled == 0))
    return;

  // This is a fairly expensive operation because both the local and
  // remote addresses have to converted into JavaScript objects. We
  // only do this if a pathValidation handler is registered.
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
    Integer::New(env()->isolate(), res),
    AddressToJS(env(), reinterpret_cast<const sockaddr*>(path->local.addr)),
    AddressToJS(env(), reinterpret_cast<const sockaddr*>(path->remote.addr))
  };

  BaseObjectPtr<Session> ptr(this);

  USE(state->session_path_validation_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));
}

bool Session::Receive(
    size_t nread,
    std::shared_ptr<v8::BackingStore> store,
    const SocketAddress& local_addr,
    const SocketAddress& remote_addr) {

  CHECK(!is_destroyed());

  Debug(this, "Receiving QUIC packet");
  IncrementStat(&SessionStats::bytes_received, nread);

  if (is_in_closing_period() && is_server()) {
    Debug(this, "Packet received while in closing period");
    IncrementConnectionCloseAttempts();
    // For server QuicSession instances, we serialize the connection close
    // packet once but may sent it multiple times. If the client keeps
    // transmitting, then the connection close may have gotten lost.
    // We don't want to send the connection close in response to
    // every received packet, however, so we use an exponential
    // backoff, increasing the ratio of packets received to connection
    // close frame sent with every one we send.
    if (UNLIKELY(ShouldAttemptConnectionClose() &&
                 !SendConnectionClose())) {
      Debug(this, "Failure sending another connection close");
      return false;
    }
  }

  {
    // These are within a scope to ensure that the InternalCallbackScope
    // and HandleScope are both exited before continuing on with the
    // function. This allows any nextTicks and queued tasks to be processed
    // before we continue.
    auto update_stats = OnScopeLeave([&](){
      UpdateDataStats();
    });
    HandleScope handle_scope(env()->isolate());
    InternalCallbackScope callback_scope(this);
    remote_address_ = remote_addr;
    Path path(local_addr, remote_address_);
    uint8_t* data = static_cast<uint8_t*>(store->Data());
    if (!ReceivePacket(&path, data, nread)) {
      HandleError();
      return false;
    }
  }

  // Only send pending data if we haven't entered draining mode.
  // We enter the draining period when a CONNECTION_CLOSE has been
  // received from the remote peer.
  if (is_in_draining_period()) {
    Debug(this, "In draining period after processing packet");
    // If processing the packet puts us into draining period, there's
    // absolutely nothing left for us to do except silently close
    // and destroy this QuicSession, which we do by updating the
    // closing timer.
    GetConnectionCloseInfo();
    UpdateClosingTimer();
    return true;
  }

  if (!is_destroyed())
    UpdateIdleTimer();
  SendPendingData();
  Debug(this, "Successfully processed received packet");
  return true;
}

bool Session::ReceivePacket(
    ngtcp2_path* path,
    const uint8_t* data,
    ssize_t nread) {
  CHECK(!is_destroyed());

  uint64_t now = uv_hrtime();
  SetStat(&SessionStats::received_at, now);
  int err = ngtcp2_conn_read_pkt(connection(), path, nullptr, data, nread, now);
  if (err < 0) {
    switch (err) {
      case NGTCP2_ERR_CALLBACK_FAILURE:
      case NGTCP2_ERR_DRAINING:
      case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
        break;
      case NGTCP2_ERR_RETRY:
        // This should only ever happen on the server
        CHECK(is_server());
        endpoint_->SendRetry(
            version(),
            scid_,
            dcid_,
            local_address_,
            remote_address_);
        // Fall through
      case NGTCP2_ERR_DROP_CONN:
        Close(SessionCloseFlags::SILENT);
        break;
      default:
        set_last_error({
          QuicError::Type::APPLICATION,
          ngtcp2_err_infer_quic_transport_error_code(err)
        });
        return false;
    }
  }

  // If the QuicSession has been destroyed but it is not
  // in the closing period, a CONNECTION_CLOSE has not yet
  // been sent to the peer. Let's attempt to send one. This
  // will have the effect of setting the idle timer to the
  // closing/draining period, after which the QuicSession
  // will be destroyed.
  if (is_destroyed() && !is_in_closing_period()) {
    Debug(this, "Session was destroyed while processing the packet");
    return SendConnectionClose();
  }

  return true;
}

bool Session::ReceiveStreamData(
    uint32_t flags,
    stream_id id,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {
  auto leave = OnScopeLeave([&]() {
    // Unconditionally extend the flow control window for the entire
    // session but not for the individual Stream.
    ExtendOffset(datalen);
  });

  return application_->ReceiveStreamData(
      flags,
      id,
      data,
      datalen,
      offset);
}

void Session::ResumeStream(stream_id id) {
  application()->ResumeStream(id);
}

void Session::SelectPreferredAddress(
    const PreferredAddress& preferred_address) {
  CHECK(!is_server());
  preferred_address_strategy_(this, preferred_address);
}

bool Session::SendConnectionClose() {
  CHECK(!NgCallbackScope::InNgCallbackScope(this));

  // Do not send any frames at all if we're in the draining period
  // or in the middle of a silent close
  if (is_in_draining_period() || state_->silent_close)
    return true;

  // The specific handling of connection close varies for client
  // and server QuicSession instances. For servers, we will
  // serialize the connection close once but may end up transmitting
  // it multiple times; whereas for clients, we will serialize it
  // once and send once only.
  QuicError error = last_error();
  Debug(this, "Sending connection close with code: %" PRIu64 " (family: %s)",
        error.code, QuicError::TypeName(error));

  UpdateClosingTimer();

  // If initial keys have not yet been installed, use the alternative
  // ImmediateConnectionClose to send a stateless connection close to
  // the peer.
  if (crypto_context()->write_crypto_level() ==
        NGTCP2_CRYPTO_LEVEL_INITIAL) {
    endpoint_->ImmediateConnectionClose(
        version(),
        dcid(),
        scid_,
        local_address_,
        remote_address_,
        error.code);
    return true;
  }

  switch (crypto_context_->side()) {
    case NGTCP2_CRYPTO_SIDE_SERVER: {
      if (!is_in_closing_period() && !StartClosingPeriod()) {
        Close(SessionCloseFlags::SILENT);
        return false;
      }
      CHECK_GT(conn_closebuf_->length(), 0);
      return SendPacket(Packet::Copy(conn_closebuf_));
    }
    case NGTCP2_CRYPTO_SIDE_CLIENT: {
      std::unique_ptr<Packet> packet =
          std::make_unique<Packet>("client connection close");
      ssize_t nwrite =
          SelectCloseFn(error)(
            connection(),
            nullptr,
            nullptr,
            packet->data(),
            max_pkt_len_,
            error.code,
            uv_hrtime());
      if (UNLIKELY(nwrite < 0)) {
        Debug(this, "Error writing connection close: %d", nwrite);
        set_last_error(kQuicInternalError);
        Close(SessionCloseFlags::SILENT);
        return false;
      }
      packet->set_length(nwrite);
      return SendPacket(std::move(packet));
    }
    default:
      UNREACHABLE();
  }
}

bool Session::SendPacket(std::unique_ptr<Packet> packet) {
  CHECK(!is_in_draining_period());

  // There's nothing to send.
  if (!packet || packet->length() == 0)
    return true;

  IncrementStat(&SessionStats::bytes_sent, packet->length());
  RecordTimestamp(&SessionStats::sent_at);
  ScheduleRetransmit();

  Debug(this, "Sending %" PRIu64 " bytes to %s from %s",
        packet->length(),
        remote_address_,
        local_address_);

  endpoint_->SendPacket(
      local_address_,
      remote_address_,
      std::move(packet),
      BaseObjectPtr<Session>(this));

  return true;
}

bool Session::SendPacket(
    std::unique_ptr<Packet> packet,
    const ngtcp2_path_storage& path) {
  UpdateEndpoint(path.path);
  return SendPacket(std::move(packet));
}

void Session::SendPendingData() {
  if (is_unable_to_send_packets())
    return;

  Debug(this, "Sending pending data");
  if (!application_->SendPendingData()) {
    Debug(this, "Error sending pending application data");
    HandleError();
  }
  ScheduleRetransmit();
}

void Session::SetSessionTicketAppData(const SessionTicketAppData& app_data) {
  application_->SetSessionTicketAppData(app_data);
}

void Session::StreamDataBlocked(stream_id id) {
  IncrementStat(&SessionStats::block_count);

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());

  HandleScope handle_scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  BaseObjectPtr<Stream> stream = FindStream(id);
  USE(state->stream_blocked_callback(env())->Call(
      env()->context(),
      object(),
      0, nullptr));
}

void Session::IncrementConnectionCloseAttempts() {
  if (connection_close_attempts_ < kMaxSizeT)
    connection_close_attempts_++;
}

void Session::RemoveStream(stream_id id) {
  Debug(this, "Removing stream %" PRId64, id);

  // ngtcp2 does not extend the max streams count automatically
  // except in very specific conditions, none of which apply
  // once we've gotten this far. We need to manually extend when
  // a remote peer initiated stream is removed.
  if (!is_in_draining_period() &&
      !is_in_closing_period() &&
      !state_->silent_close &&
      !ngtcp2_conn_is_local_stream(connection_.get(), id)) {
    if (ngtcp2_is_bidi_stream(id))
      ngtcp2_conn_extend_max_streams_bidi(connection_.get(), 1);
    else
      ngtcp2_conn_extend_max_streams_uni(connection_.get(), 1);
  }

  // Frees the persistent reference to the QuicStream object,
  // allowing it to be gc'd any time after the JS side releases
  // it's own reference.
  streams_.erase(id);
}

void Session::ScheduleRetransmit() {
  uint64_t now = uv_hrtime();
  uint64_t expiry = ngtcp2_conn_get_expiry(connection());
  // now and expiry are in nanoseconds, interval is milliseconds
  uint64_t interval = (expiry < now) ? 1 : (expiry - now) / 1000000UL;
  // If interval ends up being 0, the repeating timer won't be
  // scheduled, so set it to 1 instead.
  if (interval == 0) interval = 1;
  Debug(this, "Scheduling the retransmit timer for %" PRIu64, interval);
  UpdateRetransmitTimer(interval);
}

bool Session::ShouldAttemptConnectionClose() {
  if (connection_close_attempts_ == connection_close_limit_) {
    if (connection_close_limit_ * 2 <= kMaxSizeT)
      connection_close_limit_ *= 2;
    else
      connection_close_limit_ = kMaxSizeT;
    return true;
  }
  return false;
}

void Session::ShutdownStream(stream_id id, uint64_t code) {
  if (is_in_closing_period() ||
      is_in_draining_period() ||
      state_->silent_close == 1) {
    return;  // Nothing to do because we can't send any frames.
  }
  SendSessionScope send_scope(this);
  ngtcp2_conn_shutdown_stream(connection(), id, 0);
}

bool Session::StartClosingPeriod() {
  if (is_destroyed())
    return false;
  if (is_in_closing_period())
    return true;

  QuicError error = last_error();
  Debug(this, "Closing period has started. Error %s", error);

  conn_closebuf_ = std::make_unique<Packet>("server connection close");

  ssize_t nwrite =
      SelectCloseFn(error)(
          connection(),
          nullptr,
          nullptr,
          conn_closebuf_->data(),
          max_pkt_len_,
          error.code,
          uv_hrtime());
  if (nwrite < 0) {
    set_last_error(kQuicInternalError);
    return false;
  }
  conn_closebuf_->set_length(nwrite);
  return true;
}

void Session::StartGracefulClose() {
  state_->graceful_closing = 1;
  RecordTimestamp(&SessionStats::closing_at);
}

void Session::StreamClose(stream_id id, uint64_t app_error_code) {
  Debug(this, "Closing stream %" PRId64 " with code %" PRIu64,
        id,
        app_error_code);

  application_->StreamClose(id, app_error_code);
}

void Session::StreamReset(
    stream_id id,
    uint64_t final_size,
    uint64_t app_error_code) {
  Debug(this,
        "Reset stream %" PRId64 " with code %" PRIu64
        " and final size %" PRIu64,
        id,
        app_error_code,
        final_size);

  BaseObjectPtr<Stream> stream = FindStream(id);

  if (stream) {
    stream->set_final_size(final_size);
    application_->StreamReset(id, app_error_code);
  }
}

bool Session::SubmitHeaders(
    Stream::HeadersKind kind,
    stream_id id,
    v8::Local<v8::Array> headers) {
  return application_->SubmitHeaders(id, kind, headers);
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

void Session::UpdateConnectionID(
    int type,
    const CID& cid,
    const StatelessResetToken& token) {
  switch (type) {
    case NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE:
      endpoint_->AssociateStatelessResetToken(
          token,
          BaseObjectPtr<Session>(this));
      break;
    case NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE:
      endpoint_->DisassociateStatelessResetToken(token);
      break;
  }
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
  SetStat(&SessionStats::last_tx_pkt_ts,
          reinterpret_cast<uint64_t>(stat.last_tx_pkt_ts));
  SetStat(&SessionStats::latest_rtt, stat.latest_rtt);
  SetStat(&SessionStats::loss_detection_timer, stat.loss_detection_timer);
  SetStat(&SessionStats::loss_time,
          reinterpret_cast<uint64_t>(stat.loss_time));
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

void Session::UpdateEndpoint(const ngtcp2_path& path) {
  remote_address_.Update(path.remote.addr, path.remote.addrlen);
  local_address_.Update(path.local.addr, path.local.addrlen);
  if (remote_address_.family() == AF_INET6) {
    remote_address_.set_flow_label(
        endpoint_->GetFlowLabel(
            local_address_,
            remote_address_,
            scid_));
  }
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

void Session::UpdateRetransmitTimer(uint64_t timeout) {
  retransmit_.Update(timeout, timeout);
}

void Session::UsePreferredAddress(const PreferredAddress::Address& address) {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
      OneByteString(env()->isolate(), address.address.c_str()),
      Integer::NewFromUnsigned(env()->isolate(), address.port),
      Integer::New(env()->isolate(), address.family)
  };

  BaseObjectPtr<Session> ptr(this);

  USE(state->session_use_preferred_address_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));
}

void Session::VersionNegotiation(const uint32_t* sv, size_t nsv) {
  CHECK(!is_server());

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  std::vector<Local<Value>> versions(nsv);

  for (size_t n = 0; n < nsv; n++)
    versions.emplace_back(Integer::New(env()->isolate(), sv[n]));

  // Currently, we only support one version of QUIC but in
  // the future that may change. The callback below passes
  // an array back to the JavaScript side to future-proof.
  Local<Value> supported = Integer::New(env()->isolate(), NGTCP2_PROTO_VER_MAX);

  Local<Value> argv[] = {
    Integer::New(env()->isolate(), NGTCP2_PROTO_VER_MAX),
    Array::New(env()->isolate(), versions.data(), nsv),
    Array::New(env()->isolate(), &supported, 1)
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(this);
  USE(state->session_version_negotiation_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));
}

EndpointWrap* Session::endpoint() const { return endpoint_.get(); }

bool Session::is_handshake_completed() const {
  DCHECK(!is_destroyed());
  return ngtcp2_conn_get_handshake_completed(connection());
}

bool Session::is_in_closing_period() const {
  return ngtcp2_conn_is_in_closing_period(connection());
}

bool Session::is_in_draining_period() const {
  return ngtcp2_conn_is_in_draining_period(connection());
}

bool Session::is_unable_to_send_packets() {
  return NgCallbackScope::InNgCallbackScope(this) ||
      is_destroyed() ||
      is_in_draining_period() ||
      (is_server() && is_in_closing_period()) ||
      !endpoint_;
}

uint64_t Session::max_data_left() const {
  return ngtcp2_conn_get_max_data_left(connection());
}

uint64_t Session::max_local_streams_uni() const {
  return ngtcp2_conn_get_max_local_streams_uni(connection());
}

void Session::set_remote_transport_params() {
  DCHECK(!is_destroyed());
  ngtcp2_conn_get_remote_transport_params(connection(), &transport_params_);
  transport_params_set_ = true;
}

int Session::set_session(SSL_SESSION* session) {
  CHECK(!is_server());
  CHECK(!is_destroyed());
  int size = i2d_SSL_SESSION(session, nullptr);
  if (size > crypto::SecureContext::kMaxSessionSize)
    return 0;

  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(this);

  Local<Value> argv[] = {
    v8::Undefined(env()->isolate()),
    v8::Undefined(env()->isolate())
  };

  if (size > 0) {
    std::shared_ptr<BackingStore> session_ticket =
        ArrayBuffer::NewBackingStore(env()->isolate(), size);
    unsigned char* session_data =
        reinterpret_cast<unsigned char*>(session_ticket->Data());
    memset(session_data, 0, size);
    if (i2d_SSL_SESSION(session, &session_data) <= 0)
      return 0;
    argv[0] = ArrayBuffer::New(env()->isolate(), session_ticket);
  }

  if (transport_params_set_) {
    std::shared_ptr<BackingStore> transport_params =
        ArrayBuffer::NewBackingStore(env()->isolate(),
        sizeof(ngtcp2_transport_params));
    memcpy(
      transport_params->Data(),
      &transport_params_,
      sizeof(ngtcp2_transport_params));
    argv[1] = ArrayBuffer::New(env()->isolate(), transport_params);
  }

  BaseObjectPtr<Session> ptr(this);

  USE(state->session_ticket_callback(env())->Call(
      env()->context(),
      object(),
      arraysize(argv),
      argv));

  return 0;
}

BaseObjectPtr<QLogStream> Session::qlogstream() {
  if (!qlogstream_)
    qlogstream_ = QLogStream::Create(env());
  return qlogstream_;
}

// Gets the QUIC version negotiated for this QuicSession
uint32_t Session::version() const {
  CHECK(!is_destroyed());
  return ngtcp2_conn_get_negotiated_version(connection());
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
    OnDatagram
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
    OnDatagram
  }
};

int Session::OnReceiveCryptoData(
    ngtcp2_conn* conn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  return session->crypto_context()->Receive(
      crypto_level,
      offset,
      data,
      datalen) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::OnExtendMaxStreamsBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->ExtendMaxStreamsBidi(max_streams);
  return 0;
}

int Session::OnExtendMaxStreamsUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->ExtendMaxStreamsUni(max_streams);
  return 0;
}

int Session::OnExtendMaxStreamsRemoteUni(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->ExtendMaxStreamsRemoteUni(max_streams);
  return 0;
}

int Session::OnExtendMaxStreamsRemoteBidi(
    ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->ExtendMaxStreamsRemoteUni(max_streams);
  return 0;
}

int Session::OnExtendMaxStreamData(
    ngtcp2_conn* conn,
    stream_id id,
    uint64_t max_data,
    void* user_data,
    void* stream_user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->ExtendMaxStreamData(id, max_data);
  return 0;
}

int Session::OnConnectionIDStatus(
    ngtcp2_conn* conn,
    int type,
    uint64_t seq,
    const ngtcp2_cid* cid,
    const uint8_t* token,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if (token != nullptr) {
    NgCallbackScope scope(session);
    CID qcid(cid);
    Debug(session, "Updating connection ID %s with reset token", qcid);
    session->UpdateConnectionID(type, qcid, StatelessResetToken(token));
  }
  return 0;
}

int Session::OnHandshakeCompleted(
    ngtcp2_conn* conn,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->HandshakeCompleted();
  return 0;
}

int Session::OnHandshakeConfirmed(
    ngtcp2_conn* conn,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->HandshakeConfirmed();
  return 0;
}

int Session::OnReceiveStreamData(
    ngtcp2_conn* conn,
    uint32_t flags,
    stream_id id,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  return session->ReceiveStreamData(
      flags,
      id,
      data,
      datalen,
      offset) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::OnStreamOpen(
    ngtcp2_conn* conn,
    stream_id id,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  // We currently do not do anything with this callback.
  // Stream instances are created implicitly only once the
  // first chunk of stream data is received.

  return 0;
}

int Session::OnAckedCryptoOffset(
    ngtcp2_conn* conn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    uint64_t datalen,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->crypto_context()->AcknowledgeCryptoData(crypto_level, datalen);
  return 0;
}

int Session::OnAckedStreamDataOffset(
    ngtcp2_conn* conn,
    stream_id id,
    uint64_t offset,
    uint64_t datalen,
    void* user_data,
    void* stream_user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->AckedStreamDataOffset(id, offset, datalen);
  return 0;
}

int Session::OnSelectPreferredAddress(
    ngtcp2_conn* conn,
    ngtcp2_addr* dest,
    const ngtcp2_preferred_addr* paddr,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);

  // The paddr parameter contains the server advertised preferred
  // address. The dest parameter contains the address that is
  // actually being used. If the preferred address is selected,
  // then the contents of paddr are copied over to dest.
  session->SelectPreferredAddress(
      PreferredAddress(session->env(), dest, paddr));
  return 0;
}

int Session::OnStreamClose(
    ngtcp2_conn* conn,
    stream_id id,
    uint64_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->StreamClose(id, app_error_code);
  return 0;
}

int Session::OnStreamReset(
    ngtcp2_conn* conn,
    stream_id id,
    uint64_t final_size,
    uint64_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->StreamReset(id, final_size, app_error_code);
  return 0;
}

int Session::OnRand(
    uint8_t *dest,
    size_t destlen,
    const ngtcp2_rand_ctx *rand_ctx,
    ngtcp2_rand_usage usage) {
  // For now, we ignore both rand_ctx and usage. The rand_ctx allows
  // a custom entropy source to be passed in to the ngtcp2 configuration.
  // We don't make use of that mechanism. The usage differentiates what
  // the random data is for, in case an implementation wishes to apply
  // a different mechanism based on purpose. We don't, at least for now.
  crypto::EntropySource(dest, destlen);
  return 0;
}

int Session::OnGetNewConnectionID(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope scope(session);
  session->GetNewConnectionID(cid, token, cidlen);
  return 0;
}

int Session::OnRemoveConnectionID(
    ngtcp2_conn* conn,
    const ngtcp2_cid* cid,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if (session->is_server()) {
    NgCallbackScope callback_scope(session);
    session->endpoint()->DisassociateCID(CID(cid));
  }
  return 0;
}

int Session::OnPathValidation(
    ngtcp2_conn* conn,
    const ngtcp2_path* path,
    ngtcp2_path_validation_result res,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->PathValidation(path, res);
  return 0;
}

int Session::OnVersionNegotiation(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_hd* hd,
    const uint32_t* sv,
    size_t nsv,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  NgCallbackScope callback_scope(session);
  session->VersionNegotiation(sv, nsv);
  return 0;
}

int Session::OnStatelessReset(
    ngtcp2_conn* conn,
    const ngtcp2_pkt_stateless_reset* sr,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  session->stateless_reset_ = true;
  return 0;
}

int Session::OnDatagram(
    ngtcp2_conn* conn,
    uint32_t flags,
    const uint8_t* data,
    size_t datalen,
    void* user_data) {
  Session* session = static_cast<Session*>(user_data);

  if (UNLIKELY(session->is_destroyed()))
    return NGTCP2_ERR_CALLBACK_FAILURE;

  session->Datagram(flags, data, datalen);
  return 0;
}

void Session::DoDestroy(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Destroy();
}

void Session::GetRemoteAddress(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(args[0]->IsObject());
  args.GetReturnValue().Set(
      session->remote_address().ToJS(env, args[0].As<Object>()));
}

void Session::GetCertificate(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<Value> ret;
  if (session->crypto_context()->cert(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Session::GetPeerCertificate(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<Value> ret;
  if (session->crypto_context()->peer_cert(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Session::SilentClose(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  ProcessEmitWarning(
      session->env(),
      "Forcing silent close of Session for testing purposes only");
  session->Close(Session::SessionCloseFlags::SILENT);
}

void Session::GracefulClose(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->StartGracefulClose();
}

void Session::UpdateKey(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  // Initiating a key update may fail if it is done too early (either
  // before the TLS handshake has been confirmed or while a previous
  // key update is being processed). When it fails, InitiateKeyUpdate()
  // will return false.
  args.GetReturnValue().Set(session->crypto_context()->InitiateKeyUpdate());
}

void Session::DoDetachFromEndpoint(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->DetachFromEndpoint();
}

void Session::OnClientHelloDone(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<FunctionTemplate> cons = env->secure_context_constructor_template();
  crypto::SecureContext* context = nullptr;
  if (args[0]->IsObject() && cons->HasInstance(args[0]))
    context = Unwrap<crypto::SecureContext>(args[0].As<Object>());
  session->crypto_context()->OnClientHelloDone(
      BaseObjectPtr<crypto::SecureContext>(context));
}

void Session::OnOCSPDone(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (UNLIKELY(args[0]->IsUndefined())) return;

  // TODO(@jasnell): Implement properly
  // session->crypto_context()->OnOCSPDone(args[0]);
  session->crypto_context()->OnOCSPDone(std::shared_ptr<BackingStore>());
}

void Session::GetEphemeralKeyInfo(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<Object> ret;
  if (session->crypto_context()->ephemeral_key(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Session::DoAttachToEndpoint(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(EndpointWrap::HasInstance(env, args[0]));
  EndpointWrap* endpoint;
  ASSIGN_OR_RETURN_UNWRAP(&endpoint, args[0]);
  args.GetReturnValue().Set(
      session->AttachToNewEndpoint(endpoint, args[1]->IsTrue()));
}

void SessionStatsTraits::ToString(const Session& ptr, AddStatsField add_field) {
#define V(n, name, label) add_field(label, ptr.GetStat(&SessionStats::name));
    SESSION_STATS(V)
#undef V
  }

// Determines which Application variant the Session will be using
// based on the alpn configured for the application. For now, this is
// determined through configuration when tghe QuicSession is created
// and is not negotiable. In the future, we may allow it to be negotiated.
Session::Application* Session::SelectApplication(
    const Application::Config& config) {
  // if (alpn == NGHTTP3_ALPN_H3) {
  //   Debug(this, "Selecting HTTP/3 Application");
  //   return new Http3Application(this);
  // }

  // In the future, we may end up supporting additional
  // QUIC protocols. As they are added, extend the cases
  // here to create and return them.

  return new DefaultApplication(this, config);
}

Session::Application::Application(
    Session* session,
    const Application::Config& config)
    : session_(session),
      config_(config) {}

void Session::Application::Acknowledge(
    stream_id id,
    uint64_t offset,
    size_t datalen) {
  BaseObjectPtr<Stream> stream = session()->FindStream(id);
  if (LIKELY(stream)) {
    stream->Acknowledge(offset, datalen);
    ResumeStream(id);
  }
}

std::unique_ptr<Packet> Session::Application::CreateStreamDataPacket() {
  return std::make_unique<Packet>(
      session()->max_packet_length(),
      "stream data");
}

bool Session::Application::Initialize() {
  if (needs_init_) needs_init_ = false;
  return !needs_init_;
}

void Session::Application::MaybeSetFin(const StreamData& stream_data) {
  if (ShouldSetFin(stream_data))
    set_stream_fin(stream_data.id);
}

bool Session::Application::SendPendingData() {
  // The maximum number of packets to send per call
  static constexpr size_t kMaxPackets = 16;
  PathStorage path;
  std::unique_ptr<Packet> packet;
  uint8_t* pos = nullptr;
  size_t packets_sent = 0;
  int err;

  for (;;) {
    ssize_t ndatalen;
    StreamData stream_data;
    err = GetStreamData(&stream_data);
    if (err < 0) {
      session()->set_last_error(kQuicInternalError);
      return false;
    }

    // If stream_data.id is -1, then we're not serializing any data for any
    // specific stream. We still need to process QUIC session packets tho.
    if (stream_data.id > -1)
      Debug(session(), "Serializing packets for stream id %" PRId64,
            stream_data.id);
    else
      Debug(session(), "Serializing session packets");

    // If the packet was sent previously, then packet will have been reset.
    if (!packet) {
      packet = CreateStreamDataPacket();
      pos = packet->data();
    }

    ssize_t nwrite = WriteVStream(&path, pos, &ndatalen, stream_data);

    if (nwrite <= 0) {
      switch (nwrite) {
        case 0:
          goto congestion_limited;
        case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
          // There is a finite number of packets that can be sent
          // per connection. Once those are exhausted, there's
          // absolutely nothing we can do except immediately
          // and silently tear down the QuicSession. This has
          // to be silent because we can't even send a
          // CONNECTION_CLOSE since even those require a
          // packet number.
          session()->Close(Session::SessionCloseFlags::SILENT);
          return false;
        case NGTCP2_ERR_STREAM_DATA_BLOCKED:
          session()->StreamDataBlocked(stream_data.id);
          if (session()->max_data_left() == 0)
            goto congestion_limited;
          // Fall through
        case NGTCP2_ERR_STREAM_SHUT_WR:
          if (UNLIKELY(!BlockStream(stream_data.id)))
            return false;
          continue;
        case NGTCP2_ERR_STREAM_NOT_FOUND:
          continue;
        case NGTCP2_ERR_WRITE_MORE:
          CHECK_GT(ndatalen, 0);
          CHECK(StreamCommit(&stream_data, ndatalen));
          pos += ndatalen;
          continue;
      }
      session()->set_last_error(kQuicInternalError);
      return false;
    }

    pos += nwrite;

    if (ndatalen >= 0)
      CHECK(StreamCommit(&stream_data, ndatalen));

    Debug(session(), "Sending %" PRIu64 " bytes in serialized packet", nwrite);
    packet->set_length(nwrite);
    if (!session()->SendPacket(std::move(packet), path))
      return false;
    packet.reset();
    pos = nullptr;
    MaybeSetFin(stream_data);
    if (++packets_sent == kMaxPackets)
      break;
  }
  return true;

congestion_limited:
  // We are either congestion limited or done.
  if (pos - packet->data()) {
    // Some data was serialized into the packet. We need to send it.
    packet->set_length(pos - packet->data());
    Debug(session(), "Congestion limited, but %" PRIu64 " bytes pending",
          packet->length());
    if (!session()->SendPacket(std::move(packet), path))
      return false;
  }
  return true;
}

void Session::Application::StreamClose(
    stream_id id,
    uint64_t app_error_code) {
  BaseObjectPtr<Stream> stream = session()->FindStream(id);
  if (stream) {
    // Calling stream->OnClose() frees up the internal state and
    // disconnects the stream from the session. The subsequent
    // call to OnStreamClose notifies the JavaScript side (or
    // whichever listener is attached) so that any references and
    // state on that side can be freed up.

    BindingState* state = env()->GetBindingData<BindingState>(env()->context());
    HandleScope scope(env()->isolate());
    Context::Scope context_scope(env()->context());

    CallbackScope cb_scope(session());

    Local<Value> argv[] = {
      Number::New(env()->isolate(), static_cast<double>(id)),
      Number::New(env()->isolate(), static_cast<double>(app_error_code))
    };

    // Grab a shared pointer to this to prevent the QuicSession
    // from being freed while the MakeCallback is running.
    BaseObjectPtr<Session> ptr(session());

    USE(state->stream_close_callback(env())->Call(
        env()->context(),
        session()->object(),
        arraysize(argv),
        argv));

    stream->OnClose();
  }
}

void Session::Application::StreamHeaders(
    stream_id id,
    Stream::HeadersKind kind,
    const Stream::HeaderList& headers) {
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());

  CallbackScope cb_scope(session());

  std::vector<Local<Value>> head(headers.size());
  for (const auto& header : headers) {
    Local<Value> pair[2];
    if (UNLIKELY(!header->GetName(state).ToLocal(&pair[0])) ||
        UNLIKELY(!header->GetValue(state).ToLocal(&pair[1]))) {
      return;
    }

    head.emplace_back(Array::New(env()->isolate(), pair, 2));
  }

  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(id)),
    Array::New(env()->isolate(), head.data(), head.size()),
    Integer::NewFromUnsigned(env()->isolate(), static_cast<uint32_t>(kind)),
  };

  BaseObjectPtr<Session> ptr(session());

  USE(state->stream_headers_callback(env())->Call(
      env()->context(),
      session()->object(),
      arraysize(argv),
      argv));
}

void Session::Application::StreamReset(
    stream_id id,
    uint64_t app_error_code) {
  BindingState* state = env()->GetBindingData<BindingState>(env()->context());
  HandleScope scope(env()->isolate());
  Context::Scope context_scope(env()->context());

  CallbackScope cb_scope(session());

  Local<Value> argv[] = {
    Number::New(env()->isolate(), static_cast<double>(id)),
    Number::New(env()->isolate(), static_cast<double>(app_error_code))
  };

  // Grab a shared pointer to this to prevent the QuicSession
  // from being freed while the MakeCallback is running.
  BaseObjectPtr<Session> ptr(session());

  USE(state->stream_reset_callback(env())->Call(
      env()->context(),
      session()->object(),
      arraysize(argv),
      argv));
}

ssize_t Session::Application::WriteVStream(
    PathStorage* path,
    uint8_t* buf,
    ssize_t* ndatalen,
    const StreamData& stream_data) {
  CHECK_LE(stream_data.count, kMaxVectorCount);

  uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
  if (stream_data.remaining > 0)
    flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
  if (stream_data.fin)
    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

  return ngtcp2_conn_writev_stream(
    session()->connection(),
    &path->path,
    nullptr,
    buf,
    session()->max_packet_length(),
    ndatalen,
    flags,
    stream_data.id,
    stream_data.buf,
    stream_data.count,
    uv_hrtime());
}

void Session::Application::set_stream_fin(stream_id id) {
  BaseObjectPtr<Stream> stream = session()->FindStream(id);
  CHECK(stream);
  stream->set_fin_sent();
}

std::string Session::RemoteTransportParamsDebug::ToString() const {
  ngtcp2_transport_params params;
  ngtcp2_conn_get_remote_transport_params(session->connection(), &params);
  std::string out = "Remote Transport Params:\n";
  out += "  Ack Delay Exponent: " +
         std::to_string(params.ack_delay_exponent) + "\n";
  out += "  Active Connection ID Limit: " +
         std::to_string(params.active_connection_id_limit) + "\n";
  out += "  Disable Active Migration: " +
         std::string(params.disable_active_migration ? "Yes" : "No") + "\n";
  out += "  Initial Max Data: " +
         std::to_string(params.initial_max_data) + "\n";
  out += "  Initial Max Stream Data Bidi Local: " +
         std::to_string(params.initial_max_stream_data_bidi_local) + "\n";
  out += "  Initial Max Stream Data Bidi Remote: " +
         std::to_string(params.initial_max_stream_data_bidi_remote) + "\n";
  out += "  Initial Max Stream Data Uni: " +
         std::to_string(params.initial_max_stream_data_uni) + "\n";
  out += "  Initial Max Streams Bidi: " +
         std::to_string(params.initial_max_streams_bidi) + "\n";
  out += "  Initial Max Streams Uni: " +
         std::to_string(params.initial_max_streams_uni) + "\n";
  out += "  Max Ack Delay: " +
         std::to_string(params.max_ack_delay) + "\n";
  out += "  Max Idle Timeout: " +
         std::to_string(params.max_idle_timeout) + "\n";
  out += "  Max Packet Size: " +
         std::to_string(params.max_udp_payload_size) + "\n";

  if (!session->is_server()) {
    if (params.retry_scid_present) {
      CID cid(params.original_dcid);
      CID retry(params.retry_scid);
      out += "  Original Connection ID: " + cid.ToString() + "\n";
      out += "  Retry SCID: " + retry.ToString() + "\n";
    } else {
      out += "  Original Connection ID: N/A \n";
    }

    if (params.preferred_address_present) {
      out += "  Preferred Address Present: Yes\n";
      // TODO(@jasnell): Serialize the IPv4 and IPv6 address options
    } else {
      out += "  Preferred Address Present: No\n";
    }

    if (params.stateless_reset_token_present) {
      StatelessResetToken token(params.stateless_reset_token);
      out += "  Stateless Reset Token: " + token.ToString() + "\n";
    } else {
      out += " Stateless Reset Token: N/A";
    }
  }
  return out;
}

DefaultApplication::DefaultApplication(
    Session* session,
    const Application::Config& config)
    : Session::Application(session, config) {
  Debug(session, "Using default application");
}

void DefaultApplication::ScheduleStream(stream_id id) {
  BaseObjectPtr<Stream> stream = session()->FindStream(id);
  if (LIKELY(stream && !stream->is_destroyed())) {
    Debug(session(), "Scheduling stream %" PRIu64, id);
    stream->Schedule(&stream_queue_);
  }
}

void DefaultApplication::UnscheduleStream(stream_id id) {
  BaseObjectPtr<Stream> stream = session()->FindStream(id);
  if (LIKELY(stream)) {
    Debug(session(), "Unscheduling stream %" PRIu64, id);
    stream->Unschedule();
  }
}

void DefaultApplication::ResumeStream(stream_id id) {
  ScheduleStream(id);
}

bool DefaultApplication::ReceiveStreamData(
    uint32_t flags,
    stream_id id,
    const uint8_t* data,
    size_t datalen,
    uint64_t offset) {

  // One potential DOS attack vector is to send a bunch of
  // empty stream frames to commit resources. Check that
  // here. Essentially, we only want to create a new stream
  // if the datalen is greater than 0, otherwise, we ignore
  // the packet. ngtcp2 should be handling this for us,
  // but we handle it just to be safe.
  if (UNLIKELY(datalen == 0))
    return true;

  // Ensure that the QuicStream exists.
  Debug(session(), "Receiving stream data for %" PRIu64, id);
  BaseObjectPtr<Stream> stream = session()->FindStream(id);
  if (!stream) {
    // Because we are closing gracefully, we are not allowing
    // new streams to be created. Shut it down immediately
    // and commit no further resources.
    if (session()->is_graceful_closing()) {
      session()->ShutdownStream(id, NGTCP2_ERR_CLOSING);
      return true;
    }

    stream = session()->CreateStream(id);
  }
  CHECK(stream);

  // If the stream ended up being destroyed immediately after
  // creation, just skip the data processing and return.
  if (UNLIKELY(stream->is_destroyed()))
    return true;

  stream->ReceiveData(flags, data, datalen, offset);
  return true;
}

int DefaultApplication::GetStreamData(StreamData* stream_data) {
  Stream* stream = stream_queue_.PopFront();
  // If stream is nullptr, there are no streams with data pending.
  if (stream == nullptr)
    return 0;

  stream_data->stream.reset(stream);
  stream_data->id = stream->id();

  auto next = [&](
      int status,
      const ngtcp2_vec* data,
      size_t count,
      bob::Done done) {
    switch (status) {
      case bob::Status::STATUS_BLOCK:
        // Fall through
      case bob::Status::STATUS_WAIT:
        // Fall through
      case bob::Status::STATUS_EOS:
        return;
      case bob::Status::STATUS_END:
        stream_data->fin = 1;
    }

    stream_data->count = count;

    if (count > 0) {
      stream->Schedule(&stream_queue_);
      stream_data->remaining = get_length(data, count);
    } else {
      stream_data->remaining = 0;
    }
  };

  if (LIKELY(!stream->is_eos())) {
    CHECK_GE(stream->Pull(
        std::move(next),
        bob::Options::OPTIONS_SYNC,
        stream_data->data,
        arraysize(stream_data->data),
        kMaxVectorCount), 0);
  }

  return 0;
}

bool DefaultApplication::StreamCommit(
    StreamData* stream_data,
    size_t datalen) {
  CHECK(stream_data->stream);
  stream_data->remaining -= datalen;
  Consume(&stream_data->buf, &stream_data->count, datalen);
  stream_data->stream->Commit(datalen);
  return true;
}

bool DefaultApplication::ShouldSetFin(const StreamData& stream_data) {
  if (!stream_data.stream ||
      !IsEmpty(stream_data.buf, stream_data.count))
    return false;
  // TODO(@jasnell): Revisit this?
  //return !stream_data.stream->is_writable();
  return true;
}

bool OptionsObject::HasInstance(Environment* env, Local<Value> value) {
  return GetConstructorTemplate(env)->HasInstance(value);
}

Local<FunctionTemplate> OptionsObject::GetConstructorTemplate(
    Environment* env) {
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  Local<FunctionTemplate> tmpl =
      state->session_options_constructor_template(env);
  if (tmpl.IsEmpty()) {
    tmpl = env->NewFunctionTemplate(New);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        OptionsObject::kInternalFieldCount);
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "OptionsObject"));
    env->SetProtoMethod(tmpl, "setPreferredAddress", SetPreferredAddress);
    env->SetProtoMethod(tmpl, "setTransportParams", SetTransportParams);
    env->SetProtoMethod(tmpl, "setTLSOptions", SetTLSOptions);
    env->SetProtoMethod(tmpl, "setSessionResume", SetSessionResume);
    state->set_session_options_constructor_template(env, tmpl);
  }
  return tmpl;
}

void OptionsObject::Initialize(Environment* env, Local<Object> target) {
  env->SetConstructorFunction(
      target,
      "OptionsObject",
      GetConstructorTemplate(env));
}

void OptionsObject::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());  // ALPN
  CHECK(args[1]->IsObject());  // SecureContext
  CHECK_IMPLIES(
      !args[2]->IsUndefined(),
      args[2]->IsString());  // Hostname
  CHECK_IMPLIES(  // CID
      !args[3]->IsUndefined(),
      args[3]->IsArrayBuffer() || args[3]->IsArrayBufferView());
  CHECK_IMPLIES(  // Preferred address strategy
      !args[4]->IsUndefined(),
      args[4]->IsInt32());

  Utf8Value alpn(env->isolate(), args[0]);
  crypto::SecureContext* context;
  ASSIGN_OR_RETURN_UNWRAP(&context, args[1].As<Object>());

  OptionsObject* options = new OptionsObject(env, args.This());
  options->data()->alpn = *alpn;
  options->data()->context.reset(context);

  if (!args[2]->IsUndefined()) {
    Utf8Value hostname(env->isolate(), args[2]);
    options->data()->hostname = *hostname;
  }

  if (!args[3]->IsUndefined()) {
    crypto::ArrayBufferOrViewContents<uint8_t> cid(args[3]);
    // CHECK_LE(cid.size(), NGTCP2_MAX_CIDLEN);
    if (cid.size() > 0) {
      memcpy(
          options->data()->dcid.data(),
          cid.data(),
          cid.size());
      options->data()->dcid.set_length(cid.size());
    }
  }

  if (!args[4]->IsUndefined()) {
    PreferredAddress::Policy policy =
        static_cast<PreferredAddress::Policy>(args[4].As<Int32>()->Value());
    switch (policy) {
      case PreferredAddress::Policy::USE:
        options->data()->preferred_address_strategy =
            Session::UsePreferredAddressStrategy;
        break;
      case PreferredAddress::Policy::IGNORE:
        options->data()->preferred_address_strategy =
            Session::IgnorePreferredAddressStrategy;
        break;
      default:
        UNREACHABLE();
    }
  }
}

void OptionsObject::SetPreferredAddress(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());

  CHECK(args[0]->IsInt32());
  CHECK(args[1]->IsString());
  CHECK(args[2]->IsInt32());

  int32_t type = args[0].As<Int32>()->Value();
  int32_t port = args[2].As<Int32>()->Value();
  Utf8Value address(env->isolate(), args[1]);

  CHECK_IMPLIES(type != AF_INET, type == AF_INET6);

  SocketAddress* addr = nullptr;
  switch (type) {
    case AF_INET:
      addr = &options->data()->preferred_address_ipv4;
      break;
    case AF_INET6:
      addr = &options->data()->preferred_address_ipv6;
      break;
    default:
      UNREACHABLE();
  }

  args.GetReturnValue().Set(SocketAddress::New(type, *address, port, addr));
}

Maybe<bool> OptionsObject::SetOption(
    Local<Object> object,
    Local<String> name,
    uint64_t Session::Options::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return Nothing<bool>();

  if (value->IsUndefined())
    return Just(false);

  CHECK_IMPLIES(!value->IsBigInt(), value->IsNumber());

  uint64_t val = 0;
  if (value->IsBigInt()) {
    bool lossless = true;
    val = value.As<BigInt>()->Uint64Value(&lossless);
    if (!lossless) {
      Utf8Value label(env()->isolate(), name);
      THROW_ERR_OUT_OF_RANGE(
          env(),
          (std::string("options.") + *label + " is out of range").c_str());
      return Nothing<bool>();
    }
  } else {
    val = static_cast<int64_t>(value.As<Number>()->Value());
  }
  options_.get()->*member = val;
  return Just(true);
}

Maybe<bool> OptionsObject::SetOption(
    Local<Object> object,
    Local<String> name,
    bool Session::Options::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return Nothing<bool>();
  if (value->IsUndefined())
    return Just(false);
  CHECK(value->IsBoolean());
  options_.get()->*member = value->IsTrue();
  return Just(true);
}

void OptionsObject::SetTransportParams(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());

  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();

  if (options->SetOption(
          obj,
          state->initial_max_stream_data_bidi_local_string(env),
          &Session::Options::initial_max_stream_data_bidi_local).IsNothing() ||
      options->SetOption(
          obj,
          state->initial_max_stream_data_bidi_remote_string(env),
          &Session::Options::initial_max_stream_data_bidi_remote).IsNothing() ||
      options->SetOption(
          obj,
          state->initial_max_stream_data_uni_string(env),
          &Session::Options::initial_max_stream_data_uni).IsNothing() ||
      options->SetOption(
          obj,
          state->initial_max_data_string(env),
          &Session::Options::initial_max_data).IsNothing() ||
      options->SetOption(
          obj,
          state->initial_max_streams_bidi_string(env),
          &Session::Options::initial_max_streams_bidi).IsNothing() ||
      options->SetOption(
          obj,
          state->initial_max_streams_uni_string(env),
          &Session::Options::initial_max_streams_uni).IsNothing() ||
      options->SetOption(
          obj,
          state->max_idle_timeout_string(env),
          &Session::Options::max_idle_timeout).IsNothing() ||
      options->SetOption(
          obj,
          state->active_connection_id_limit_string(env),
          &Session::Options::active_connection_id_limit).IsNothing() ||
      options->SetOption(
          obj,
          state->ack_delay_exponent_string(env),
          &Session::Options::ack_delay_exponent).IsNothing() ||
      options->SetOption(
          obj,
          state->max_ack_delay_string(env),
          &Session::Options::max_ack_delay).IsNothing() ||
      options->SetOption(
          obj,
          state->max_datagram_frame_size_string(env),
          &Session::Options::max_datagram_frame_size).IsNothing() ||
      options->SetOption(
          obj,
          state->disable_active_migration_string(env),
          &Session::Options::disable_active_migration).IsNothing()) {
    // The if block intentionally does nothing. The code is structured
    // like this to shortcircuit if any of the SetOptions() returns Nothing.
  }
}

void OptionsObject::SetTLSOptions(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  BindingState* state = env->GetBindingData<BindingState>(env->context());
  OptionsObject* options;
  ASSIGN_OR_RETURN_UNWRAP(&options, args.Holder());

  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();

  if (options->SetOption(
          obj,
          state->reject_unauthorized_string(env),
          &Session::Options::reject_unauthorized).IsNothing() ||
      options->SetOption(
          obj,
          state->enable_tls_trace_string(env),
          &Session::Options::enable_tls_trace).IsNothing() ||
      options->SetOption(
          obj,
          state->request_peer_certificate_string(env),
          &Session::Options::request_peer_certificate).IsNothing() ||
      options->SetOption(
          obj,
          state->request_ocsp_string(env),
          &Session::Options::request_ocsp).IsNothing() ||
      options->SetOption(
          obj,
          state->verify_hostname_identity_string(env),
          &Session::Options::verify_hostname_identity).IsNothing()) {
    // The if block intentionally does nothing. The code is structured
    // like this to shortcircuit if any of the SetOptions() returns Nothing.
  }
}

void OptionsObject::SetSessionResume(const FunctionCallbackInfo<Value>& args) {
  // TODO(@jasnell): Implement
}

BaseObjectPtr<BaseObject> OptionsObject::TransferData::Deserialize(
    Environment* env,
    Local<Context> context,
    std::unique_ptr<worker::TransferData> self) {
  Local<Object> obj;
  if (!OptionsObject::GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(context).ToLocal(&obj)) {
    return BaseObjectPtr<BaseObject>();
  }

  return MakeDetachedBaseObject<OptionsObject>(env, obj, std::move(options_));
}

OptionsObject::OptionsObject(
    Environment* env,
    Local<Object> object,
    std::shared_ptr<Session::Options> options)
    : BaseObject(env, object),
      options_(std::move(options)) {
  MakeWeak();
}

void Session::Options::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("alpn", alpn.length());
  tracker->TrackFieldWithSize("hostname", hostname.length());
  tracker->TrackField("context", context);
}

void OptionsObject::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
}

void OptionsObject::TransferData::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
}

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
