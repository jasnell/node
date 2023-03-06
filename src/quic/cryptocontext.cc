#include "bindingdata-inl.h"
#include "cryptocontext-inl.h"
#include "sessionticket.h"
#include "session-inl.h"
#include <base_object-inl.h>
#include <crypto/crypto_common.h>
#include <crypto/crypto_tls.h>
#include <crypto/crypto_x509.h>
#include <debug_utils-inl.h>
#include <env-inl.h>
#include <node_process-inl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <v8.h>

namespace node {

using v8::ArrayBuffer;
using v8::BackingStore;
using v8::Just;

namespace quic {

namespace {
// class AeadContextPointer final : public ngtcp2_crypto_aead_ctx {
//  public:
//   enum class Mode { ENCRYPT, DECRYPT };

//   QUIC_MOVE_NO_COPY(AeadContextPointer)

//   ~AeadContextPointer() { ngtcp2_crypto_aead_ctx_free(this); }

//   inline operator const ngtcp2_crypto_aead_ctx*() const { return this; }
//   inline operator ngtcp2_crypto_aead_ctx*() { return this; }

//   static AeadContextPointer forEncrypt(
//       const uint8_t* key,
//       const ngtcp2_crypto_aead& aead) {
//     AeadContextPointer ptr;
//     CHECK(NGTCP2_OK(ngtcp2_crypto_aead_ctx_encrypt_init(
//         ptr, &aead, key, kCryptoTokenIvlen)));
//     return ptr;
//   }

//   static AeadContextPointer forDecrypt(
//       const uint8_t* key,
//       const ngtcp2_crypto_aead& aead) {
//     AeadContextPointer ptr;
//     CHECK(NGTCP2_OK(ngtcp2_crypto_aead_ctx_decrypt_init(
//         ptr, &aead, key, kCryptoTokenIvlen)));
//     return ptr;
//   }

//  private:
//   AeadContextPointer() = default;
// };

// For now, we always allow early data. Later, we might make that configurable.
int allow_early_data_callback(SSL* ssl, void* arg) {
  return 1;
}

int new_session_callback(SSL* ssl, SSL_SESSION* session) {
  return CryptoContext::From(ssl).OnNewSession(session);
}

void keylog_callback(const SSL* ssl, const char* line) {
  CryptoContext::From(ssl).Keylog(line);
}

int alpn_selection_callback(SSL* ssl,
                          const unsigned char** out,
                          unsigned char* outlen,
                          const unsigned char* in,
                          unsigned int inlen,
                          void* arg) {
  auto& context = CryptoContext::From(ssl);

  auto requested = context.requested_alpn();
  if (requested.length() > kMaxAlpnLen) return SSL_TLSEXT_ERR_NOACK;

  // The Session supports exactly one ALPN identifier. If that does not match
  // any of the ALPN identifiers provided in the client request, then we fail
  // here. Note that this will not fail the TLS handshake, so we have to check
  // later if the ALPN matches the expected identifier or not.
  //
  // We might eventually want to support the ability to negotiate multiple
  // possible ALPN's on a single endpoint/session but for now, we only support
  // one.
  if (SSL_select_next_proto(
          const_cast<unsigned char**>(out),
          outlen,
          reinterpret_cast<const unsigned char*>(requested.begin()),
          requested.length(),
          in,
          inlen) == OPENSSL_NPN_NO_OVERLAP) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

BaseObjectPtr<crypto::SecureContext> InitializeSecureContext(
    CryptoContext::Side side,
    const Session& session,
    const CryptoContext::Options& options) {
  auto context = crypto::SecureContext::Create(session.env());
  bool failed = false;

  context->Initialize([&](crypto::SSLCtxPointer& ctx) {
    switch (side) {
      case CryptoContext::Side::SERVER: {
        ctx.reset(SSL_CTX_new(TLS_server_method()));
        SSL_CTX_set_app_data(ctx.get(), context);

        if (NGTCP2_ERR(
                ngtcp2_crypto_openssl_configure_server_context(ctx.get()))) {
          failed = true;
          return;
        }

        SSL_CTX_set_max_early_data(ctx.get(), UINT32_MAX);
        SSL_CTX_set_allow_early_data_cb(
            ctx.get(), allow_early_data_callback, nullptr);
        SSL_CTX_set_options(ctx.get(),
                            (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                                SSL_OP_SINGLE_ECDH_USE |
                                SSL_OP_CIPHER_SERVER_PREFERENCE |
                                SSL_OP_NO_ANTI_REPLAY);
        SSL_CTX_set_mode(ctx.get(), SSL_MODE_RELEASE_BUFFERS);
        SSL_CTX_set_alpn_select_cb(ctx.get(), alpn_selection_callback, nullptr);
        SSL_CTX_set_session_ticket_cb(
            ctx.get(),
            GenerateSessionTicketCallback,
            DecryptSessionTicketCallback,
            nullptr);

        const unsigned char* sid_ctx = reinterpret_cast<const unsigned char*>(
            options.session_id_ctx.c_str());
        SSL_CTX_set_session_id_context(
            ctx.get(), sid_ctx, options.session_id_ctx.length());

        break;
      }
      case CryptoContext::Side::CLIENT: {
        ctx.reset(SSL_CTX_new(TLS_client_method()));
        SSL_CTX_set_app_data(ctx.get(), context);

        if (NGTCP2_ERR(
                ngtcp2_crypto_openssl_configure_client_context(ctx.get()))) {
          failed = true;
          return;
        }

        SSL_CTX_set_session_cache_mode(
            ctx.get(),
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ctx.get(), new_session_callback);
        break;
      }
      default:
        UNREACHABLE();
    }

    SSL_CTX_set_default_verify_paths(ctx.get());

    if (options.keylog) SSL_CTX_set_keylog_callback(ctx.get(), keylog_callback);

    if (SSL_CTX_set_ciphersuites(ctx.get(), options.ciphers.c_str()) != 1) {
      failed = true;
      return;
    }

    if (SSL_CTX_set1_groups_list(ctx.get(), options.groups.c_str()) != 1) {
      failed = true;
      return;
    }
  });

  if (failed) {
    return BaseObjectPtr<crypto::SecureContext>();
  }

  // Handle CA certificates...

  const auto addCACert = [&](uv_buf_t ca) {
    crypto::ClearErrorOnReturn clear_error_on_return;
    crypto::BIOPointer bio = crypto::NodeBIO::NewFixed(ca.base, ca.len);
    if (!bio) return false;
    context->SetCACert(bio);
    return true;
  };

  const auto addRootCerts = [&] {
    crypto::ClearErrorOnReturn clear_error_on_return;
    context->SetRootCerts();
  };

  if (!options.ca.empty()) {
    for (auto& ca : options.ca) {
      if (!addCACert(ca)) {
        return BaseObjectPtr<crypto::SecureContext>();
      }
    }
  } else {
    addRootCerts();
  }

  // Handle Certs

  const auto addCert = [&](uv_buf_t cert) {
    crypto::ClearErrorOnReturn clear_error_on_return;
    crypto::BIOPointer bio = crypto::NodeBIO::NewFixed(cert.base, cert.len);
    if (!bio) return Just(false);
    auto ret = context->AddCert(session.env(), std::move(bio));
    return ret;
  };

  for (auto& cert : options.certs) {
    if (!addCert(cert).IsJust()) {
      return BaseObjectPtr<crypto::SecureContext>();
    }
  }

  // Handle keys

  const auto addKey = [&](auto& key) {
    crypto::ClearErrorOnReturn clear_error_on_return;
    return context->UseKey(session.env(), key);
    // TODO(@jasnell): Maybe SSL_CTX_check_private_key also?
  };

  for (auto& key : options.keys) {
    if (!addKey(key).IsJust()) {
      return BaseObjectPtr<crypto::SecureContext>();
    }
  }

  // Handle CRL

  const auto addCRL = [&](uv_buf_t crl) {
    crypto::ClearErrorOnReturn clear_error_on_return;
    crypto::BIOPointer bio = crypto::NodeBIO::NewFixed(crl.base, crl.len);
    if (!bio) return Just(false);
    return context->SetCRL(session.env(), bio);
  };

  for (auto& crl : options.crl) {
    if (!addCRL(crl).IsJust()) {
      return BaseObjectPtr<crypto::SecureContext>();
    }
  }

  // TODO(@jasnell): Possibly handle other bits. Such a pfx, client cert engine,
  // and session timeout.
  return BaseObjectPtr<crypto::SecureContext>(context);
}

void enable_trace(Environment* env, crypto::BIOPointer* bio, SSL* ssl) {
#if HAVE_SSL_TRACE
  static bool warn_trace_tls = true;
    if (warn_trace_tls) {
      warn_trace_tls = false;
      ProcessEmitWarning(env,
                         "Enabling --trace-tls can expose sensitive data in "
                         "the resulting log");
    }
  if (!*bio) {

    bio->reset(BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT));
    SSL_set_msg_callback(
        ssl,
        [](int write_p,
           int version,
           int content_type,
           const void* buf,
           size_t len,
           SSL* ssl,
           void* arg) -> void {
          crypto::MarkPopErrorOnReturn mark_pop_error_on_return;
          SSL_trace(write_p, version, content_type, buf, len, ssl, arg);
        });
    SSL_set_msg_callback_arg(ssl, bio->get());
  }
#endif
}

}  // namespace

CryptoContext::CryptoContext(Environment* env,
                             CryptoContext::Side side,
                             Session* session,
                             const Options& options)
    : conn_ref_({getConnection, this}),
      side_(side),
      session_(session),
      options_(options),
      secure_context_(InitializeSecureContext(side, *session, options)) {
  CHECK(secure_context_);
  ssl_.reset(SSL_new(secure_context_->ctx().get()));
  CHECK(ssl_ && SSL_is_quic(ssl_.get()));

  SSL_set_app_data(ssl_.get(), &conn_ref_);

  SSL_set_verify(ssl_.get(), SSL_VERIFY_NONE, crypto::VerifyCallback);

  // Enable tracing if the `--trace-tls` command line flag is used.
  if (UNLIKELY(env->options()->trace_tls || options.enable_tls_trace))
    enable_trace(env, &bio_trace_, ssl_.get());

  switch (side) {
    case Side::CLIENT: {
      SSL_set_connect_state(ssl_.get());
      CHECK_EQ(0, SSL_set_alpn_protos(
          ssl_.get(),
          reinterpret_cast<const unsigned char*>(requested_alpn().begin()),
          requested_alpn().length()));
      CHECK_EQ(0, SSL_set_tlsext_host_name(ssl_.get(),
          requested_servername().begin()));
      break;
    }
    case Side::SERVER: {
      SSL_set_accept_state(ssl_.get());
      if (options.request_peer_certificate) {
        int verify_mode = SSL_VERIFY_PEER;
        if (options.reject_unauthorized)
          verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_set_verify(ssl_.get(), verify_mode, crypto::VerifyCallback);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void CryptoContext::Start() {
  ngtcp2_conn_set_tls_native_handle(*session_, ssl_.get());

  const ngtcp2_transport_params* params =
      ngtcp2_conn_get_local_transport_params(*session_);
  uint8_t buf[512];
  ssize_t nwrite = ngtcp2_encode_transport_params(
      buf,
      arraysize(buf),
      NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
      params);
  if (nwrite >= 0) SSL_set_quic_transport_params(ssl_.get(), buf, nwrite);
}

void CryptoContext::Keylog(const char* line) const {
  session_->EmitKeylog(line);
}

int CryptoContext::Receive(ngtcp2_crypto_level crypto_level,
                           uint64_t offset,
                           const uint8_t* data,
                           size_t datalen) {
  // ngtcp2 provides an implementation of this in
  // ngtcp2_crypto_recv_crypto_data_cb but given that we are using the
  // implementation specific error codes below, we can't use it.

  if (UNLIKELY(session_->is_destroyed())) return NGTCP2_ERR_CALLBACK_FAILURE;

  // Internally, this passes the handshake data off to openssl for processing.
  // The handshake may or may not complete.
  int ret = ngtcp2_crypto_read_write_crypto_data(
      *session_, crypto_level, data, datalen);

  switch (ret) {
    case 0:
    // Fall-through

    // In either of following cases, the handshake is being paused waiting for
    // user code to take action (for instance OCSP requests or client hello
    // modification)
    case NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_X509_LOOKUP:
      // Fall-through
    case NGTCP2_CRYPTO_OPENSSL_ERR_TLS_WANT_CLIENT_HELLO_CB:
      return 0;
  }
  return ret;
}

int CryptoContext::OnNewSession(SSL_SESSION* session) {
  // Used to generate and emit a SessionTicket for TLS session resumption.

  // If there is nothing listening for the session ticket, don't both emitting.
  if (LIKELY(session_->state_->session_ticket == 0)) return 0;

  // Pre-fight to see how much space we need to allocate for the session ticket.
  size_t size = i2d_SSL_SESSION(session, nullptr);

  if (size > 0 && size < crypto::SecureContext::kMaxSessionSize) {
    // Generate the actual ticket. If this fails, we'll simply carry on without
    // emitting the ticket.
    std::shared_ptr<BackingStore> ticket = ArrayBuffer::NewBackingStore(
        session_->env()->isolate(), size);
    unsigned char* data = reinterpret_cast<unsigned char*>(ticket->Data());
    if (i2d_SSL_SESSION(session, &data) <= 0) return 0;
    session_->EmitSessionTicket(Store(std::move(ticket), size));
  }
  // If size == 0, there's no session ticket data to emit. Let's ignore it
  // and continue without emitting the sessionticket event.

  return 0;
}

bool CryptoContext::InitiateKeyUpdate() {
  if (session_->is_destroyed() || in_key_update_) return false;
  auto leave = OnScopeLeave([this] { in_key_update_ = false; });
  in_key_update_ = true;

  session_->stats_.Increment<&Session::Stats::keyupdate_count>();
  return ngtcp2_conn_initiate_key_update(*session_, uv_hrtime()) == 0;
}

int CryptoContext::VerifyPeerIdentity() {
  return crypto::VerifyPeerCertificate(ssl_);
}

void CryptoContext::MaybeSetEarlySession(
    const BaseObjectPtr<SessionTicket>& sessionTicket) {
  // Nothing to do if there is no ticket
  if (!sessionTicket) return;

  Session::TransportParams rtp(
      Session::TransportParams::Type::ENCRYPTED_EXTENSIONS,
      sessionTicket->transport_params());

  // Ignore invalid remote transport parameters.
  if (!rtp) return;

  uv_buf_t buf = sessionTicket->ticket();
  crypto::SSLSessionPointer ticket = crypto::GetTLSSession(
      reinterpret_cast<unsigned char*>(buf.base), buf.len);

  // Silently ignore invalid TLS session
  if (!ticket || !SSL_SESSION_get_max_early_data(ticket.get())) return;

  // The early data will just be ignored if it's invalid.
  if (crypto::SetTLSSession(ssl_, ticket)) {
    ngtcp2_conn_set_early_remote_transport_params(*session_, rtp);
    session_->state_->stream_open_allowed = 1;
  }
}

void CryptoContext::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
  tracker->TrackField("secure_context", secure_context_);
}

v8::MaybeLocal<v8::Object> CryptoContext::cert(Environment* env) const {
  return crypto::X509Certificate::GetCert(env, ssl_);
}

v8::MaybeLocal<v8::Object> CryptoContext::peer_cert(Environment* env) const {
  crypto::X509Certificate::GetPeerCertificateFlag flag =
      side_ == Side::SERVER ?
          crypto::X509Certificate::GetPeerCertificateFlag::SERVER :
          crypto::X509Certificate::GetPeerCertificateFlag::NONE;
  return crypto::X509Certificate::GetPeerCert(env, ssl_, flag);
}

v8::MaybeLocal<v8::Value> CryptoContext::cipher_name(Environment* env) const {
  return crypto::GetCurrentCipherName(env, ssl_);
}

v8::MaybeLocal<v8::Value> CryptoContext::cipher_version(
    Environment* env) const {
  return crypto::GetCurrentCipherVersion(env, ssl_);
}

v8::MaybeLocal<v8::Object> CryptoContext::ephemeral_key(
    Environment* env) const {
  return crypto::GetEphemeralKey(env, ssl_);
}

std::string CryptoContext::servername() const {
  const char* servername = crypto::GetServerName(ssl_.get());
  return servername != nullptr ? std::string(servername) : std::string();
}

std::string CryptoContext::selected_alpn() const {
  const unsigned char* alpn_buf = nullptr;
  unsigned int alpnlen;
  SSL_get0_alpn_selected(ssl_.get(), &alpn_buf, &alpnlen);
  return alpnlen ? std::string(reinterpret_cast<const char*>(alpn_buf), alpnlen)
                 : std::string();
}

const std::string_view CryptoContext::requested_alpn() const {
  return options_.alpn;
}

const std::string_view CryptoContext::requested_servername() const {
  return options_.hostname;
}

bool CryptoContext::was_early_data_accepted() const {
  return (early_data_ &&
          SSL_get_early_data_status(ssl_.get()) == SSL_EARLY_DATA_ACCEPTED);
}

void CryptoContext::Options::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("keys", keys);
  tracker->TrackField("certs", certs);
  tracker->TrackField("ca", ca);
  tracker->TrackField("crl", crl);
}

ngtcp2_conn* CryptoContext::getConnection(ngtcp2_crypto_conn_ref* ref) {
  CryptoContext* context = ContainerOf(&CryptoContext::conn_ref_, ref);
  return *context->session_;
}

}  // namespace quic
}  // namespace node
