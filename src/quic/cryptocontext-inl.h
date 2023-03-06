#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "cryptocontext.h"
#include "openssl/ssl.h"

namespace node {
namespace quic {

const Session& CryptoContext::session() const { return *session_; }
CryptoContext::Side CryptoContext::side() const { return side_; }

inline const CryptoContext& CryptoContext::From(const SSL* ssl) {
  auto ref = static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl));
  CryptoContext* context = ContainerOf(&CryptoContext::conn_ref_, ref);
  return *context;
}

inline CryptoContext& CryptoContext::From(SSL* ssl) {
  auto ref = static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl));
  CryptoContext* context = ContainerOf(&CryptoContext::conn_ref_, ref);
  return *context;
}

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
