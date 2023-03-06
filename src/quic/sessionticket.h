#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "defs.h"
#include "util.h"
#include <base_object.h>
#include <node_external_reference.h>
#include <crypto/crypto_common.h>

namespace node {
namespace quic {

// A TLS 1.3 Session resumption ticket. Encapsulates both the TLS
// ticket and the encoded QUIC transport parameters. The structure
// should be considered to be opaque for end users.
class SessionTicket final : public BaseObject {
 public:
  HAS_INSTANCE()
  GET_CONSTRUCTOR_TEMPLATE()
  static void Initialize(Environment* env, v8::Local<v8::Object> target);
  static void RegisterExternalReferences(ExternalReferenceRegistry* registry);

  static BaseObjectPtr<SessionTicket> Create(Environment* env,
                                             Store&& ticket,
                                             Store&& transport_params);

  SessionTicket(Environment* env,
                v8::Local<v8::Object> object,
                Store&& ticket,
                Store&& transport_params);

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(SessionTicket)
  SET_SELF_SIZE(SessionTicket)

  uv_buf_t ticket() const;
  ngtcp2_vec transport_params() const;

  class AppData;

 private:
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Encode(const v8::FunctionCallbackInfo<v8::Value>& args);

  Store ticket_;
  Store transport_params_;
};

// SessionTicket::AppData is a utility class that is used only during the
// generation or access of TLS stateless sesson tickets. It exists solely to
// provide a easier way for Session::Application instances to set relevant
// metadata in the session ticket when it is created, and the exract and
// subsequently verify that data when a ticket is received and is being
// validated. The app data is completely opaque to anything other than the
// server-side of the Session::Application that sets it.
class SessionTicket::AppData final {
 public:
  enum class Status {
    TICKET_IGNORE = SSL_TICKET_RETURN_IGNORE,
    TICKET_IGNORE_RENEW = SSL_TICKET_RETURN_IGNORE_RENEW,
    TICKET_USE = SSL_TICKET_RETURN_USE,
    TICKET_USE_RENEW = SSL_TICKET_RETURN_USE_RENEW,
  };

  enum class Flag { STATUS_NONE, STATUS_RENEW };

  explicit AppData(SSL* session);
  QUIC_NO_COPY_OR_MOVE(AppData)

  bool Set(const uint8_t* data, size_t len);
  bool Get(uint8_t** data, size_t* len) const;

  // A source of application data collected during the creation of the
  // session ticket.
  class Source {
   public:
    virtual void CollectSessionTicketAppData(
        AppData* app_data) const = 0;
    virtual Status ExtractSessionTicketAppData(
        const AppData& app_data,
        Flag flag = Flag::STATUS_NONE) = 0;
  };
  static void Collect(SSL* ssl);
  static Status Extract(SSL* ssl);

 private:
  bool set_ = false;
  SSL* ssl_;
};

// The callback that OpenSSL will call when generating the sesson ticket
// and it needs to collect additional application specific data.
int GenerateSessionTicketCallback(SSL* ssl, void* arg);

SSL_TICKET_RETURN DecryptSessionTicketCallback(SSL* ssl,
                                       SSL_SESSION* session,
                                       const unsigned char* keyname,
                                       size_t keyname_len,
                                       SSL_TICKET_STATUS status,
                                       void* arg);

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
