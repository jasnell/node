#include "bindingdata-inl.h"
#include "openssl/ssl.h"
#include "sessionticket.h"
#include "util-inl.h"
#include <base_object-inl.h>
#include <crypto/crypto_util.h>
#include <env-inl.h>
#include <memory_tracker-inl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <node_buffer.h>
#include <v8.h>
#include <optional>

namespace node {

using crypto::ArrayBufferOrViewContents;
using v8::ArrayBufferView;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::Uint8Array;
using v8::Value;

namespace quic {

namespace {
MaybeLocal<Object> encode(Environment* env,
                          const Store& ticket,
                          const Store& transport_params) {
  // The encoded session ticket uses V8 structured serialization
  // (the same serialization format used for structured clone).
  auto context = env->context();
  v8::ValueSerializer ser(env->isolate());
  ser.WriteHeader();

  if (ser.WriteValue(context, ticket.ToArrayBufferView<Uint8Array>(env))
          .IsNothing() ||
      ser.WriteValue(context,
                     transport_params.ToArrayBufferView<Uint8Array>(env))
          .IsNothing()) {
    return MaybeLocal<Object>();
  }

  auto result = ser.Release();

  return Buffer::New(env,
                     reinterpret_cast<char*>(result.first),
                     result.second);
}

std::optional<SessionTicket::AppData::Source*>
get_appdatasource(SSL* ssl) {
  ngtcp2_crypto_conn_ref* ref =
      static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl));
  if (ref != nullptr) {
    auto source = static_cast<SessionTicket::AppData::Source*>(
        ref->user_data);
    if (source != nullptr) {
      return source;
    }
  }
  return std::nullopt;
}
}  // namespace

Local<FunctionTemplate> SessionTicket::GetConstructorTemplate(
    Environment* env) {
  auto& state = BindingData::Get(env);
  auto tmpl = state.sessionticket_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = NewFunctionTemplate(env->isolate(), New);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        SessionTicket::kInternalFieldCount);
    tmpl->SetClassName(state.sessionticket_string());
    SetProtoMethod(env->isolate(), tmpl, "encoded", Encode);
    state.set_sessionticket_constructor_template(tmpl);
  }
  return tmpl;
}

void SessionTicket::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  registry->Register(New);
  registry->Register(Encode);
}

void SessionTicket::Initialize(Environment* env, Local<Object> target) {
  SetConstructorFunction(env->context(),
                         target,
                         "SessionTicket",
                         GetConstructorTemplate(env),
                         SetConstructorFunctionFlag::NONE);
}

BaseObjectPtr<SessionTicket> SessionTicket::Create(
    Environment* env,
    Store&& ticket,
    Store&& transport_params) {
  Local<Object> obj;
  if (UNLIKELY(!GetConstructorTemplate(env)
                    ->InstanceTemplate()
                    ->NewInstance(env->context())
                    .ToLocal(&obj))) {
    return BaseObjectPtr<SessionTicket>();
  }

  return MakeDetachedBaseObject<SessionTicket>(
      env,
      obj,
      std::move(ticket),
      std::move(transport_params));
}

SessionTicket::SessionTicket(
    Environment* env,
    Local<Object> object,
    Store&& ticket,
    Store&& transport_params)
    : BaseObject(env, object),
      ticket_(std::move(ticket)),
      transport_params_(std::move(transport_params)) {
  MakeWeak();
}

void SessionTicket::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("ticket", ticket_);
  tracker->TrackField("transport_params", transport_params_);
}

void SessionTicket::New(const v8::FunctionCallbackInfo<v8::Value>& args) {
  auto env = Environment::GetCurrent(args);
  if (!args[0]->IsArrayBufferView()) {
    THROW_ERR_INVALID_ARG_TYPE(env, "The ticket must be an ArrayBufferView.");
    return;
  }

  auto context = env->context();
  ArrayBufferOrViewContents<uint8_t> view(args[0]);
  v8::ValueDeserializer des(env->isolate(), view.data(), view.size());

  if (des.ReadHeader(context).IsNothing()) {
    THROW_ERR_INVALID_ARG_VALUE(env, "The ticket format is invalid.");
    return;
  }

  Local<Value> ticket;
  Local<Value> transport_params;

  if (!des.ReadValue(context).ToLocal(&ticket) ||
      !ticket->IsArrayBufferView()) {
    THROW_ERR_INVALID_ARG_VALUE(env, "The ticket format is invalid.");
    return;
  }

  if (!des.ReadValue(context).ToLocal(&transport_params) ||
      !transport_params->IsArrayBufferView()) {
    THROW_ERR_INVALID_ARG_VALUE(env, "The ticket format is invalid.");
    return;
  }

  new SessionTicket(env,
                    args.This(),
                    Store(ticket.As<ArrayBufferView>()),
                    Store(transport_params.As<ArrayBufferView>()));
}

void SessionTicket::Encode(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  SessionTicket* sessionTicket;
  ASSIGN_OR_RETURN_UNWRAP(&sessionTicket, args.Holder());
  Local<Object> encoded;
  if (encode(env,
             sessionTicket->ticket_,
             sessionTicket->transport_params_).ToLocal(&encoded)) {
    args.GetReturnValue().Set(encoded);
  }
}

uv_buf_t SessionTicket::ticket() const {
  return ticket_;
}

ngtcp2_vec SessionTicket::transport_params() const {
  return transport_params_;
}

SessionTicket::AppData::AppData(SSL* ssl)
    : ssl_(ssl) {}

bool SessionTicket::AppData::Set(const uint8_t* data, size_t len) {
  if (set_) return false;
  set_ = true;
  SSL_SESSION_set1_ticket_appdata(SSL_get0_session(ssl_), data, len);
  return set_;
}

bool SessionTicket::AppData::Get(uint8_t** data, size_t* len) const {
  return SSL_SESSION_get0_ticket_appdata(
      SSL_get0_session(ssl_),
      reinterpret_cast<void**>(data), len) == 1;
}

void SessionTicket::AppData::Collect(SSL* ssl) {
  auto source = get_appdatasource(ssl);
  if (source != std::nullopt) {
    SessionTicket::AppData app_data(ssl);
    source.value()->CollectSessionTicketAppData(&app_data);
  }
}

SessionTicket::AppData::Status SessionTicket::AppData::Extract(
    SSL* ssl) {
  auto source = get_appdatasource(ssl);
  if (source != std::nullopt) {
    SessionTicket::AppData app_data(ssl);
    return source.value()->ExtractSessionTicketAppData(app_data);
  }
  return Status::TICKET_IGNORE;
}

int GenerateSessionTicketCallback(SSL* ssl, void* arg) {
  SessionTicket::AppData::Collect(ssl);
  return 1;
}

SSL_TICKET_RETURN DecryptSessionTicketCallback(SSL* ssl,
                                       SSL_SESSION* session,
                                       const unsigned char* keyname,
                                       size_t keyname_len,
                                       SSL_TICKET_STATUS status,
                                       void* arg) {
  switch (status) {
    default:
      return SSL_TICKET_RETURN_IGNORE;
    case SSL_TICKET_EMPTY:
      // Fall through
    case SSL_TICKET_NO_DECRYPT:
      return SSL_TICKET_RETURN_IGNORE_RENEW;
    case SSL_TICKET_SUCCESS_RENEW:
      // Fall through
    case SSL_TICKET_SUCCESS:
      return static_cast<SSL_TICKET_RETURN>(
          SessionTicket::AppData::Extract(ssl));
  }
}

}  // namespace quic
}  // namespace node
