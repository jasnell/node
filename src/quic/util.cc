#include "util-inl.h"
#include "bindingdata-inl.h"
#include <req_wrap-inl.h>

namespace node {

using v8::BigInt;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::Value;

namespace quic {

// ============================================================================

Local<FunctionTemplate> Packet::GetConstructorTemplate(Environment* env) {
  auto& state = BindingData::Get(env);
  Local<FunctionTemplate> tmpl = state.send_wrap_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = NewFunctionTemplate(env->isolate(), IllegalConstructor);
    tmpl->Inherit(ReqWrap<uv_udp_send_t>::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Packet::kInternalFieldCount);
    tmpl->SetClassName(state.packetwrap_string());
    state.set_send_wrap_constructor_template(tmpl);
  }
  return tmpl;
}

BaseObjectPtr<Packet> Packet::Create(
    Environment* env,
    Listener* listener,
    const SocketAddress& destination,
    size_t length,
    const char* diagnostic_label) {
  Local<Object> obj;
  if (UNLIKELY(!GetConstructorTemplate(env)
                    ->InstanceTemplate()
                    ->NewInstance(env->context())
                    .ToLocal(&obj))) {
    return BaseObjectPtr<Packet>();
  }

  return MakeBaseObject<Packet>(
      env, listener, obj, destination, length, diagnostic_label);
}

BaseObjectPtr<Packet> Packet::Clone() const {
  Local<Object> obj;
  if (UNLIKELY(!GetConstructorTemplate(env())
                    ->InstanceTemplate()
                    ->NewInstance(env()->context())
                    .ToLocal(&obj))) {
    return BaseObjectPtr<Packet>();
  }

  return MakeBaseObject<Packet>(env(), listener_, obj, destination_, data_);
}

Packet::Packet(Environment* env,
               Listener* listener,
               v8::Local<v8::Object> object,
               const SocketAddress& destination,
               std::shared_ptr<Data> data)
    : ReqWrap<uv_udp_send_t>(env, object, AsyncWrap::PROVIDER_QUIC_PACKET),
      listener_(listener),
      destination_(destination),
      data_(std::move(data)) {}

Packet::Packet(Environment* env,
               Listener* listener,
               v8::Local<v8::Object> object,
               const SocketAddress& destination,
               size_t length,
               const char* diagnostic_label)
    : Packet(env,
             listener,
             object,
             destination,
             std::make_shared<Data>(length, diagnostic_label)) {}

void Packet::Done(int status) {
  CHECK_NOT_NULL(listener_);
  listener_->PacketDone(status);
  handle_.reset();
  listener_ = nullptr;
}

std::string Packet::ToString() const {
  if (!data_) return "Packet (<empty>)";
  return std::string("Packet (") + data_->diagnostic_label_ + ", " +
         std::to_string(data_->length()) + ")";
}

void Packet::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("destination", destination_);
  tracker->TrackField("data", data_);
  tracker->TrackField("handle", handle_);
}

Packet::Data::Data(size_t length, const char* diagnostic_label)
    : diagnostic_label_(diagnostic_label) {
  data_.AllocateSufficientStorage(length);
}

void Packet::Data::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("data", data_.length());
}

size_t Packet::Data::length() const { return data_.length(); }
uint8_t* Packet::Data::data() { return data_.out(); }

// ============================================================================

void Store::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("store", store_);
}

Store::Store(std::shared_ptr<v8::BackingStore> store,
             size_t length,
             size_t offset)
    : store_(std::move(store)),
      offset_(offset),
      length_(length) {}

Store::Store(std::unique_ptr<v8::BackingStore> store,
             size_t length,
             size_t offset)
    : store_(std::move(store)),
      offset_(offset),
      length_(length) {}

Store::Store(v8::Local<v8::ArrayBuffer> buffer,
             Option option)
    : Store(buffer->GetBackingStore(), buffer->ByteLength()) {
  if (option == Option::DETACH) {
    USE(buffer->Detach(v8::Local<v8::Object>()));
  }
}

Store::Store(v8::Local<v8::ArrayBufferView> view,
             Option option)
    : Store(view->Buffer()->GetBackingStore(),
            view->ByteLength(),
            view->ByteOffset()) {
  if (option == Option::DETACH) {
    USE(view->Buffer()->Detach(v8::Local<v8::Object>()));
  }
}

// ============================================================================

inline QuicError::QuicError(const std::string_view reason)
    : reason_(reason),
      ptr_(&error_) {
  ngtcp2_connection_close_error_default(&error_);
}

QuicError::QuicError(const ngtcp2_connection_close_error* ptr)
    : reason_(reinterpret_cast<const char*>(ptr->reason), ptr->reasonlen),
      ptr_(ptr) {}

QuicError::QuicError(const ngtcp2_connection_close_error& error)
    : reason_(reinterpret_cast<const char*>(error.reason), error.reasonlen),
      error_(error) {}

const uint8_t* QuicError::reason_c_str() const {
  return reinterpret_cast<const uint8_t*>(reason_.c_str());
}

MaybeLocal<Value> QuicError::ToV8Value(Environment* env) {
  Local<Value> argv[] = {
      Integer::New(env->isolate(), static_cast<int>(type())),
      BigInt::NewFromUnsigned(env->isolate(), code()),
      Undefined(env->isolate()),
  };
  if (reason_.length() > 0 &&
      !node::ToV8Value(env->context(), reason()).ToLocal(&argv[2])) {
    return MaybeLocal<Value>();
  }
  return v8::Array::New(env->isolate(), argv, arraysize(argv)).As<Value>();
}

namespace {
std::string TypeName(QuicError::Type type) {
  switch (type) {
    case QuicError::Type::APPLICATION:
      return "APPLICATION";
    case QuicError::Type::TRANSPORT:
      return "TRANSPORT";
    case QuicError::Type::VERSION_NEGOTIATION:
      return "VERSION_NEGOTIATION";
    case QuicError::Type::IDLE_CLOSE:
      return "IDLE_CLOSE";
  }
  UNREACHABLE();
}
}  // namespace

QuicError QuicError::ForTransport(
    error_code code,
    const std::string_view reason) {
  QuicError error(reason);
  ngtcp2_connection_close_error_set_transport_error(
      &error.error_, code, error.reason_c_str(), reason.length());
  return error;
}

QuicError QuicError::ForApplication(
    error_code code,
    const std::string_view reason) {
  QuicError error(reason);
  ngtcp2_connection_close_error_set_application_error(
      &error.error_, code, error.reason_c_str(), reason.length());
  return error;
}

QuicError QuicError::ForVersionNegotiation(const std::string_view reason) {
  QuicError error(reason);
  ngtcp2_connection_close_error_set_transport_error_liberr(
      &error.error_,
      NGTCP2_ERR_RECV_VERSION_NEGOTIATION,
      error.reason_c_str(),
      reason.length());
  return error;
}

QuicError QuicError::ForIdleClose(const std::string_view reason) {
  QuicError error(reason);
  ngtcp2_connection_close_error_set_transport_error_liberr(
      &error.error_,
      NGTCP2_ERR_IDLE_CLOSE,
      error.reason_c_str(),
      reason.length());
  return error;
}

QuicError QuicError::ForNgtcp2Error(
    int code,
    const std::string_view reason) {
  QuicError error(reason);
  ngtcp2_connection_close_error_set_transport_error_liberr(
      &error.error_, code, error.reason_c_str(), reason.length());
  return error;
}

QuicError QuicError::ForTlsAlert(
    int code,
    const std::string_view reason) {
  QuicError error(reason);
  ngtcp2_connection_close_error_set_transport_error_tls_alert(
      &error.error_, code, error.reason_c_str(), reason.length());
  return error;
}

QuicError QuicError::FromConnectionClose(ngtcp2_conn* session) {
  QuicError error;
  ngtcp2_conn_get_connection_close_error(session, &error.error_);
  return error;
}

std::string QuicError::ToString() const {
  auto str = std::string("QuicError(") + TypeName(type()) + ") " +
             std::to_string(code());
  if (reason_.length() > 0) str += ": " + reason_;
  return str;
}

void QuicError::MemoryInfo(MemoryTracker* tracker) const {
  if (ptr_ == &error_) tracker->TrackField("reason", reason_);
}

QuicError QuicError::TRANSPORT_NO_ERROR =
    QuicError::ForTransport(NGTCP2_NO_ERROR);
QuicError QuicError::APPLICATION_NO_ERROR =
    QuicError::ForApplication(NGTCP2_APP_NOERROR);
QuicError QuicError::VERSION_NEGOTIATION =
    QuicError::ForVersionNegotiation();
QuicError QuicError::IDLE_CLOSE =
    QuicError::ForIdleClose();

// ============================================================================

StatsBase::StatsBase(Environment* env, size_t size)
    : stats_store_(
          v8::ArrayBuffer::NewBackingStore(env->isolate(), size)) {}

v8::Local<v8::BigUint64Array> StatsBase::ToBigUint64Array(Environment* env) {
  size_t size = stats_store_->ByteLength();
  size_t count = size / sizeof(uint64_t);
  v8::Local<v8::ArrayBuffer> stats_buffer =
      v8::ArrayBuffer::New(env->isolate(), stats_store_);
  auto ret = v8::BigUint64Array::New(stats_buffer, 0, count);
  stats_buffer->SetIntegrityLevel(env->context(), v8::IntegrityLevel::kSealed);
  ret->SetIntegrityLevel(env->context(), v8::IntegrityLevel::kSealed);
  return ret;
}

void StatsBase::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("stats_store", stats_store_);
}

CallbackScopeBase::CallbackScopeBase(Environment* env)
    : env(env),
      context_scope(env->context()),
      try_catch(env->isolate()) {}

CallbackScopeBase::~CallbackScopeBase() {
  if (try_catch.HasCaught() && !try_catch.HasTerminated()) {
    errors::TriggerUncaughtException(env->isolate(), try_catch);
  }
}

// ============================================================================

void IllegalConstructor(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  THROW_ERR_ILLEGAL_CONSTRUCTOR(Environment::GetCurrent(args));
}

}  // namespace quic
}  // namespace node
