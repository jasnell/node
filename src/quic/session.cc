#include "quic/defs.h"
#include "session-inl.h"
#include "streams-inl.h"
#include "endpoint.h"
#include "bindingdata-inl.h"
#include "cryptocontext-inl.h"
#include "http3.h"
#include "preferredaddress.h"
#include "sessionticket.h"
#include "statelessresettoken-inl.h"
#include "util-inl.h"
#include <aliased_struct-inl.h>
#include <async_wrap-inl.h>
#include <stream_base-inl.h>
#include <timer_wrap-inl.h>
#include <v8.h>
#include <ngtcp2/ngtcp2.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::ArrayBufferView;
using v8::BigInt;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Integer;
using v8::Int32;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::PropertyAttribute;
using v8::String;
using v8::Uint8Array;
using v8::Uint32;
using v8::Value;

namespace quic {

class Session::LogStream : public AsyncWrap, public StreamBase {
 public:
  HAS_INSTANCE()
  static Local<FunctionTemplate> GetConstructorTemplate(
      Environment* env) {
    auto& state = BindingData::Get(env);
    Local<FunctionTemplate> tmpl =
        state.logstream_constructor_template();
    if (tmpl.IsEmpty()) {
      tmpl = FunctionTemplate::New(env->isolate());
      tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
      tmpl->InstanceTemplate()->SetInternalFieldCount(
          StreamBase::kInternalFieldCount);
      tmpl->SetClassName(state.logstream_string());
      StreamBase::AddMethods(env, tmpl);
      state.set_logstream_constructor_template(tmpl);
    }
    return tmpl;
  }
  static BaseObjectPtr<LogStream> Create(Environment* env) {
    v8::Local<v8::Object> obj;
    if (!GetConstructorTemplate(env)
             ->InstanceTemplate()
             ->NewInstance(env->context())
             .ToLocal(&obj)) {
      return BaseObjectPtr<LogStream>();
    }
    return MakeDetachedBaseObject<LogStream>(env, obj);
  }

  LogStream(Environment* env, Local<Object> obj)
      : AsyncWrap(env, obj, AsyncWrap::PROVIDER_QUIC_LOGSTREAM),
        StreamBase(env) {
    MakeWeak();
    StreamBase::AttachToObject(GetObject());
  }

  enum class EmitOption {
    NONE,
    FIN,
  };

  void Emit(const uint8_t* data, size_t len, EmitOption option = EmitOption::NONE) {
    if (fin_seen_) return;
    fin_seen_ = option == EmitOption::FIN;

    size_t remaining = len;
    // If the len is greater than the size of the buffer returned by
    // EmitAlloc then EmitRead will be called multiple times.
    while (remaining != 0) {
      uv_buf_t buf = EmitAlloc(len);
      size_t len = std::min<size_t>(remaining, buf.len);
      memcpy(buf.base, data, len);
      remaining -= len;
      data += len;
      // If we are actively reading from the stream, we'll call emit
      // read immediately. Otherwise we buffer the chunk and will push
      // the chunks out the next time ReadStart() is called.
      if (reading_) {
        EmitRead(len, buf);
      } else {
        // The total measures the total memory used so we always
        // increment but buf.len and not chunk len.
        ensure_space(buf.len);
        total_ += buf.len;
        buffer_.push_back(Chunk{ len, buf });
      }
    }

    if (ended_ && reading_) {
      EmitRead(UV_EOF);
    }
  }

  void Emit(const std::string_view line, EmitOption option = EmitOption::NONE) {
    Emit(reinterpret_cast<const uint8_t*>(
        line.begin()),
        line.length(),
        option);
  }

  void End() { ended_ = true; }

  int ReadStart() override {
    if (reading_) return 0;
    // Flush any chunks that have already been buffered.
    for (const auto& chunk : buffer_) EmitRead(chunk.len, chunk.buf);
    total_ = 0;
    buffer_.clear();
    if (fin_seen_) {
      // If we've already received the fin, there's nothing else to wait for.
      EmitRead(UV_EOF);
      return ReadStop();
    } else {
      // Otherwise, we're going to wait for more chunks to be written.
      reading_ = true;
    }
    return 0;
  }

  int ReadStop() override {
    reading_ = false;
    return 0;
  }

  // We do not use either of these.
  int DoShutdown(ShutdownWrap* req_wrap) override { UNREACHABLE(); }
  int DoWrite(WriteWrap* w,
              uv_buf_t* bufs,
              size_t count,
              uv_stream_t* send_handle) override {
    UNREACHABLE();
  }

  bool IsAlive() override { return !ended_; }
  bool IsClosing() override { return ended_; }
  AsyncWrap* GetAsyncWrap() override { return this; }

  void MemoryInfo(MemoryTracker* tracker) const override {
    tracker->TrackFieldWithSize("buffer", total_);
  }

  SET_MEMORY_INFO_NAME(LogStream);
  SET_SELF_SIZE(LogStream);

 private:
  struct Chunk {
    // len will be <= buf.len
    size_t len;
    uv_buf_t buf;
  };
  size_t total_ = 0;
  bool fin_seen_ = false;
  bool ended_ = false;
  bool reading_ = false;
  std::deque<Chunk> buffer_;

  // The LogStream buffer enforces a maximum size of kMaxLogStreamBuffer.
  void ensure_space(size_t amt) {
    while (total_ + amt > kMaxLogStreamBuffer) {
      total_ -= buffer_.front().buf.len;
      buffer_.pop_front();
    }
  }
};

namespace {
// Qlog is a JSON-based logging format that is being standardized for low-level
// debug logging of QUIC connections and dataflows. The qlog output is generated
// optionally by ngtcp2 for us. The on_qlog_write callback is registered with
// ngtcp2 to emit the qlog information. Every Session will have it's own qlog
// stream.
void on_qlog_write(void* user_data,
                   uint32_t flags,
                   const void* data,
                   size_t len) {
  Session* session = static_cast<Session*>(user_data);

  // Fun fact... ngtcp2 does not emit the final qlog statement until the
  // ngtcp2_conn object is destroyed. Ideally, destroying is explicit, but
  // sometimes the Session object can be garbage collected without being
  // explicitly destroyed. During those times, we cannot call out to JavaScript.
  // Because we don't know for sure if we're in in a GC when this is called, it
  // is safer to just defer writes to immediate, and to keep it consistent,
  // let's just always defer (this is not performance sensitive so the deferring
  // is fine).
  if (session->qlogstream()) {
    std::vector<uint8_t> buffer(len);
    memcpy(buffer.data(), data, len);
    session->env()->SetImmediate(
        [ptr = session->qlogstream(), buffer = std::move(buffer), flags](
            Environment*) {
      ptr->Emit(buffer.data(), buffer.size(),
          flags & NGTCP2_QLOG_WRITE_FLAG_FIN ?
              Session::LogStream::EmitOption::FIN :
              Session::LogStream::EmitOption::NONE);
    });
  }
}

// Forwards detailed(verbose) debugging information from ngtcp2. Enabled using
// the NODE_DEBUG_NATIVE=NGTCP2_DEBUG category.
void ngtcp2_debug_log(void* user_data, const char* fmt, ...) {
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
}  // namespace

// Used to enforce the no-reentry requirement for ngtcp2 callbacks.
// Instances should only ever be stack allocated within the ngtcp2
// callbacks.
struct Session::NgCallbackScope final {
  Session* session;
  explicit NgCallbackScope(Session* session_) : session(session_) {
    CHECK(!session->in_ng_callback_);
    session->in_ng_callback_ = true;
  }
  QUIC_NO_COPY_OR_MOVE(NgCallbackScope)

  ~NgCallbackScope() { session->in_ng_callback_ = false; }

  static bool InNgCallbackScope(const Session& session) {
    return session.in_ng_callback_;
  }
};

// Used to conditionally trigger sending an explicit connection
// close. If there are multiple MaybeCloseConnectionScope in the
// stack, the determination of whether to send the close will be
// done once the final scope is closed.
struct Session::MaybeCloseConnectionScope final {
  Session* session;
  bool silent = false;
  MaybeCloseConnectionScope(Session* session_, bool silent_)
      : session(session_),
        silent(silent_ || session->connection_close_depth_ > 0) {
    session->connection_close_depth_++;
  }
  QUIC_NO_COPY_OR_MOVE(MaybeCloseConnectionScope)
  ~MaybeCloseConnectionScope() noexcept {
    // We only want to trigger the sending the connection close if ...
    // a) Silent is not explicitly true at this scope.
    // b) We're not within the scope of an ngtcp2 callback, and
    // c) We are not already in a closing or draining period.
    session->connection_close_depth_--;
    if (session->connection_close_depth_ == 0 &&
        !silent &&
        !NgCallbackScope::InNgCallbackScope(*session) &&
        !session->is_destroyed() &&
        !session->is_in_closing_period() &&
        !session->is_in_draining_period()) {
      session->SendConnectionClose();
    }
  }
};

Session::SendPendingDataScope::SendPendingDataScope(Session* session_)
    : session(session_) {
  session->send_scope_depth_++;
}

Session::SendPendingDataScope::~SendPendingDataScope() {
  session->send_scope_depth_--;
  if (session->send_scope_depth_ == 0 &&
      !NgCallbackScope::InNgCallbackScope(*session) &&
      !session->is_destroyed() &&
      !session->is_in_closing_period() && !session->is_in_draining_period()) {
    session->SendPendingData();
  }
}

// ============================================================================
// Session::Config

Session::Config::Config(CryptoContext::Side side,
                        const Endpoint& endpoint,
                        const CID& dcid,
                        const SocketAddress& local_address,
                        const SocketAddress& remote_address,
                        quic_version version,
                        quic_version min_version)
    : side(side),
      version(version),
      min_version(min_version),
      // For now, we're always using the default, but we will make this
      // configurable soon.
      cid_factory(CIDFactory::random()),
      local_addr(local_address),
      remote_addr(remote_address),
      dcid(dcid),
      scid(cid_factory.Generate()) {
  ngtcp2_settings_default(this);
  initial_ts = uv_hrtime();

  if (UNLIKELY(endpoint.env()->enabled_debug_list()->enabled(DebugCategory::NGTCP2_DEBUG))) {
    log_printf = ngtcp2_debug_log;
  }

  auto& config = endpoint.options();

  cc_algo = config.cc_algorithm;
  max_udp_payload_size = config.max_payload_size;

  if (config.max_window_override > 0) max_window = config.max_window_override;

  if (config.max_stream_window_override > 0)
    max_stream_window = config.max_stream_window_override;

  if (config.unacknowledged_packet_threshold > 0)
    ack_thresh = config.unacknowledged_packet_threshold;
}

void Session::Config::EnableQLog(const CID& ocid) {
  if (ocid) {
    qlog.odcid = ocid;
    this->ocid = ocid;
  }
  qlog.write = on_qlog_write;
}

// ======================================================================================
// Session::Options and OptionsObject

namespace {
  // The Options object that is actually created by user code to pass in the
  // values for the options struct.
class OptionsObject final : public BaseObject {
  public:
  HAS_INSTANCE()
  GET_CONSTRUCTOR_TEMPLATE();
  static void Initialize(Environment* env, v8::Local<v8::Object> target);
  static void RegisterExternalReferences(ExternalReferenceRegistry* registry);

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);

  OptionsObject(Environment* env, v8::Local<v8::Object> object);
  QUIC_NO_COPY_OR_MOVE(OptionsObject)

  operator const Session::Options&() const;

  void MemoryInfo(MemoryTracker*) const override;
  SET_MEMORY_INFO_NAME(OptionsObject)
  SET_SELF_SIZE(OptionsObject);

  private:
  template <typename Opt>
  bool SetOption(Opt* options,
                  const v8::Local<v8::Object>& object,
                  const v8::Local<v8::String>& name,
                  bool Opt::*member);

  template <typename Opt>
  bool SetOption(Opt* options,
                  const v8::Local<v8::Object>& object,
                  const v8::Local<v8::String>& name,
                  uint64_t Opt::*member);

  template <typename Opt>
  bool SetOption(Opt* options,
                  const v8::Local<v8::Object>& object,
                  const v8::Local<v8::String>& name,
                  uint32_t Opt::*member);

  template <typename Opt>
  bool SetOption(Opt* options,
                  const v8::Local<v8::Object>& object,
                  const v8::Local<v8::String>& name,
                  std::string Opt::*member);

  template <typename Opt>
  bool SetOption(
      Opt* options,
      const v8::Local<v8::Object>& object,
      const v8::Local<v8::String>& name,
      std::vector<std::shared_ptr<crypto::KeyObjectData>> Opt::*member);

  template <typename Opt>
  bool SetOption(Opt* options,
                  const v8::Local<v8::Object>& object,
                  const v8::Local<v8::String>& name,
                  std::vector<Store> Opt::*member);

  Session::Options options_;
};

OptionsObject::operator const Session::Options&() const {
  return options_;
}

void OptionsObject::Initialize(Environment* env,
                                        Local<Object> target) {
  SetConstructorFunction(env->context(),
                         target,
                         "SessionOptions",
                         GetConstructorTemplate(env),
                         SetConstructorFunctionFlag::NONE);
}

void OptionsObject::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  registry->Register(New);
}

Local<FunctionTemplate> OptionsObject::GetConstructorTemplate(
    Environment* env) {
  auto& state = BindingData::Get(env);
  Local<FunctionTemplate> tmpl = state.session_options_constructor_template();
  if (tmpl.IsEmpty()) {
    auto isolate = env->isolate();
    tmpl = NewFunctionTemplate(isolate, New);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        OptionsObject::kInternalFieldCount);
    tmpl->SetClassName(state.session_options_string());
    state.set_session_options_constructor_template(tmpl);
  }
  return tmpl;
}

OptionsObject::OptionsObject(Environment* env,
                                      v8::Local<v8::Object> object)
    : BaseObject(env, object) {
  MakeWeak();
}

template <typename Opt>
bool OptionsObject::SetOption(Opt* options,
                                       const Local<Object>& object,
                                       const Local<String>& name,
                                       uint64_t Opt::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return false;

  if (!value->IsUndefined()) {
    CHECK_IMPLIES(!value->IsBigInt(), value->IsNumber());

    uint64_t val = 0;
    if (value->IsBigInt()) {
      bool lossless = true;
      val = value.As<BigInt>()->Uint64Value(&lossless);
      if (!lossless) {
        Utf8Value label(env()->isolate(), name);
        THROW_ERR_OUT_OF_RANGE(
            env(),
            (std::string("options.") + (*label) + " is out of range").c_str());
        return false;
      }
    } else {
      val = static_cast<int64_t>(value.As<Number>()->Value());
    }
    options->*member = val;
  }
  return true;
}

template <typename Opt>
bool OptionsObject::SetOption(Opt* options,
                                       const Local<Object>& object,
                                       const Local<String>& name,
                                       uint32_t Opt::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return false;

  if (!value->IsUndefined()) {
    CHECK(value->IsUint32());
    uint32_t val = value.As<Uint32>()->Value();
    options->*member = val;
  }
  return true;
}

template <typename Opt>
bool OptionsObject::SetOption(Opt* options,
                                       const Local<Object>& object,
                                       const Local<String>& name,
                                       bool Opt::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return false;
  if (!value->IsUndefined()) {
    CHECK(value->IsBoolean());
    options->*member = value->IsTrue();
  }
  return true;
}

template <typename Opt>
bool OptionsObject::SetOption(Opt* options,
                                       const Local<Object>& object,
                                       const Local<String>& name,
                                       std::string Opt::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return false;
  if (!value->IsUndefined()) {
    Utf8Value val(env()->isolate(), value);
    options->*member = val.ToString();
  }
  return true;
}

template <typename Opt>
bool OptionsObject::SetOption(
    Opt* options,
    const Local<Object>& object,
    const Local<String>& name,
    std::vector<std::shared_ptr<crypto::KeyObjectData>> Opt::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return false;

  if (value->IsArray()) {
    auto context = env()->context();
    auto values = value.As<v8::Array>();
    uint32_t count = values->Length();
    for (uint32_t n = 0; n < count; n++) {
      Local<Value> item;
      if (!values->Get(context, n).ToLocal(&item)) {
        return false;
      }
      if (crypto::KeyObjectHandle::HasInstance(env(), item)) {
        crypto::KeyObjectHandle* handle;
        ASSIGN_OR_RETURN_UNWRAP(&handle, item, false);
        (options->*member).push_back(handle->Data());
      }
    }
  } else if (crypto::KeyObjectHandle::HasInstance(env(), value)) {
    crypto::KeyObjectHandle* handle;
    ASSIGN_OR_RETURN_UNWRAP(&handle, value, false);
    (options->*member).push_back(handle->Data());
  } else {
    UNREACHABLE();
  }
  return true;
}

template <typename Opt>
bool OptionsObject::SetOption(Opt* options,
                                       const Local<Object>& object,
                                       const Local<String>& name,
                                       std::vector<Store> Opt::*member) {
  Local<Value> value;
  if (!object->Get(env()->context(), name).ToLocal(&value))
    return false;

  if (value->IsArray()) {
    auto context = env()->context();
    auto values = value.As<v8::Array>();
    uint32_t count = values->Length();
    for (uint32_t n = 0; n < count; n++) {
      Local<Value> item;
      if (!values->Get(context, n).ToLocal(&item)) {
        return false;
      }
      if (item->IsArrayBufferView()) {
        Store store(item.As<ArrayBufferView>());
        (options->*member).push_back(std::move(store));
      }
    }
  } else if (value->IsArrayBufferView()) {
    Store store(value.As<ArrayBufferView>());
    (options->*member).push_back(std::move(store));
  }

  return true;
}

void OptionsObject::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  auto env = Environment::GetCurrent(args);
  auto& state = BindingData::Get(env);

  static constexpr auto kAlpn = 0;
  static constexpr auto kHostname = 1;
  static constexpr auto kPreferredAddressStrategy = 2;
  static constexpr auto kConnectionIdFactory = 3;
  static constexpr auto kQlogEnabled = 4;
  static constexpr auto kTlsOptions = 5;
  static constexpr auto kApplicationOptions = 6;
  static constexpr auto kTransportParams = 7;
  static constexpr auto kIpv4PreferredAddress = 8;
  static constexpr auto kIpv6PreferredAddress = 9;

  CHECK(args[kAlpn]->IsString());
  CHECK_IMPLIES(!args[kHostname]->IsUndefined(), args[kHostname]->IsString());
  CHECK_IMPLIES(!args[kPreferredAddressStrategy]->IsUndefined(),
                args[kPreferredAddressStrategy]->IsInt32());
  CHECK_IMPLIES(!args[kConnectionIdFactory]->IsUndefined(),
                args[kConnectionIdFactory]->IsObject());
  CHECK_IMPLIES(!args[kQlogEnabled]->IsUndefined(),
                args[kQlogEnabled]->IsBoolean());
  CHECK_IMPLIES(!args[kTlsOptions]->IsUndefined(),
                args[kTlsOptions]->IsObject());
  CHECK_IMPLIES(!args[kApplicationOptions]->IsUndefined(),
                args[kApplicationOptions]->IsObject());
  CHECK_IMPLIES(!args[kTransportParams]->IsUndefined(),
                args[kTransportParams]->IsObject());
  CHECK_IMPLIES(
      !args[kIpv4PreferredAddress]->IsUndefined(),
      SocketAddressBase::HasInstance(env, args[kIpv4PreferredAddress]));
  CHECK_IMPLIES(
      !args[kIpv6PreferredAddress]->IsUndefined(),
      SocketAddressBase::HasInstance(env, args[kIpv6PreferredAddress]));

  OptionsObject* options = new OptionsObject(env, args.This());

  Utf8Value alpn(env->isolate(), args[kAlpn]);
  options->options_.crypto_options.alpn = std::string(1, alpn.length()) + (*alpn);

  if (!args[kHostname]->IsUndefined()) {
    Utf8Value hostname(env->isolate(), args[kHostname]);
    options->options_.crypto_options.hostname = *hostname;
  }

  if (!args[kPreferredAddressStrategy]->IsUndefined()) {
    auto value = args[kPreferredAddressStrategy].As<Int32>()->Value();
    if (value < 0 || value > static_cast<int>(PreferredAddress::Policy::USE)) {
      THROW_ERR_INVALID_ARG_VALUE(env, "Invalid preferred address policy.");
      return;
    }
    options->options_.preferred_address_strategy =
        static_cast<PreferredAddress::Policy>(value);
  }

  // TODO(@jasnell): Skipping this for now
  // Add support for the other strategies once implemented
  // if (RandomConnectionIDBase::HasInstance(env, args[5])) {
  //   RandomConnectionIDBase* cid_strategy;
  //   ASSIGN_OR_RETURN_UNWRAP(&cid_strategy, args[5]);
  //   options->options()->cid_strategy = cid_strategy->strategy();
  //   options->options()->cid_strategy_strong_ref.reset(cid_strategy);
  // } else {
  //   UNREACHABLE();
  // }

  options->options_.qlog = args[kQlogEnabled]->IsTrue();

  if (!args[kTlsOptions]->IsUndefined()) {
    // TLS Options
    Local<Object> tls_options = args[kTlsOptions].As<Object>();

    if (UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.reject_unauthorized_string(),
                                 &CryptoContext::Options::reject_unauthorized)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.enable_tls_trace_string(),
                                 &CryptoContext::Options::enable_tls_trace)) ||
        UNLIKELY(
            options
                ->SetOption(&options->options_.crypto_options,
                            tls_options,
                            state.request_peer_certificate_string(),
                            &CryptoContext::Options::request_peer_certificate)) ||
        UNLIKELY(
            options
                ->SetOption(&options->options_.crypto_options,
                            tls_options,
                            state.verify_hostname_identity_string(),
                            &CryptoContext::Options::verify_hostname_identity)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.keylog_string(),
                                 &CryptoContext::Options::keylog)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.session_id_string(),
                                 &CryptoContext::Options::session_id_ctx)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.ciphers_string(),
                                 &CryptoContext::Options::ciphers)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.groups_string(),
                                 &CryptoContext::Options::groups)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.keys_string(),
                                 &CryptoContext::Options::keys)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.certs_string(),
                                 &CryptoContext::Options::certs)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.ca_string(),
                                 &CryptoContext::Options::ca)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.crypto_options,
                                 tls_options,
                                 state.crl_string(),
                                 &CryptoContext::Options::crl))) {
      return;  // Failed!
    }
  }

  if (!args[kApplicationOptions]->IsUndefined()) {
    Local<Object> app_options = args[kApplicationOptions].As<Object>();

    if (UNLIKELY(options
                     ->SetOption(&options->options_.application,
                                 app_options,
                                 state.max_header_pairs_string(),
                                 &Session::Application::Options::max_header_pairs)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.application,
                                 app_options,
                                 state.max_header_length_string(),
                                 &Session::Application::Options::max_header_length)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.application,
                                 app_options,
                                 state.max_field_section_size_string(),
                                 &Session::Application::Options::max_field_section_size)) ||
        UNLIKELY(
            options
                ->SetOption(&options->options_.application,
                            app_options,
                            state.qpack_max_table_capacity_string(),
                            &Session::Application::Options::qpack_max_dtable_capacity)) ||
        UNLIKELY(
            options
                ->SetOption(
                    &options->options_.application,
                    app_options,
                    state.qpack_encoder_max_dtable_capacity_string(),
                    &Session::Application::Options::qpack_encoder_max_dtable_capacity)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_.application,
                                 app_options,
                                 state.qpack_blocked_streams_string(),
                                 &Session::Application::Options::qpack_blocked_streams))) {
      // Intentionally do not return here.
    }
  }
  // TODO(@jasnell): Skipping this for now
  // if (Http3OptionsObject::HasInstance(env, args[kApplicationOptions])) {
  //   Http3OptionsObject* http3Options;
  //   ASSIGN_OR_RETURN_UNWRAP(&http3Options, args[kApplicationOptions]);
  //   options->options()->application = http3Options->options();
  // }

  if (!args[kTransportParams]->IsUndefined()) {
    // Transport params
    Local<Object> params = args[kTransportParams].As<Object>();

    if (UNLIKELY(options
                     ->SetOption(
                         &options->options_,
                         params,
                         state.initial_max_stream_data_bidi_local_string(),
                         &Session::Options::initial_max_stream_data_bidi_local)) ||
        UNLIKELY(options
                     ->SetOption(
                         &options->options_,
                         params,
                         state.initial_max_stream_data_bidi_remote_string(),
                         &Session::Options::initial_max_stream_data_bidi_remote)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.initial_max_stream_data_uni_string(),
                                 &Session::Options::initial_max_stream_data_uni)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.initial_max_data_string(),
                                 &Session::Options::initial_max_data)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.initial_max_streams_bidi_string(),
                                 &Session::Options::initial_max_streams_bidi)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.initial_max_streams_uni_string(),
                                 &Session::Options::initial_max_streams_uni)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.max_idle_timeout_string(),
                                 &Session::Options::max_idle_timeout)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.active_connection_id_limit_string(),
                                 &Session::Options::active_connection_id_limit)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.ack_delay_exponent_string(),
                                 &Session::Options::ack_delay_exponent)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.max_ack_delay_string(),
                                 &Session::Options::max_ack_delay)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.max_datagram_frame_size_string(),
                                 &Session::Options::max_datagram_frame_size)) ||
        UNLIKELY(options
                     ->SetOption(&options->options_,
                                 params,
                                 state.disable_active_migration_string(),
                                 &Session::Options::disable_active_migration))) {
      return;
    }
  }

  if (!args[kIpv4PreferredAddress]->IsUndefined()) {
    SocketAddressBase* preferred_addr;
    ASSIGN_OR_RETURN_UNWRAP(&preferred_addr, args[kIpv4PreferredAddress]);
    CHECK_EQ(preferred_addr->address()->family(), AF_INET);
    options->options_.preferred_address_ipv4 = *preferred_addr->address();
  }

  if (!args[kIpv6PreferredAddress]->IsUndefined()) {
    SocketAddressBase* preferred_addr;
    ASSIGN_OR_RETURN_UNWRAP(&preferred_addr, args[kIpv6PreferredAddress]);
    CHECK_EQ(preferred_addr->address()->family(), AF_INET6);
    options->options_.preferred_address_ipv6 = *preferred_addr->address();
  }
}

void OptionsObject::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
}
}  // namespace

void Session::Options::MemoryInfo(MemoryTracker* tracker) const {
  if (preferred_address_ipv4 != std::nullopt)
    tracker->TrackField("preferred_address_ipv4",
                        preferred_address_ipv4.value());
  if (preferred_address_ipv6 != std::nullopt)
    tracker->TrackField("preferred_address_ipv6",
                        preferred_address_ipv6.value());
  tracker->TrackField("tls", crypto_options);
}

// ======================================================================================
// Session::TransportParams

Session::TransportParams::TransportParams(const Config& config,
                                          const Options& options)
    : TransportParams(Type::ENCRYPTED_EXTENSIONS) {
  ngtcp2_transport_params_default(&params_);
  params_.active_connection_id_limit = options.active_connection_id_limit;
  params_.initial_max_stream_data_bidi_local =
      options.initial_max_stream_data_bidi_local;
  params_.initial_max_stream_data_bidi_remote =
      options.initial_max_stream_data_bidi_remote;
  params_.initial_max_stream_data_uni = options.initial_max_stream_data_uni;
  params_.initial_max_streams_bidi = options.initial_max_streams_bidi;
  params_.initial_max_streams_uni = options.initial_max_streams_uni;
  params_.initial_max_data = options.initial_max_data;
  params_.max_idle_timeout = options.max_idle_timeout * NGTCP2_SECONDS;
  params_.max_ack_delay = options.max_ack_delay;
  params_.ack_delay_exponent = options.ack_delay_exponent;
  params_.max_datagram_frame_size = options.max_datagram_frame_size;
  params_.disable_active_migration = options.disable_active_migration ? 1 : 0;
  params_.preferred_address_present = 0;
  params_.stateless_reset_token_present = 0;
  params_.retry_scid_present = 0;

  if (config.side == CryptoContext::Side::SERVER) {
    // For the server side, the original dcid is always set.
    CHECK(config.ocid);
    params_.original_dcid = config.ocid;

    // The retry_scid is only set if the server validated a retry token.
    if (config.retry_scid) {
      params_.retry_scid = config.retry_scid;
      params_.retry_scid_present = 1;
    }
  }

  if (options.preferred_address_ipv4 != std::nullopt)
    SetPreferredAddress(options.preferred_address_ipv4.value());

  if (options.preferred_address_ipv6 != std::nullopt)
    SetPreferredAddress(options.preferred_address_ipv6.value());
}

Session::TransportParams::TransportParams(Type type, const ngtcp2_vec& vec)
    : TransportParams(type) {
  int ret = ngtcp2_decode_transport_params(
      &params_,
      static_cast<ngtcp2_transport_params_type>(type),
      vec.base,
      vec.len);

  if (ret != 0) {
    ptr_ = nullptr;
    error_ = QuicError::ForNgtcp2Error(ret);
  }
}

Store Session::TransportParams::Encode(Environment* env) {
  if (ptr_ == nullptr) {
    error_ = QuicError::ForNgtcp2Error(NGTCP2_INTERNAL_ERROR);
    return Store();
  }

  // Preflight to see how much storage we'll need.
  ssize_t size = ngtcp2_encode_transport_params(
      nullptr, 0, static_cast<ngtcp2_transport_params_type>(type_), &params_);

  CHECK_GT(size, 0);

  auto result = ArrayBuffer::NewBackingStore(env->isolate(), size);

  auto ret = ngtcp2_encode_transport_params(
      static_cast<uint8_t*>(result->Data()),
      size,
      static_cast<ngtcp2_transport_params_type>(type_),
      &params_);

  if (ret != 0) {
    error_ = QuicError::ForNgtcp2Error(ret);
    return Store();
  }

  return Store(std::move(result), size);
}

void Session::TransportParams::SetPreferredAddress(
    const SocketAddress& address) {
  CHECK(ptr_ == &params_);
  params_.preferred_address_present = 1;
  switch (address.family()) {
    case AF_INET: {
      const sockaddr_in* src =
          reinterpret_cast<const sockaddr_in*>(address.data());
      memcpy(params_.preferred_address.ipv4_addr,
             &src->sin_addr,
             sizeof(params_.preferred_address.ipv4_addr));
      params_.preferred_address.ipv4_port = address.port();
      return;
    }
    case AF_INET6: {
      const sockaddr_in6* src =
          reinterpret_cast<const sockaddr_in6*>(address.data());
      memcpy(params_.preferred_address.ipv6_addr,
             &src->sin6_addr,
             sizeof(params_.preferred_address.ipv6_addr));
      params_.preferred_address.ipv6_port = address.port();
      return;
    }
  }
  UNREACHABLE();
}

void Session::TransportParams::GenerateStatelessResetToken(
    const Endpoint& endpoint, const CID& cid) {
  CHECK(ptr_ == &params_);
  CHECK(cid);
  params_.stateless_reset_token_present = 1;

  StatelessResetToken token(params_.stateless_reset_token,
                            endpoint.options().reset_token_secret,
                            cid);
}

void Session::TransportParams::GeneratePreferredAddressToken(Session* session,
                                                             CID* pscid) {
  CHECK_NOT_NULL(session);
  CHECK(ptr_ == &params_);
  CHECK(pscid);
  *pscid = session->cid_factory_.Generate();
  params_.preferred_address.cid = *pscid;
  session->endpoint_->AssociateStatelessResetToken(
      session->endpoint().GenerateNewStatelessResetToken(
        params_.preferred_address.stateless_reset_token, *pscid),
      session);
}

// ======================================================================================
// Session::Application

std::string Session::Application::StreamData::ToString() const {
  return std::string("StreamData [") + std::to_string(id) +
         "]: buffers = " + std::to_string(count) +
         ", remaining = " + std::to_string(remaining) +
         ", fin = " + std::to_string(fin);
}

void Session::Application::AcknowledgeStreamData(Stream* stream,
                                                 uint64_t offset,
                                                 size_t datalen) {
  stream->Acknowledge(offset, datalen);
}

void Session::Application::BlockStream(stream_id id) {
  auto stream = session().FindStream(id);
  if (stream) stream->Blocked();
}

// Called to determine if a Header can be added to this application.
// Applications that do not support headers (which is the default) will always
// return false.
bool Session::Application::CanAddHeader(size_t current_count,
                                        size_t current_headers_length,
                                        size_t this_header_length) {
  return false;
}

SessionTicket::AppData::Status Session::Application::ExtractSessionTicketAppData(
    const SessionTicket::AppData& app_data,
    SessionTicket::AppData::Flag flag) {
  // By default we do not have any application data to retrieve.
  return flag == SessionTicket::AppData::Flag::STATUS_RENEW
             ? SessionTicket::AppData::Status::TICKET_USE_RENEW
             : SessionTicket::AppData::Status::TICKET_USE;
}

BaseObjectPtr<Packet> Session::Application::CreateStreamDataPacket() {
  return Packet::Create(
      env(),
      session_->endpoint_.get(),
      session_->remote_address_,
      ngtcp2_conn_get_max_udp_payload_size(*session_),
      "stream data");
}

void Session::Application::StreamClose(Stream* stream, QuicError error) {
  stream->Destroy(error);
}

void Session::Application::StreamReset(Stream* stream,
                                       uint64_t final_size,
                                       QuicError error) {
  stream->ReceiveResetStream(final_size, error);
}

void Session::Application::StreamStopSending(Stream* stream, QuicError error) {
  stream->ReceiveStopSending(error);
}

void Session::Application::SendPendingData() {
  PathStorage path;

  BaseObjectPtr<Packet> packet;
  uint8_t* pos = nullptr;
  int err = 0;

  size_t maxPacketCount =
      std::min(static_cast<size_t>(64000),
               ngtcp2_conn_get_send_quantum(*session_));
  size_t packetSendCount = 0;

  const auto updateTimer = [&] {
    ngtcp2_conn_update_pkt_tx_time(*session_, uv_hrtime());
    session_->UpdateTimer();
  };

  const auto congestionLimited = [&](auto packet) {
    auto len = pos - ngtcp2_vec(*packet).base;
    // We are either congestion limited or done.
    if (len) {
      // Some data was serialized into the packet. We need to send it.
      packet->Truncate(len);
      session_->Send(std::move(packet), path);
    }

    updateTimer();
  };

  for (;;) {
    ssize_t ndatalen;
    StreamData stream_data;

    err = GetStreamData(&stream_data);

    if (err < 0) {
      session_->last_error_ = QuicError::ForNgtcp2Error(NGTCP2_ERR_INTERNAL);
      return session_->Close(Session::CloseMethod::SILENT);
    }

    if (!packet) {
      packet = CreateStreamDataPacket();
      if (!packet) {
        session_->last_error_ = QuicError::ForNgtcp2Error(NGTCP2_ERR_INTERNAL);
        return session_->Close(Session::CloseMethod::SILENT);
      }
      pos = ngtcp2_vec(*packet).base;
    }

    ssize_t nwrite = WriteVStream(&path, pos, &ndatalen, stream_data);

    if (nwrite <= 0) {
      switch (nwrite) {
        case 0:
          if (stream_data.id >= 0) ResumeStream(stream_data.id);
          return congestionLimited(std::move(packet));
        case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
          session().StreamDataBlocked(stream_data.id);
          if (session().max_data_left() == 0) {
            if (stream_data.id >= 0) ResumeStream(stream_data.id);
            return congestionLimited(std::move(packet));
          }
          CHECK_LE(ndatalen, 0);
          continue;
        }
        case NGTCP2_ERR_STREAM_SHUT_WR: {
          // Indicates that the writable side of the stream has been closed
          // locally or the stream is being reset. In either case, we can't send
          // any stream data!
          CHECK_GE(stream_data.id, 0);
          // We need to notify the stream that the writable side has been closed
          // and no more outbound data can be sent.
          CHECK_LE(ndatalen, 0);
          auto stream = session_->FindStream(stream_data.id);
          if (stream) stream->EndWritable();
          continue;
        }
        case NGTCP2_ERR_WRITE_MORE: {
          CHECK_GT(ndatalen, 0);
          if (!StreamCommit(&stream_data, ndatalen)) return session_->Close();
          pos += ndatalen;
          continue;
        }
      }

      session_->last_error_ = QuicError::ForNgtcp2Error(nwrite);
      return session_->Close(Session::CloseMethod::SILENT);
    }

    pos += nwrite;
    if (ndatalen > 0 && !StreamCommit(&stream_data, ndatalen)) {
      // Since we are closing the session here, we don't worry about updating
      // the pkt tx time. The failed StreamCommit should have updated the
      // last_error_ appropriately.
      return session_->Close(Session::CloseMethod::SILENT);
    }

    if (stream_data.id >= 0 && ndatalen < 0) ResumeStream(stream_data.id);

    packet->Truncate(nwrite);
    session_->Send(std::move(packet), path);

    pos = nullptr;

    if (++packetSendCount == maxPacketCount) {
      break;
    }
  }

  updateTimer();
}

ssize_t Session::Application::WriteVStream(PathStorage* path,
                                           uint8_t* buf,
                                           ssize_t* ndatalen,
                                           const StreamData& stream_data) {
  CHECK_LE(stream_data.count, kMaxVectorCount);
  uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
  if (stream_data.remaining > 0) flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
  if (stream_data.fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
  ssize_t ret = ngtcp2_conn_writev_stream(
      *session_,
      &path->path,
      nullptr,
      buf,
      ngtcp2_conn_get_max_udp_payload_size(*session_),
      ndatalen,
      flags,
      stream_data.id,
      stream_data.buf,
      stream_data.count,
      uv_hrtime());
  return ret;
}

// ======================================================================================
// Session

Session* Session::From(ngtcp2_conn* conn, void* user_data) {
  auto session = static_cast<Session*>(user_data);
  CHECK_EQ(conn, session->connection_.get());
  return session;
}

Local<FunctionTemplate> Session::GetConstructorTemplate(Environment* env) {
  auto& state = BindingData::Get(env);
  auto tmpl = state.session_constructor_template();
  if (tmpl.IsEmpty()) {
    auto isolate = env->isolate();
    tmpl = NewFunctionTemplate(isolate, IllegalConstructor);
    tmpl->SetClassName(state.session_string());
    tmpl->Inherit(AsyncWrap::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        Session::kInternalFieldCount);
    SetProtoMethodNoSideEffect(
        isolate, tmpl, "getRemoteAddress", GetRemoteAddress);
    SetProtoMethodNoSideEffect(isolate, tmpl, "getCertificate", GetCertificate);
    SetProtoMethodNoSideEffect(
        isolate, tmpl, "getPeerCertificate", GetPeerCertificate);
    SetProtoMethodNoSideEffect(
        isolate, tmpl, "getEphemeralKeyInfo", GetEphemeralKeyInfo);
    SetProtoMethod(isolate, tmpl, "destroy", DoDestroy);
    SetProtoMethod(isolate, tmpl, "gracefulClose", GracefulClose);
    SetProtoMethod(isolate, tmpl, "silentClose", SilentClose);
    SetProtoMethod(isolate, tmpl, "updateKey", UpdateKey);
    SetProtoMethod(isolate, tmpl, "openStream", DoOpenStream);
    SetProtoMethod(isolate, tmpl, "sendDatagram", DoSendDatagram);
    state.set_session_constructor_template(tmpl);
  }
  return tmpl;
}

void Session::Initialize(Environment* env, Local<Object> target) {
  USE(GetConstructorTemplate(env));

  OptionsObject::Initialize(env, target);

#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATS_SESSION_##name);
  SESSION_STATS(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATS_SESSION_COUNT);
#undef V
#define V(name, _, __) NODE_DEFINE_CONSTANT(target, IDX_STATE_SESSION_##name);
  SESSION_STATE(V)
  NODE_DEFINE_CONSTANT(target, IDX_STATE_SESSION_COUNT);
#undef V

  constexpr uint32_t STREAM_DIRECTION_BIDIRECTIONAL =
      static_cast<uint32_t>(Direction::BIDIRECTIONAL);
  constexpr uint32_t STREAM_DIRECTION_UNIDIRECTIONAL =
      static_cast<uint32_t>(Direction::UNIDIRECTIONAL);

  NODE_DEFINE_CONSTANT(target, STREAM_DIRECTION_BIDIRECTIONAL);
  NODE_DEFINE_CONSTANT(target, STREAM_DIRECTION_UNIDIRECTIONAL);
}

void Session::RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(DoDestroy);
  registry->Register(GetRemoteAddress);
  registry->Register(GetCertificate);
  registry->Register(GetEphemeralKeyInfo);
  registry->Register(GetPeerCertificate);
  registry->Register(GracefulClose);
  registry->Register(SilentClose);
  registry->Register(UpdateKey);
  registry->Register(DoOpenStream);
  registry->Register(DoSendDatagram);
  OptionsObject::RegisterExternalReferences(registry);
}

BaseObjectPtr<Session> Session::Create(BaseObjectPtr<Endpoint> endpoint,
                                       const Config& config,
                                       const Options& options) {
  auto env = endpoint->env();
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
           ->InstanceTemplate()
           ->NewInstance(env->context())
           .ToLocal(&obj))
    return BaseObjectPtr<Session>();
  return MakeDetachedBaseObject<Session>(
      obj, std::move(endpoint), config, options);
}

std::string Session::diagnostic_name() const {
  const auto get_type = [&] { return is_server() ? "server" : "client"; };

  return std::string("Session (") + get_type() + "," +
         std::to_string(env()->thread_id()) + ":" +
         std::to_string(static_cast<int64_t>(get_async_id())) + ")";
}

Session::Session(Local<Object> object,
                 BaseObjectPtr<Endpoint> endpoint,
                 const Config& config,
                 const Options& options)
    : AsyncWrap(endpoint->env(), object, AsyncWrap::PROVIDER_QUIC_SESSION),
      stats_(endpoint->env()),
      allocator_(BindingData::Get(env())),
      options_(std::move(options)),
      endpoint_(std::move(endpoint)),
      state_(env()->isolate()),
      cid_factory_(config.cid_factory),
      maybe_cid_factory_ref_(config.cid_factory),
      local_address_(config.local_addr),
      remote_address_(config.remote_addr),
      application_(SelectApplication(config, options_)),
      crypto_context_(endpoint->env(), config.side, this, options_.crypto_options),
      timer_(env(),
             [this, self = BaseObjectPtr<Session>(this)] { OnTimeout(); }),
      dcid_(config.dcid),
      scid_(config.scid),
      preferred_address_cid_(CID()) {
  MakeWeak();
  timer_.Unref();

  if (config.ocid) ocid_ = config.ocid;

  ExtendMaxStreams(
      EndpointLabel::LOCAL, Direction::BIDIRECTIONAL, DEFAULT_MAX_STREAMS_BIDI);
  ExtendMaxStreams(
      EndpointLabel::LOCAL, Direction::UNIDIRECTIONAL, DEFAULT_MAX_STREAMS_UNI);

  const auto defineProperty = [&](auto name, auto value) {
    object
        ->DefineOwnProperty(
            env()->context(), name, value, PropertyAttribute::ReadOnly)
        .Check();
  };

  defineProperty(env()->state_string(), state_.GetArrayBuffer());
  defineProperty(env()->stats_string(), stats_.ToBigUint64Array(env()));

  auto& binding_data = BindingData::Get(env());

  if (UNLIKELY(options.qlog)) {
    qlogstream_ = LogStream::Create(env());
    if (LIKELY(qlogstream_)) {
      defineProperty(binding_data.qlog_string(), qlogstream_->object());
    }
  }

  if (UNLIKELY(options.crypto_options.keylog)) {
    keylogstream_ = LogStream::Create(env());
    if (LIKELY(keylogstream_)) {
      defineProperty(binding_data.keylog_string(), keylogstream_->object());
    }
  }

  ngtcp2_conn* conn;
  Path path(local_address_, remote_address_);
  TransportParams transport_params(config, options);
  switch (config.side) {
    case CryptoContext::Side::SERVER: {
      transport_params.GenerateStatelessResetToken(*endpoint_, scid_);
      const ngtcp2_transport_params& params = transport_params;
      if (params.preferred_address_present) {
        transport_params.GeneratePreferredAddressToken(this,
                                                       &preferred_address_cid_);
      }
      CHECK_EQ(ngtcp2_conn_server_new(&conn,
                                      dcid_,
                                      scid_,
                                      &path,
                                      config.version,
                                      &callbacks[static_cast<int>(config.side)],
                                      &config,
                                      transport_params,
                                      &allocator_,
                                      this),
               0);
      break;
    }
    case CryptoContext::Side::CLIENT: {
      DEBUG_ARGS(this, "Initializing as client session [%s]", scid_);
      CHECK_EQ(ngtcp2_conn_client_new(&conn,
                                      dcid_,
                                      scid_,
                                      &path,
                                      config.version,
                                      &callbacks[static_cast<int>(config.side)],
                                      &config,
                                      transport_params,
                                      &allocator_,
                                      this),
               0);
      crypto_context_.MaybeSetEarlySession(config.session_ticket);
      break;
    }
    default:
      UNREACHABLE();
  }

  connection_.reset(conn);

  // We index the Session by our local CID (the scid) and dcid (the peer's cid)
  endpoint_->AddSession(scid_, BaseObjectPtr<Session>(this));
  endpoint_->AssociateCID(dcid_, scid_);

  crypto_context_.Start();

  UpdateDataStats();
}

Session::~Session() {
  if (qlogstream_) {
    env()->SetImmediate(
        [ptr = std::move(qlogstream_)](Environment*) { ptr->End(); });
  }
  if (keylogstream_) {
    env()->SetImmediate(
        [ptr = std::move(keylogstream_)](Environment*) { ptr->End(); });
  }
  CHECK(streams_.empty());
}

void Session::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("options", options_);
  tracker->TrackField("endpoint", endpoint_);
  tracker->TrackField("streams", streams_);
  tracker->TrackField("local_address", local_address_);
  tracker->TrackField("remote_address", remote_address_);
  tracker->TrackField("application", application_);
  tracker->TrackField("crypto_context", crypto_context_);
  tracker->TrackField("timer", timer_);
  tracker->TrackField("conn_closebuf", conn_closebuf_);
  tracker->TrackField("qlogstream", qlogstream_);
  tracker->TrackField("keylogstream", keylogstream_);
}

BaseObjectPtr<Stream> Session::FindStream(stream_id id) const {
  auto it = streams_.find(id);
  return it == std::end(streams_) ? BaseObjectPtr<Stream>() : it->second;
}

bool Session::HandshakeCompleted() {
  if (state_->handshake_completed) return false;
  state_->handshake_completed = true;
  stats_.RecordTimestamp<&Stats::handshake_completed_at>();

  if (!crypto_context_.was_early_data_accepted()) {
    ngtcp2_conn_early_data_rejected(*this);
  }

  // When in a server session, handshake completed == handshake confirmed.
  if (is_server()) {
    HandshakeConfirmed();

    uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
    size_t tokenlen = 0;

    if (!endpoint_->GenerateNewToken(version(), token, remote_address_)
             .To(&tokenlen)) {
      // Failed to generate a new token on handshake complete.
      // This isn't the end of the world, just keep going.
      return true;
    }

    if (NGTCP2_ERR(
            ngtcp2_conn_submit_new_token(connection_.get(), token, tokenlen))) {
      // Submitting the new token failed...
      return false;
    }
  }

  EmitHandshakeComplete();

  return true;
}

void Session::HandshakeConfirmed() {
  if (state_->handshake_confirmed) return;
  state_->handshake_confirmed = true;
  stats_.RecordTimestamp<&Stats::handshake_confirmed_at>();
}

void Session::Close(CloseMethod method) {
  if (is_destroyed()) return;
  switch (method) {
    case CloseMethod::DEFAULT:
      return DoClose();
    case CloseMethod::SILENT:
      return DoClose(true);
    case CloseMethod::GRACEFUL:
      if (is_graceful_closing()) return;
      // If there are no open streams, then we can close just immediately and not
      // worry about waiting around for the right moment.
      if (streams_.empty()) return DoClose();
      state_->graceful_closing = 1;
      stats_.RecordTimestamp<&Stats::graceful_closing_at>();
      return;
  }
  UNREACHABLE();
}

void Session::DoClose(bool silent) {
  CHECK(!is_destroyed());
  // Once Close has been called, we cannot re-enter
  if (state_->closing) return;
  state_->closing = 1;

  // Iterate through all of the known streams and close them. The streams
  // will remove themselves from the Session as soon as they are closed.
  // Note: we create a copy because the streams will remove themselves
  // while they are cleaning up which will invalidate the iterator.
  auto streams = streams_;
  for (auto& stream : streams) stream.second->Destroy(last_error_);
  streams.clear();

  // If the state has not been passed out to JavaScript yet, we can skip closing
  // entirely and drop directly out to Destroy.
  if (!state_->wrapped) return Destroy();

  // If we're not running within a ngtcp2 callback scope, schedule a
  // CONNECTION_CLOSE to be sent when Close exits. If we are within a ngtcp2
  // callback scope, sending the CONNECTION_CLOSE will be deferred.
  {
    MaybeCloseConnectionScope close_scope(this, silent);
    stats_.RecordTimestamp<&Stats::closing_at>();

    state_->closing = true;
    state_->silent_close = silent ? 1 : 0;
  }

  // We emit a close callback so that the JavaScript side can clean up anything
  // it needs to clean up before destroying. It's the JavaScript side's
  // responsibility to call destroy() when ready.
  EmitClose();
}

void Session::Destroy() {
  if (is_destroyed()) return;

  // The DoClose() method should have already been called.
  CHECK(state_->closing);

  // We create a copy of the streams because they will remove themselves
  // from streams_ as they are cleaning up, causing the iterator to be
  // invalidated.
  auto streams = streams_;
  for (auto& stream : streams) stream.second->Destroy(last_error_);

  CHECK(streams_.empty());

  stats_.RecordTimestamp<&Stats::destroyed_at>();
  state_->closing = 0;
  state_->graceful_closing = 0;

  timer_.Stop();

  // The Session instances are kept alive using a in the Endpoint. Removing the
  // Session from the Endpoint will free that pointer, allowing the Session to
  // be deconstructed once the stack unwinds and any remaining
  // BaseObjectPtr<Session> instances fall out of scope.

  std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(*this));
  std::vector<ngtcp2_cid_token> tokens(
      ngtcp2_conn_get_num_active_dcid(*this));
  ngtcp2_conn_get_scid(*this, cids.data());
  ngtcp2_conn_get_active_dcid(*this, tokens.data());

  endpoint_->DisassociateCID(dcid_);
  endpoint_->DisassociateCID(preferred_address_cid_);

  for (auto cid : cids) endpoint_->DisassociateCID(CID(&cid));

  for (auto token : tokens) {
    if (token.token_present)
      endpoint_->DisassociateStatelessResetToken(
          StatelessResetToken(token.token));
  }

  state_->destroyed = 1;

  BaseObjectPtr<Endpoint> endpoint = std::move(endpoint_);

  endpoint->RemoveSession(scid_, remote_address_);
}

Session::TransportParams Session::GetLocalTransportParams() const {
  CHECK(!is_destroyed());
  return TransportParams(TransportParams::Type::ENCRYPTED_EXTENSIONS,
                         ngtcp2_conn_get_local_transport_params(*this));
}

Session::TransportParams Session::GetRemoteTransportParams() const {
  CHECK(!is_destroyed());
  return TransportParams(TransportParams::Type::ENCRYPTED_EXTENSIONS,
                         ngtcp2_conn_get_remote_transport_params(*this));
}

bool Session::is_unable_to_send_packets() const {
  return NgCallbackScope::InNgCallbackScope(*this) || is_destroyed() ||
         is_in_draining_period() || (is_server() && is_in_closing_period()) ||
         !endpoint_;
}

void Session::UpdateTimer() {
  // Both uv_hrtime and ngtcp2_conn_get_expiry return nanosecond units.
  uint64_t expiry = ngtcp2_conn_get_expiry(*this);
  uint64_t now = uv_hrtime();

  if (expiry <= now) {
    // The timer has already expired.
    return OnTimeout();
  }

  auto timeout = (expiry - now) / NGTCP2_MILLISECONDS;

  // If timeout is zero here, it means our timer is less than a millisecond
  // off from expiry. Let's bump the timer to 1.
  timer_.Update(timeout == 0 ? 1 : timeout);
}

void Session::OnTimeout() {
  HandleScope scope(env()->isolate());

  if (is_destroyed()) return;

  int ret = ngtcp2_conn_handle_expiry(*this, uv_hrtime());
  if (NGTCP2_OK(ret) && !is_in_closing_period() && !is_in_draining_period()) {
    SendPendingDataScope send_scope(this);
    return;
  }

  last_error_ = QuicError::ForNgtcp2Error(ret);
  Close(CloseMethod::SILENT);
}

void Session::SendConnectionClose() {
  CHECK(!NgCallbackScope::InNgCallbackScope(*this));

  if (is_destroyed() || is_in_draining_period() || state_->silent_close) return;

  auto on_exit = OnScopeLeave([this] { UpdateTimer(); });

  switch (crypto_context_.side()) {
    case CryptoContext::Side::SERVER: {
      if (!is_in_closing_period() && !StartClosingPeriod()) {
        Close(CloseMethod::SILENT);
      } else {
        CHECK(conn_closebuf_);
        Send(conn_closebuf_->Clone());
      }
      return;
    }
    case CryptoContext::Side::CLIENT: {
      Path path(local_address_, remote_address_);
      auto packet = Packet::Create(env(),
                                   endpoint_.get(),
                                   remote_address_,
                                   kDefaultMaxPacketLength,
                                   "immediate connection close (client)");
      ngtcp2_vec vec = *packet;
      ssize_t nwrite = ngtcp2_conn_write_connection_close(*this,
                                                          &path,
                                                          nullptr,
                                                          vec.base,
                                                          vec.len,
                                                          last_error_,
                                                          uv_hrtime());

      if (UNLIKELY(nwrite < 0)) {
        last_error_ = QuicError::ForNgtcp2Error(NGTCP2_INTERNAL_ERROR);
        Close(CloseMethod::SILENT);
      } else {
        packet->Truncate(nwrite);
        Send(std::move(packet));
      }
      return;
    }
  }
  UNREACHABLE();
}

void Session::Send(BaseObjectPtr<Packet> packet) {
  CHECK(!is_destroyed());
  CHECK(!is_in_draining_period());

  if (packet->length() > 0) {
    stats_.Increment<&Stats::bytes_sent>(packet->length());
    endpoint_->Send(std::move(packet));
  }
}

void Session::Send(BaseObjectPtr<Packet> packet, const PathStorage& path) {
  UpdatePath(path);
  return Send(std::move(packet));
}

void Session::UpdatePath(const PathStorage& storage) {
  remote_address_.Update(storage.path.remote.addr, storage.path.remote.addrlen);
  local_address_.Update(storage.path.local.addr, storage.path.local.addrlen);
}

bool Session::StartClosingPeriod() {
  if (is_destroyed()) return false;
  if (is_in_closing_period()) return true;

  auto packet = Packet::Create(env(),
                               endpoint_.get(),
                               remote_address_,
                               kDefaultMaxPacketLength,
                               "server connection close");
  ngtcp2_vec vec = *packet;

  ssize_t nwrite = ngtcp2_conn_write_connection_close(*this,
                                                      nullptr,
                                                      nullptr,
                                                      vec.base,
                                                      vec.len,
                                                      last_error_,
                                                      uv_hrtime());
  if (nwrite < 0) {
    last_error_ = QuicError::ForNgtcp2Error(NGTCP2_INTERNAL_ERROR);
    return false;
  }

  packet->Truncate(nwrite);
  conn_closebuf_ = std::move(packet);
  return true;
}

void Session::UpdateDataStats() {
  if (state_->destroyed) return;

  ngtcp2_conn_stat stat;
  ngtcp2_conn_get_conn_stat(*this, &stat);

  stats_.Set<&Stats::bytes_in_flight>(stat.bytes_in_flight);
  stats_.Set<&Stats::congestion_recovery_start_ts>(stat.congestion_recovery_start_ts);
  stats_.Set<&Stats::cwnd>(stat.cwnd);
  stats_.Set<&Stats::delivery_rate_sec>(stat.delivery_rate_sec);
  stats_.Set<&Stats::first_rtt_sample_ts>(stat.first_rtt_sample_ts);
  stats_.Set<&Stats::initial_rtt>(stat.initial_rtt);
  stats_.Set<&Stats::last_tx_pkt_ts>(reinterpret_cast<uint64_t>(stat.last_tx_pkt_ts));
  stats_.Set<&Stats::latest_rtt>(stat.latest_rtt);
  stats_.Set<&Stats::loss_detection_timer>(stat.loss_detection_timer);
  stats_.Set<&Stats::loss_time>(reinterpret_cast<uint64_t>(stat.loss_time));
  stats_.Set<&Stats::max_udp_payload_size>(stat.max_udp_payload_size);
  stats_.Set<&Stats::min_rtt>(stat.min_rtt);
  stats_.Set<&Stats::pto_count>(stat.pto_count);
  stats_.Set<&Stats::rttvar>(stat.rttvar);
  stats_.Set<&Stats::smoothed_rtt>(stat.smoothed_rtt);
  stats_.Set<&Stats::ssthresh>(stat.ssthresh);

  if (stat.bytes_in_flight > stats_.Get<&Stats::max_bytes_in_flight>())
    stats_.Set<&Stats::max_bytes_in_flight>(stat.bytes_in_flight);
}

void Session::AcknowledgeStreamDataOffset(Stream* stream,
                                          uint64_t offset,
                                          uint64_t datalen) {
  if (is_destroyed()) return;
  application_->AcknowledgeStreamData(stream, offset, datalen);
}

void Session::ActivateConnectionId(uint64_t seq,
                                   const CID& cid,
                                   std::optional<StatelessResetToken> reset_token) {
  endpoint_->AssociateCID(scid_, cid);
  if (reset_token != std::nullopt) {
    endpoint_->AssociateStatelessResetToken(reset_token.value(), this);
  }
}

void Session::DeactivateConnectionId(uint64_t seq,
                                     const CID& cid,
                                     std::optional<StatelessResetToken> reset_token) {
  endpoint_->DisassociateCID(cid);
  if (reset_token != std::nullopt) {
    endpoint_->DisassociateStatelessResetToken(reset_token.value());
  }
}

datagram_id Session::SendDatagram(Store&& data) {
  auto tp = ngtcp2_conn_get_remote_transport_params(*this);
  uint64_t max_datagram_size = tp->max_datagram_frame_size;
  if (max_datagram_size == 0 || data.length() > max_datagram_size) {
    // Datagram is too large.
    return 0;
  }

  BaseObjectPtr<Packet> packet;
  uint8_t* pos = nullptr;
  int accepted = 0;
  ngtcp2_vec vec = data;
  PathStorage path;
  int flags = NGTCP2_WRITE_DATAGRAM_FLAG_MORE;
  datagram_id did = last_datagram_id_ + 1;

  // Let's give it a max number of attempts to send the datagram
  static const int kMaxAttempts = 16;
  int attempts = 0;

  for (;;) {
    if (!packet) {
      packet =
          Packet::Create(env(),
                         endpoint_.get(),
                         remote_address_,
                         ngtcp2_conn_get_max_udp_payload_size(*this),
                         "datagram");
      if (!packet) {
        last_error_ = QuicError::ForNgtcp2Error(NGTCP2_ERR_INTERNAL);
        Close(CloseMethod::SILENT);
        return 0;
      }
      pos = ngtcp2_vec(*packet).base;
    }

    ssize_t nwrite = ngtcp2_conn_writev_datagram(*this,
                                                 &path.path,
                                                 nullptr,
                                                 pos,
                                                 packet->length(),
                                                 &accepted,
                                                 flags,
                                                 did,
                                                 &vec,
                                                 1,
                                                 uv_hrtime());

    if (nwrite < 0) {
      switch (nwrite) {
        case 0: {
          // We cannot send data because of congestion control or the data will
          // not fit. Since datagrams are best effort, we are going to abandon
          // the attempt and just return.
          CHECK_EQ(accepted, 0);
          return 0;
        }
        case NGTCP2_ERR_WRITE_MORE: {
          // We keep on looping! Keep on sending!
          continue;
        }
        case NGTCP2_ERR_INVALID_STATE: {
          // The remote endpoint does not want to accept datagrams. That's ok,
          // just return 0.
          return 0;
        }
        case NGTCP2_ERR_INVALID_ARGUMENT: {
          // The datagram is too large. That should have been caught above but
          // that's ok. We'll just abandon the attempt and return.
          return 0;
        }
      }
      last_error_ = QuicError::ForNgtcp2Error(nwrite);
      Close(CloseMethod::SILENT);
      return 0;
    }

    // In this case, a complete packet was written and we need to send it along.
    packet->Truncate(nwrite);
    Send(std::move(packet));
    ngtcp2_conn_update_pkt_tx_time(*this, uv_hrtime());

    if (accepted != 0) {
      // Yay! The datagram was accepted into the packet we just sent and we can
      // just return the datagram ID.
      last_datagram_id_ = did;
      return did;
    }

    // We sent a packet, but it wasn't the datagram packet. That can happen.
    // Let's loop around and try again.
    if (++attempts == kMaxAttempts) {
      // Too many attempts to send the datagram.
      break;
    }
  }

  return 0;
}

void Session::DatagramAcknowledged(datagram_id id) {
  EmitDatagramAcknowledged(id);
}

void Session::DatagramLost(datagram_id id) {
  EmitDatagramLost(id);
}

void Session::DatagramReceived(const uint8_t* data,
                               size_t datalen,
                               DatagramReceivedFlag flag) {
  // If there is nothing watching for the datagram on the JavaScript side,
  // we just drop it on the floor.
  if (state_->datagram == 0 || datalen == 0) return;

  auto backing = ArrayBuffer::NewBackingStore(env()->isolate(), datalen);
  memcpy(backing->Data(), data, datalen);
  EmitDatagram(Store(std::move(backing), datalen), flag);
}

void Session::ExtendMaxStreamData(Stream* stream, uint64_t max) {
  application_->ExtendMaxStreamData(stream, max);
}

void Session::ExtendMaxStreams(EndpointLabel label,
                               Direction direction,
                               uint64_t max) {
  application_->ExtendMaxStreams(label, direction, max);
}

bool Session::GenerateNewConnectionId(ngtcp2_cid* cid,
                                      size_t len,
                                      uint8_t* token) {
  CID cid_ = cid_factory_.Generate(len);
  StatelessResetToken new_token(
      token, endpoint_->options().reset_token_secret, cid_);
  endpoint_->AssociateCID(cid_, scid_);
  endpoint_->AssociateStatelessResetToken(new_token, this);
  return true;
}

bool Session::Receive(Store&& store,
                      const SocketAddress& local_address,
                      const SocketAddress& remote_address) {
  CHECK(!is_destroyed());

  const auto receivePacket = [&](ngtcp2_path* path, ngtcp2_vec vec) {
    CHECK(!is_destroyed());

    uint64_t now = uv_hrtime();
    ngtcp2_pkt_info pi{};  // Not used but required.
    DEBUG_ARGS(this, "Reading %" PRIu64 " byte packet", vec.len);
    int err =
        ngtcp2_conn_read_pkt(*this, path, &pi, vec.base, vec.len, now);
    switch (err) {
      case 0: {
        // Return true so we send after receiving.
        return true;
      }
      case NGTCP2_ERR_DRAINING: {
        // Connection has entered the draining state, no further data should be
        // sent. This happens when the remote peer has sent a CONNECTION_CLOSE.
        return false;
      }
      case NGTCP2_ERR_CRYPTO: {
        // Crypto error happened! Set the last error to the tls alert
        last_error_ =
            QuicError::ForTlsAlert(ngtcp2_conn_get_tls_alert(*this));
        Close();
        return false;
      }
      case NGTCP2_ERR_RETRY: {
        // This should only ever happen on the server. We have to sent a path
        // validation challenge in the form of a RETRY packet to the peer and
        // drop the connection.
        CHECK(is_server());
        endpoint_->SendRetry(Endpoint::PathDescriptor {
          version(),
          dcid_,
          scid_,
          local_address_,
          remote_address_,
        });
        Close(CloseMethod::SILENT);
        return false;
      }
      case NGTCP2_ERR_DROP_CONN: {
        DEBUG(this, "Needs drop connection");
        // There's nothing else to do but drop the connection state.
        Close(CloseMethod::SILENT);
        return false;
      }
    }
    // Shouldn't happen but just in case.
    last_error_ = QuicError::ForNgtcp2Error(err);
    Close();
    return false;
  };

  auto update_stats = OnScopeLeave([&] { UpdateDataStats(); });
  remote_address_ = remote_address;
  Path path(local_address, remote_address_);
  stats_.Increment<&Stats::bytes_received>(store.length());
  if (receivePacket(&path, store)) SendPendingData();

  if (!is_destroyed()) UpdateTimer();

  return true;
}

int Session::ReceiveCryptoData(ngtcp2_crypto_level level,
                               uint64_t offset,
                               const uint8_t* data,
                               size_t datalen) {
  return crypto_context_.Receive(level, offset, data, datalen);
}

bool Session::ReceiveRxKey(ngtcp2_crypto_level level) {
  return !is_server() && level == NGTCP2_CRYPTO_LEVEL_APPLICATION
             ? application_->Start()
             : true;
}

bool Session::ReceiveTxKey(ngtcp2_crypto_level level) {
  return is_server() && level == NGTCP2_CRYPTO_LEVEL_APPLICATION
             ? application_->Start()
             : true;
}

void Session::ReceiveNewToken(const ngtcp2_vec* token) {
  // Currently, we don't do anything with this. We may want to use it in the
  // future.
}

void Session::ReceiveStatelessReset(const ngtcp2_pkt_stateless_reset* sr) {
  state_->stateless_reset = 1;
  // TODO(now): Should we emit an event?
}

void Session::ReceiveStreamData(Stream* stream,
                                Application::ReceiveStreamDataFlags flags,
                                uint64_t offset,
                                const uint8_t* data,
                                size_t datalen) {
  application_->ReceiveStreamData(stream, flags, data, datalen, offset);
}

void Session::RemoveConnectionId(const CID& cid) {
  endpoint_->DisassociateCID(cid);
}

void Session::SelectPreferredAddress(const PreferredAddress& preferredAddress) {
  if (options_.preferred_address_strategy ==
      PreferredAddress::Policy::IGNORE_PREFERED) {
    return;
  }

  CHECK_NE(endpoint_->local_address(), std::nullopt);

  auto local_address = endpoint_->local_address().value();
  int family = local_address.family();

  switch (family) {
    case AF_INET: {
      auto ipv4 = preferredAddress.ipv4();
      if (ipv4 != std::nullopt) {
        if (ipv4->address.empty() || ipv4->port == 0) return;
        SocketAddress::New(
            AF_INET, ipv4->address.c_str(), ipv4->port, &remote_address_);
        state_->using_preferred_address = 1;
        preferredAddress.Use(ipv4.value());
      }
      break;
    }
    case AF_INET6: {
      auto ipv6 = preferredAddress.ipv6();
      if (ipv6 != std::nullopt) {
        if (ipv6->address.empty() || ipv6->port == 0) return;
        SocketAddress::New(
            AF_INET, ipv6->address.c_str(), ipv6->port, &remote_address_);
        state_->using_preferred_address = 1;
        preferredAddress.Use(ipv6.value());
      }
      break;
    }
  }
}

void Session::StreamClose(Stream* stream, QuicError error) {
  application_->StreamClose(stream, error);
}

void Session::StreamOpen(stream_id id) {
  // Currently, we don't do anything with stream open. That may change later.
}

void Session::StreamReset(Stream* stream,
                          uint64_t final_size,
                          QuicError error) {
  application_->StreamReset(stream, final_size, error);
}

void Session::StreamStopSending(Stream* stream, QuicError error) {
  application_->StreamStopSending(stream, error);
}

void Session::ReportPathValidationStatus(PathValidationResult result,
                                         PathValidationFlags flags,
                                         const SocketAddress& local_address,
                                         const SocketAddress& remote_address) {
  EmitPathValidation(result, flags, local_address, remote_address);
}

void Session::CollectSessionTicketAppData(SessionTicket::AppData* app_data) const {
  application_->CollectSessionTicketAppData(app_data);
}

SessionTicket::AppData::Status Session::ExtractSessionTicketAppData(
    const SessionTicket::AppData& app_data,
    SessionTicket::AppData::Flag flag) {
  return application_->ExtractSessionTicketAppData(app_data, flag);
}

BaseObjectPtr<Stream> Session::CreateStream(stream_id id) {
  if (!can_create_streams()) return BaseObjectPtr<Stream>();
  auto stream = Stream::Create(env(), this, id);
  if (stream) AddStream(stream);
  return stream;
}

BaseObjectPtr<Stream> Session::OpenStream(Direction direction) {
  if (!can_create_streams()) return BaseObjectPtr<Stream>();
  stream_id id;
  switch (direction) {
    case Direction::BIDIRECTIONAL:
      if (ngtcp2_conn_open_bidi_stream(*this, &id, nullptr) == 0) {
        return CreateStream(id);
      }
      return BaseObjectPtr<Stream>();
    case Direction::UNIDIRECTIONAL:
      if (ngtcp2_conn_open_uni_stream(*this, &id, nullptr) == 0) {
        return CreateStream(id);
      }
      return BaseObjectPtr<Stream>();
  }
  UNREACHABLE();
}

void Session::AddStream(const BaseObjectPtr<Stream>& stream) {
  ngtcp2_conn_set_stream_user_data(*this, stream->id(), stream.get());
  streams_[stream->id()] = stream;

  // Update tracking statistics for the number of streams associated with this
  // session.
  switch (stream->origin()) {
    case CryptoContext::Side::CLIENT:
      if (is_server())
        stats_.Increment<&Stats::streams_in_count>();
      else
        stats_.Increment<&Stats::streams_out_count>();
      break;
    case CryptoContext::Side::SERVER:
      if (is_server())
        stats_.Increment<&Stats::streams_out_count>();
      else
        stats_.Increment<&Stats::streams_in_count>();
  }
  stats_.Increment<&Stats::streams_out_count>();
  switch (stream->direction()) {
    case Direction::BIDIRECTIONAL:
      stats_.Increment<&Stats::bidi_stream_count>();
      break;
    case Direction::UNIDIRECTIONAL:
      stats_.Increment<&Stats::uni_stream_count>();
      break;
  }
}

void Session::RemoveStream(stream_id id) {
  // ngtcp2 does not extend the max streams count automatically except in very
  // specific conditions, none of which apply once we've gotten this far. We
  // need to manually extend when a remote peer initiated stream is removed.
  if (!is_in_draining_period() && !is_in_closing_period() &&
      !state_->silent_close &&
      !ngtcp2_conn_is_local_stream(connection_.get(), id)) {
    if (ngtcp2_is_bidi_stream(id))
      ngtcp2_conn_extend_max_streams_bidi(connection_.get(), 1);
    else
      ngtcp2_conn_extend_max_streams_uni(connection_.get(), 1);
  }

  // Frees the persistent reference to the Stream object, allowing it to be gc'd
  // any time after the JS side releases it's own reference.
  streams_.erase(id);
  ngtcp2_conn_set_stream_user_data(*this, id, nullptr);
}

void Session::ResumeStream(stream_id id) {
  SendPendingDataScope send_scope(this);
  application_->ResumeStream(id);
}

void Session::ShutdownStream(stream_id id, QuicError code) {
  if (is_in_closing_period() || is_in_draining_period() ||
      state_->silent_close == 1) {
    SendPendingDataScope send_scope(this);
    ngtcp2_conn_shutdown_stream(*this,
                                id,
                                code.type() == QuicError::Type::APPLICATION
                                    ? code.code()
                                    : NGTCP2_APP_NOERROR);
  }
}

void Session::StreamDataBlocked(stream_id id) {
  stats_.Increment<&Stats::block_count>();
  application_->BlockStream(id);
}

void Session::ShutdownStreamWrite(stream_id id, QuicError code) {
  if (is_in_closing_period() || is_in_draining_period() ||
      state_->silent_close == 1) {
    return;  // Nothing to do because we can't send any frames.
  }
  SendPendingDataScope send_scope(this);
  ngtcp2_conn_shutdown_stream_write(
      *this,
      id,
      code.type() == QuicError::Type::APPLICATION ? code.code() : 0);
}

// ======================================================================================
// V8 Callouts

void Session::EmitDatagramAcknowledged(datagram_id id) {
  CHECK(!is_destroyed());
  if (!env()->can_call_into_js()) return;

  CallbackScope cb_scope(this);

  Local<Value> arg = BigInt::NewFromUnsigned(env()->isolate(), id);
  MakeCallback(BindingData::Get(env()).session_datagram_ack_callback(), 1, &arg);
}

void Session::EmitDatagramLost(datagram_id id) {
  CHECK(!is_destroyed());
  if (!env()->can_call_into_js()) return;

  CallbackScope cb_scope(this);

  Local<Value> arg = BigInt::NewFromUnsigned(env()->isolate(), id);
  MakeCallback(BindingData::Get(env()).session_datagram_lost_callback(), 1, &arg);
}

void Session::EmitDatagram(Store&& datagram, DatagramReceivedFlag flag) {
  CHECK(!is_destroyed());
  if (!env()->can_call_into_js()) return;

  CallbackScope cbv_scope(this);

  Local<Value> argv[] = {
      datagram.ToArrayBufferView<Uint8Array>(env()),
      flag.early ?
          v8::True(env()->isolate()) :
          v8::False(env()->isolate()),
  };

  MakeCallback(BindingData::Get(env()).session_datagram_callback(),
               arraysize(argv), argv);
}

void Session::EmitHandshakeComplete() {
  CHECK(!is_destroyed());
  if (!env()->can_call_into_js()) return;

  CallbackScope cb_scope(this);

  auto isolate = env()->isolate();
  Local<Value> argv[] = {Undefined(isolate),     // The negotiated server name
                         Undefined(isolate),     // The selected alpn
                         Undefined(isolate),     // Cipher name
                         Undefined(isolate),     // Cipher version
                         Undefined(isolate),     // Validation error reason
                         Undefined(isolate),     // Validation error code
                         crypto_context_.was_early_data_accepted()
                             ? v8::True(isolate)
                             : v8::False(isolate)};

  static constexpr auto kServerName = 0;
  static constexpr auto kSelectedAlpn = 1;
  static constexpr auto kCipherName = 2;
  static constexpr auto kCipherVersion = 3;
  static constexpr auto kValidationErrorReason = 4;
  static constexpr auto kValidationErrorCode = 5;

  int err = crypto_context_.VerifyPeerIdentity();

  if (!ToV8Value(env()->context(), crypto_context_.servername())
           .ToLocal(&argv[kServerName]) ||
      !ToV8Value(env()->context(), crypto_context_.selected_alpn())
           .ToLocal(&argv[kSelectedAlpn]) ||
      !crypto_context_.cipher_name(env()).ToLocal(&argv[kCipherName]) ||
      !crypto_context_.cipher_version(env()).ToLocal(&argv[kCipherVersion])) {
    return;
  }

  if (err != X509_V_OK && (!crypto::GetValidationErrorReason(env(), err)
                                .ToLocal(&argv[kValidationErrorReason]) ||
                           !crypto::GetValidationErrorCode(env(), err)
                                .ToLocal(&argv[kValidationErrorCode]))) {
    return;
  }

  MakeCallback(BindingData::Get(env()).session_handshake_callback(),
               arraysize(argv), argv);
}

void Session::EmitVersionNegotiation(const ngtcp2_pkt_hd& hd,
                                     const quic_version* sv,
                                     size_t nsv) {
  CHECK(!is_destroyed());
  CHECK(!is_server());
  if (!env()->can_call_into_js()) return;

  auto isolate = env()->isolate();
  const auto to_integer = [&](quic_version version) {
    return Integer::New(isolate, version);
  };

  CallbackScope cb_scope(this);

  MaybeStackBuffer<Local<Value>, 5> versions;
  versions.AllocateSufficientStorage(nsv);
  for (size_t n = 0; n < nsv; n++)
    versions[n] = to_integer(sv[n]);

  Local<Value> supported[] = {
    to_integer(NGTCP2_PROTO_VER_MIN),
    to_integer(NGTCP2_PROTO_VER_MAX)
  };

  Local<Value> argv[] = {// The version configured for this session.
                         to_integer(version()),
                         // The versions requested.
                         Array::New(isolate, versions.out(), nsv),
                         // The versions we actually support.
                         Array::New(isolate, supported, arraysize(supported))};

  MakeCallback(BindingData::Get(env()).session_version_negotiation_callback(),
               arraysize(argv), argv);
}

void Session::EmitSessionTicket(Store&& ticket) {
  CHECK(!is_destroyed());
  if (!env()->can_call_into_js()) return;

  // If there is nothing listening for the session ticket, don't both emitting.
  if (LIKELY(state_->session_ticket == 0)) return;

  CallbackScope cb_scope(this);

  auto remote_transport_params = GetRemoteTransportParams();
  Store transport_params;
  if (remote_transport_params)
    transport_params = remote_transport_params.Encode(env());

  auto sessionTicket = SessionTicket::Create(
      env(), std::move(ticket), std::move(transport_params));
  Local<Value> argv = sessionTicket->object();

  MakeCallback(BindingData::Get(env()).session_ticket_callback(), 1, &argv);
}

void Session::EmitError(const QuicError& error) {
  CHECK(!is_destroyed());

  if (!env()->can_call_into_js()) return Destroy();

  CallbackScope cb_scope(this);
  Local<Value> argv[] = {
      Integer::New(env()->isolate(), static_cast<int>(error.type())),
      BigInt::NewFromUnsigned(env()->isolate(), error.code()),
      Undefined(env()->isolate()),
  };
  if (error->reasonlen > 0 &&
      !ToV8Value(env()->context(), error.reason()).ToLocal(&argv[2])) {
    return;
  }
  MakeCallback(BindingData::Get(env()).session_error_callback(),
               arraysize(argv), argv);
}

void Session::EmitClose() {
  CHECK(!is_destroyed());

  if (!env()->can_call_into_js()) return Destroy();

  CallbackScope cb_scope(this);

  // if last_error_ is a transport or application no_error, only emit close.
  if (!last_error_) {
    MakeCallback(BindingData::Get(env()).session_close_callback(), 0, nullptr);
    return;
  }

  // Otherwise, we will emit the codes and let the JavaScript side construct a
  // proper error from them.

  EmitError(last_error_);
}

void Session::EmitPathValidation(PathValidationResult result,
                                 PathValidationFlags flags,
                                 const SocketAddress& local_address,
                                 const SocketAddress& remote_address) {
  CHECK(!is_destroyed());

  if (!env()->can_call_into_js()) return;

  if (LIKELY(state_->path_validation == 0)) return;

  auto isolate = env()->isolate();

  CallbackScope cb_scope(this);

  auto& state = BindingData::Get(env());

  const auto resultToString = [&] {
    switch (result) {
      case PathValidationResult::ABORTED: return state.aborted_string();
      case PathValidationResult::FAILURE: return state.failure_string();
      case PathValidationResult::SUCCESS: return state.success_string();
    }
    UNREACHABLE();
  };

  Local<Value> argv[4] = {
      resultToString(),
      SocketAddressBase::Create(env(),
                                std::make_shared<SocketAddress>(local_address))
          ->object(),
      SocketAddressBase::Create(env(),
                                std::make_shared<SocketAddress>(remote_address))
          ->object(),
      flags.preferredAddress ? v8::True(isolate) : v8::False(isolate),
  };

  MakeCallback(state.session_path_validation_callback(),
               arraysize(argv),
               argv);
}

void Session::EmitKeylog(const char* line) {
  if (!env()->can_call_into_js()) return;
  if (keylogstream_) {
    std::string data = line;
    data += "\n";
    env()->SetImmediate([ptr = keylogstream_, data = std::move(data)](
                            Environment* env) {
      ptr->Emit(data);
    });
  }
}

void Session::EmitNewStream(const BaseObjectPtr<Stream>& stream) {
  if (is_destroyed()) return;
  if (!env()->can_call_into_js()) return;
  CallbackScope cb_scope(this);
  Local<Value> arg = stream->object();

  MakeCallback(BindingData::Get(env()).stream_created_callback(), 1, &arg);
}

// ======================================================================================
// V8 Callbacks

void Session::DoDestroy(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Destroy();
}

void Session::GetRemoteAddress(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  auto address = session->remote_address();
  args.GetReturnValue().Set(
      SocketAddressBase::Create(env, std::make_shared<SocketAddress>(address))
          ->object());
}

void Session::GetCertificate(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<Value> ret;
  if (session->crypto_context().cert(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Session::GetEphemeralKeyInfo(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<Object> ret;
  if (!session->is_server() &&
      session->crypto_context().ephemeral_key(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Session::GetPeerCertificate(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Local<Value> ret;
  if (session->crypto_context().peer_cert(env).ToLocal(&ret))
    args.GetReturnValue().Set(ret);
}

void Session::GracefulClose(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Close(Session::CloseMethod::GRACEFUL);
}

void Session::SilentClose(const FunctionCallbackInfo<Value>& args) {
  // This is exposed for testing purposes only!
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Close(Session::CloseMethod::SILENT);
}

void Session::UpdateKey(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  // Initiating a key update may fail if it is done too early (either
  // before the TLS handshake has been confirmed or while a previous
  // key update is being processed). When it fails, InitiateKeyUpdate()
  // will return false.
  args.GetReturnValue().Set(session->crypto_context().InitiateKeyUpdate());
}

void Session::DoOpenStream(const FunctionCallbackInfo<Value>& args) {
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(args[0]->IsUint32());
  auto direction = static_cast<Direction>(args[0].As<Uint32>()->Value());
  BaseObjectPtr<Stream> stream = session->OpenStream(direction);

  if (stream) args.GetReturnValue().Set(stream->object());
}

void Session::DoSendDatagram(const FunctionCallbackInfo<Value>& args) {
  auto env = Environment::GetCurrent(args);
  Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(args[0]->IsArrayBufferView());
  args.GetReturnValue().Set(
      BigInt::New(env->isolate(),
                  session->SendDatagram(Store(args[0].As<ArrayBufferView>()))));
}

// ======================================================================================
// ngtcp2 static callbacks

const ngtcp2_callbacks Session::callbacks[2] = {
    // NGTCP2_CRYPTO_SIDE_CLIENT
    {ngtcp2_crypto_client_initial_cb,
     nullptr,
     on_receive_crypto_data,
     on_handshake_completed,
     on_receive_version_negotiation,
     ngtcp2_crypto_encrypt_cb,
     ngtcp2_crypto_decrypt_cb,
     ngtcp2_crypto_hp_mask_cb,
     on_receive_stream_data,
     on_acknowledge_stream_data_offset,
     on_stream_open,
     on_stream_close,
     on_receive_stateless_reset,
     ngtcp2_crypto_recv_retry_cb,
     on_extend_max_streams_bidi,
     on_extend_max_streams_uni,
     on_rand,
     on_get_new_cid,
     on_remove_connection_id,
     ngtcp2_crypto_update_key_cb,
     on_path_validation,
     on_select_preferred_address,
     on_stream_reset,
     on_extend_max_remote_streams_bidi,
     on_extend_max_remote_streams_uni,
     on_extend_max_stream_data,
     on_cid_status,
     on_handshake_confirmed,
     on_receive_new_token,
     ngtcp2_crypto_delete_crypto_aead_ctx_cb,
     ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
     on_receive_datagram,
     on_acknowledge_datagram,
     on_lost_datagram,
     on_get_path_challenge_data,
     on_stream_stop_sending,
     ngtcp2_crypto_version_negotiation_cb,
     on_receive_rx_key,
     on_receive_tx_key},
    // NGTCP2_CRYPTO_SIDE_SERVER
    {nullptr,
     ngtcp2_crypto_recv_client_initial_cb,
     on_receive_crypto_data,
     on_handshake_completed,
     nullptr,
     ngtcp2_crypto_encrypt_cb,
     ngtcp2_crypto_decrypt_cb,
     ngtcp2_crypto_hp_mask_cb,
     on_receive_stream_data,
     on_acknowledge_stream_data_offset,
     on_stream_open,
     on_stream_close,
     on_receive_stateless_reset,
     nullptr,
     on_extend_max_streams_bidi,
     on_extend_max_streams_uni,
     on_rand,
     on_get_new_cid,
     on_remove_connection_id,
     ngtcp2_crypto_update_key_cb,
     on_path_validation,
     nullptr,
     on_stream_reset,
     on_extend_max_remote_streams_bidi,
     on_extend_max_remote_streams_uni,
     on_extend_max_stream_data,
     on_cid_status,
     nullptr,
     nullptr,
     ngtcp2_crypto_delete_crypto_aead_ctx_cb,
     ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
     on_receive_datagram,
     on_acknowledge_datagram,
     on_lost_datagram,
     on_get_path_challenge_data,
     on_stream_stop_sending,
     ngtcp2_crypto_version_negotiation_cb,
     on_receive_rx_key,
     on_receive_tx_key}};

#define NGTCP2_CALLBACK_SCOPE(name)                                            \
  auto name = Session::From(conn, user_data);                                  \
  if (UNLIKELY(name->is_destroyed())) return NGTCP2_ERR_CALLBACK_FAILURE;      \
  NgCallbackScope callback_scope(name);

int Session::on_acknowledge_stream_data_offset(ngtcp2_conn* conn,
                                           int64_t stream_id,
                                           uint64_t offset,
                                           uint64_t datalen,
                                           void* user_data,
                                           void* stream_user_data) {
  NGTCP2_CALLBACK_SCOPE(session)
  session->AcknowledgeStreamDataOffset(
      Stream::From(conn, stream_user_data), offset, datalen);
  return NGTCP2_SUCCESS;
}

int Session::on_acknowledge_datagram(ngtcp2_conn* conn,
                                   uint64_t dgram_id,
                                   void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session)
  session->DatagramAcknowledged(dgram_id);
  return NGTCP2_SUCCESS;
}

int Session::on_cid_status(ngtcp2_conn* conn,
                                  int type,
                                  uint64_t seq,
                                  const ngtcp2_cid* cid,
                                  const uint8_t* token,
                                  void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  switch (type) {
    case NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE:
      if (token != nullptr) {
        session->ActivateConnectionId(seq, CID(cid),
                                      StatelessResetToken(token));
      } else {
        session->ActivateConnectionId(seq, CID(cid), std::nullopt);
      }
      return NGTCP2_SUCCESS;
    case NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE:
      if (token != nullptr) {
        session->DeactivateConnectionId(seq, CID(cid),
                                        StatelessResetToken(token));
      } else {
        session->DeactivateConnectionId(seq, CID(cid), std::nullopt);
      }
      return NGTCP2_SUCCESS;
  }
  return NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::on_extend_max_remote_streams_bidi(ngtcp2_conn* conn,
                                          uint64_t max_streams,
                                          void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ExtendMaxStreams(
      EndpointLabel::REMOTE, Direction::BIDIRECTIONAL, max_streams);
  return NGTCP2_SUCCESS;
}

int Session::on_extend_max_remote_streams_uni(ngtcp2_conn* conn,
                                         uint64_t max_streams,
                                         void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ExtendMaxStreams(
      EndpointLabel::REMOTE, Direction::UNIDIRECTIONAL, max_streams);
  return NGTCP2_SUCCESS;
}

int Session::on_extend_max_streams_bidi(ngtcp2_conn* conn,
                                    uint64_t max_streams,
                                    void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ExtendMaxStreams(
      EndpointLabel::LOCAL, Direction::BIDIRECTIONAL, max_streams);
  return NGTCP2_SUCCESS;
}

int Session::on_extend_max_stream_data(ngtcp2_conn* conn,
                                   int64_t stream_id,
                                   uint64_t max_data,
                                   void* user_data,
                                   void* stream_user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ExtendMaxStreamData(Stream::From(conn, stream_user_data), max_data);
  return NGTCP2_SUCCESS;
}

int Session::on_extend_max_streams_uni(ngtcp2_conn* conn,
                                       uint64_t max_streams,
                                       void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ExtendMaxStreams(EndpointLabel::LOCAL,
                            Direction::BIDIRECTIONAL,
                            max_streams);
  return NGTCP2_SUCCESS;
}

int Session::on_get_new_cid(ngtcp2_conn* conn,
                                  ngtcp2_cid* cid,
                                  uint8_t* token,
                                  size_t cidlen,
                                  void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  return session->GenerateNewConnectionId(cid, cidlen, token)
             ? NGTCP2_SUCCESS
             : NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::on_get_path_challenge_data(ngtcp2_conn* conn,
                                    uint8_t* data,
                                    void* user_data) {
  // For now, simple random data will suffice. Later we might need to make this
  // more cryptographically secure / pseudorandom for more protection.
  CHECK(crypto::CSPRNG(data, NGTCP2_PATH_CHALLENGE_DATALEN).is_ok());
  return NGTCP2_SUCCESS;
}

int Session::on_handshake_completed(ngtcp2_conn* conn, void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  return session->HandshakeCompleted() ? NGTCP2_SUCCESS
                                       : NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::on_handshake_confirmed(ngtcp2_conn* conn, void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->HandshakeConfirmed();
  return NGTCP2_SUCCESS;
}

int Session::on_lost_datagram(ngtcp2_conn* conn,
                            uint64_t dgram_id,
                            void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->DatagramLost(dgram_id);
  return NGTCP2_SUCCESS;
}

int Session::on_path_validation(ngtcp2_conn* conn,
                              uint32_t flags,
                              const ngtcp2_path* path,
                              ngtcp2_path_validation_result res,
                              void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);

  session->ReportPathValidationStatus(
      static_cast<PathValidationResult>(res),
      PathValidationFlags{
        QUIC_FLAG(flags, NGTCP2_PATH_VALIDATION_FLAG_PREFERRED_ADDR)
      },
      SocketAddress(path->local.addr),
      SocketAddress(path->remote.addr));
  return NGTCP2_SUCCESS;
}

int Session::on_receive_crypto_data(ngtcp2_conn* conn,
                                 ngtcp2_crypto_level crypto_level,
                                 uint64_t offset,
                                 const uint8_t* data,
                                 size_t datalen,
                                 void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  return session->ReceiveCryptoData(crypto_level, offset, data, datalen);
}

int Session::on_receive_datagram(ngtcp2_conn* conn,
                               uint32_t flags,
                               const uint8_t* data,
                               size_t datalen,
                               void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->DatagramReceived(data, datalen, DatagramReceivedFlag{
    QUIC_FLAG(flags, NGTCP2_DATAGRAM_FLAG_EARLY)
  });
  return NGTCP2_SUCCESS;
}

int Session::on_receive_new_token(ngtcp2_conn* conn,
                               const ngtcp2_vec* token,
                               void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ReceiveNewToken(token);
  return NGTCP2_SUCCESS;
}

int Session::on_receive_rx_key(ngtcp2_conn* conn,
                            ngtcp2_crypto_level level,
                            void* user_data) {
  return Session::From(conn, user_data)->ReceiveRxKey(level)
             ? NGTCP2_SUCCESS
             : NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::on_receive_tx_key(ngtcp2_conn* conn,
                            ngtcp2_crypto_level level,
                            void* user_data) {
  return Session::From(conn, user_data)->ReceiveTxKey(level)
             ? NGTCP2_SUCCESS
             : NGTCP2_ERR_CALLBACK_FAILURE;
}

int Session::on_receive_stateless_reset(ngtcp2_conn* conn,
                                     const ngtcp2_pkt_stateless_reset* sr,
                                     void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->ReceiveStatelessReset(sr);
  return NGTCP2_SUCCESS;
}

int Session::on_receive_stream_data(ngtcp2_conn* conn,
                                 uint32_t flags,
                                 int64_t stream_id,
                                 uint64_t offset,
                                 const uint8_t* data,
                                 size_t datalen,
                                 void* user_data,
                                 void* stream_user_data) {
  NGTCP2_CALLBACK_SCOPE(session);

  Application::ReceiveStreamDataFlags receive_flags {
    QUIC_FLAG(flags, NGTCP2_STREAM_DATA_FLAG_FIN),
    QUIC_FLAG(flags, NGTCP2_STREAM_DATA_FLAG_EARLY)
  };

  if (stream_user_data == nullptr) {
    // What we likely have here is an implicitly created stream. Let's try to
    // create it. If successful, we'll pass our lovely bit of received data on
    // to it for processing. Otherwise, we are going to tell ngtcp2 to shut down
    // the stream.
    auto stream = session->CreateStream(stream_id);
    if (stream) {
      session->EmitNewStream(stream);
      session->ReceiveStreamData(
          stream.get(), receive_flags, offset, data, datalen);
    } else {
      USE(ngtcp2_conn_shutdown_stream(*session, stream_id, NGTCP2_APP_NOERROR));
    }
  } else {
    session->ReceiveStreamData(Stream::From(conn, stream_user_data),
                               receive_flags,
                               offset,
                               data,
                               datalen);
  }
  return NGTCP2_SUCCESS;
}

int Session::on_receive_version_negotiation(ngtcp2_conn* conn,
                                         const ngtcp2_pkt_hd* hd,
                                         const uint32_t* sv,
                                         size_t nsv,
                                         void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->EmitVersionNegotiation(*hd, sv, nsv);
  return NGTCP2_SUCCESS;
}

int Session::on_remove_connection_id(ngtcp2_conn* conn,
                                  const ngtcp2_cid* cid,
                                  void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->RemoveConnectionId(CID(cid));
  return NGTCP2_SUCCESS;
}

int Session::on_select_preferred_address(ngtcp2_conn* conn,
                                      ngtcp2_path* dest,
                                      const ngtcp2_preferred_addr* paddr,
                                      void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->SelectPreferredAddress(PreferredAddress(dest, paddr));
  return NGTCP2_SUCCESS;
}

int Session::on_stream_close(ngtcp2_conn* conn,
                           uint32_t flags,
                           int64_t stream_id,
                           uint64_t app_error_code,
                           void* user_data,
                           void* stream_user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->StreamClose(Stream::From(conn, stream_user_data),
                       QUIC_FLAG(flags, NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)
                           ? QuicError::ForApplication(app_error_code)
                           : QuicError());
  return NGTCP2_SUCCESS;
}

int Session::on_stream_open(ngtcp2_conn* conn,
                          int64_t stream_id,
                          void* user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->StreamOpen(stream_id);
  return NGTCP2_SUCCESS;
}

int Session::on_stream_reset(ngtcp2_conn* conn,
                           int64_t stream_id,
                           uint64_t final_size,
                           uint64_t app_error_code,
                           void* user_data,
                           void* stream_user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->StreamReset(Stream::From(conn, stream_user_data),
                       final_size,
                       QuicError::ForApplication(app_error_code));
  return NGTCP2_SUCCESS;
}

int Session::on_stream_stop_sending(ngtcp2_conn* conn,
                                 int64_t stream_id,
                                 uint64_t app_error_code,
                                 void* user_data,
                                 void* stream_user_data) {
  NGTCP2_CALLBACK_SCOPE(session);
  session->StreamStopSending(Stream::From(conn, stream_user_data),
                             QuicError::ForApplication(app_error_code));
  return NGTCP2_SUCCESS;
}

void Session::on_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
  CHECK(crypto::CSPRNG(dest, destlen).is_ok());
}

// ======================================================================================
// Default Application

namespace {
inline void Consume(ngtcp2_vec** pvec, size_t* pcnt, size_t len) {
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

inline int IsEmpty(const ngtcp2_vec* vec, size_t cnt) {
  size_t i;
  for (i = 0; i < cnt && vec[i].len == 0; ++i) {
  }
  return i == cnt;
}

template <typename T>
size_t get_length(const T* vec, size_t count) {
  CHECK_NOT_NULL(vec);
  size_t len = 0;
  for (size_t n = 0; n < count; n++) len += vec[n].len;
  return len;
}
}  // namespace

class DefaultApplication final : public Session::Application {
 public:
  DefaultApplication(Session* session,
                     const Session::Config& config,
                     const Application::Options& options);

  QUIC_NO_COPY_OR_MOVE(DefaultApplication)

  bool ReceiveStreamData(Stream* stream,
                         ReceiveStreamDataFlags flags,
                         const uint8_t* data,
                         size_t datalen,
                         uint64_t offset) override;

  int GetStreamData(StreamData* stream_data) override;

  void ResumeStream(stream_id id) override;
  bool ShouldSetFin(const StreamData& stream_data) override;
  bool StreamCommit(StreamData* stream_data, size_t datalen) override;

  SET_SELF_SIZE(DefaultApplication)
  SET_MEMORY_INFO_NAME(DefaultApplication)
  SET_NO_MEMORY_INFO()

 private:
  void ScheduleStream(stream_id id);
  void UnscheduleStream(stream_id id);

  Stream::Queue stream_queue_;
};

DefaultApplication::DefaultApplication(Session* session,
                                       const Session::Config& config,
                                       const Application::Options& options)
    : Session::Application(session, options) {}

void DefaultApplication::ScheduleStream(stream_id id) {
  auto stream = session().FindStream(id);
  if (LIKELY(stream && !stream->is_destroyed())) {
    stream->Schedule(&stream_queue_);
  }
}

void DefaultApplication::UnscheduleStream(stream_id id) {
  auto stream = session().FindStream(id);
  if (LIKELY(stream)) stream->Unschedule();
}

void DefaultApplication::ResumeStream(stream_id id) {
  ScheduleStream(id);
}

bool DefaultApplication::ReceiveStreamData(Stream* stream,
                                           ReceiveStreamDataFlags flags,
                                           const uint8_t* data,
                                           size_t datalen,
                                           uint64_t offset) {
  // One potential DOS attack vector is to send a bunch of empty stream frames
  // to commit resources. Check that here. Essentially, we only want to create a
  // new stream if the datalen is greater than 0, otherwise, we ignore the
  // packet. ngtcp2 should be handling this for us, but we handle it just to be
  // safe. We also want to make sure that the stream hasn't been destroyed.
  if (LIKELY(datalen > 0 && !stream->is_destroyed()))
    stream->ReceiveData(flags, data, datalen, offset);
  return true;
}

int DefaultApplication::GetStreamData(StreamData* stream_data) {
  if (stream_queue_.IsEmpty()) return 0;

  Stream* stream = stream_queue_.PopFront();
  CHECK_NOT_NULL(stream);
  stream_data->stream.reset(stream);
  stream_data->id = stream->id();
  auto next =
      [&](int status, const ngtcp2_vec* data, size_t count, bob::Done done) {
        switch (status) {
          case bob::Status::STATUS_BLOCK:
            // Fall through
          case bob::Status::STATUS_WAIT:
            return;
          case bob::Status::STATUS_EOS:
            stream_data->fin = 1;
        }

        stream_data->count = count;

        if (count > 0) {
          stream->Schedule(&stream_queue_);
          stream_data->remaining = get_length(data, count);
        } else {
          stream_data->remaining = 0;
        }

        // Not calling done here because we defer committing
        // the data until after we're sure it's written.
      };

  if (LIKELY(!stream->is_eos())) {
    int ret = stream->Pull(std::move(next),
                           bob::Options::OPTIONS_SYNC,
                           stream_data->data,
                           arraysize(stream_data->data),
                           kMaxVectorCount);
    switch (ret) {
      case bob::Status::STATUS_EOS:
        stream_data->fin = 1;
        break;
    }
  } else {
    stream_data->fin = 1;
  }

  return 0;
}

bool DefaultApplication::StreamCommit(StreamData* stream_data, size_t datalen) {
  CHECK(stream_data->stream);
  stream_data->remaining -= datalen;
  Consume(&stream_data->buf, &stream_data->count, datalen);
  stream_data->stream->Commit(datalen);
  return true;
}

bool DefaultApplication::ShouldSetFin(const StreamData& stream_data) {
  if (!stream_data.stream || !IsEmpty(stream_data.buf, stream_data.count))
    return false;
  return true;
}

// ======================================================================================

std::unique_ptr<Session::Application> Session::SelectApplication(
    const Config& config, const Options& options) {
  if (options.crypto_options.alpn == QUIC_ALPN_H3)
    return std::make_unique<Http3Application>(this, options.application);

  // In the future, we may end up supporting additional QUIC protocols. As they
  // are added, extend the cases here to create and return them.

  return std::make_unique<DefaultApplication>(
      this, config, options.application);
}

}  // namespace quic
}  // namespace node
