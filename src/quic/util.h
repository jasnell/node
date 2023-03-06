#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "defs.h"
#include "bindingdata.h"
#include <base_object.h>
#include <env.h>
#include <memory_tracker.h>
#include <node.h>
#include <node_errors.h>
#include <node_mutex.h>
#include <node_sockaddr.h>
#include <v8.h>
#include <ngtcp2/ngtcp2.h>
#include <string>
#include <optional>

namespace node {
namespace quic {

// ============================================================================

struct Path final : public ngtcp2_path {
  inline Path(const SocketAddress& local, const SocketAddress& remote);
};

struct PathStorage final : public ngtcp2_path_storage {
  inline PathStorage();
  inline operator ngtcp2_path();
};

// ============================================================================

// A Packet encapsulates serialized outbound QUIC data.
class Packet final : public ReqWrap<uv_udp_send_t> {
 private:
  struct Data;

 public:
  using Queue = std::deque<BaseObjectPtr<Packet>>;
  GET_CONSTRUCTOR_TEMPLATE()
  HAS_INSTANCE()

  class Listener {
   public:
    virtual void PacketDone(int status) = 0;
  };

  // Really should be private but MakeBaseObject needs to be able to see it.
  // Use Create() to create instances.
  Packet(Environment* env,
         Listener* listener,
         v8::Local<v8::Object> object,
         const SocketAddress& destination,
         size_t length,
         const char* diagnostic_label = "<unknown>");

  // Really should be private but MakeBaseObject needs to be able to see it.
  // Use Create() to create instances.
  Packet(Environment* env,
         Listener* listener,
         v8::Local<v8::Object> object,
         const SocketAddress& destination,
         std::shared_ptr<Data> data);

  QUIC_NO_COPY_OR_MOVE(Packet)

  inline const SocketAddress& destination() const;
  inline bool is_pending() const;
  inline size_t length() const;
  inline operator uv_buf_t() const;
  inline operator ngtcp2_vec() const;
  inline void Truncate(size_t len);

  static BaseObjectPtr<Packet> Create(
      Environment* env,
      Listener* listener,
      const SocketAddress& destination,
      size_t length = kDefaultMaxPacketLength,
      const char* diagnostic_label = "<unknown>");

  BaseObjectPtr<Packet> Clone() const;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(Packet)
  SET_SELF_SIZE(Packet)

  std::string ToString() const;

 private:
  struct Data final : public MemoryRetainer {
    MaybeStackBuffer<uint8_t, kDefaultMaxPacketLength> data_;

    // The diagnostic_label_ is used only as a debugging tool when
    // logging debug information about the packet. It identifies
    // the purpose of the packet.
    const std::string diagnostic_label_;

    void MemoryInfo(MemoryTracker* tracker) const override;
    SET_MEMORY_INFO_NAME(Data)
    SET_SELF_SIZE(Data)

    Data(size_t length, const char* diagnostic_label);
    size_t length() const;
    uint8_t* data();
  };

  inline void Attach(BaseObjectPtr<BaseObject> handle);
  void Done(int status);

  Listener* listener_;
  SocketAddress destination_;
  std::shared_ptr<Data> data_;

  BaseObjectPtr<BaseObject> handle_;

  friend class Endpoint;
  friend class UDP;
};

// =============================================================================
// Store

// Store provides a utility wrapper around v8::BackingStore that provides
// transparent adaptation to both uv_buf_t, ngtcp2_vec, and nghttp3_vec.
class Store final : public MemoryRetainer {
 public:
  Store() = default;

  explicit Store(std::shared_ptr<v8::BackingStore> store,
                 size_t length,
                 size_t offset = 0);
  explicit Store(std::unique_ptr<v8::BackingStore> store,
                 size_t length,
                 size_t offset = 0);

  enum class Option {
    NONE,
    DETACH,
  };

  explicit Store(v8::Local<v8::ArrayBuffer> buffer,
                 Option option = Option::NONE);
  explicit Store(v8::Local<v8::ArrayBufferView> view,
                 Option option = Option::NONE);

  inline operator uv_buf_t() const;
  inline operator ngtcp2_vec() const;
  inline operator nghttp3_vec() const;
  inline operator bool() const;
  inline size_t length() const;

  template <typename View>
  inline v8::Local<View> ToArrayBufferView(Environment* env) const;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(Store)
  SET_SELF_SIZE(Store)

 private:
  std::shared_ptr<v8::BackingStore> store_;
  size_t offset_ = 0;
  size_t length_ = 0;
};

// =============================================================================
// QuicError

class QuicError final : public MemoryRetainer {
 public:
  enum class Type : int {
    TRANSPORT = NGTCP2_CONNECTION_CLOSE_ERROR_CODE_TYPE_TRANSPORT,
    APPLICATION = NGTCP2_CONNECTION_CLOSE_ERROR_CODE_TYPE_APPLICATION,
    VERSION_NEGOTIATION =
        NGTCP2_CONNECTION_CLOSE_ERROR_CODE_TYPE_TRANSPORT_VERSION_NEGOTIATION,
    IDLE_CLOSE = NGTCP2_CONNECTION_CLOSE_ERROR_CODE_TYPE_TRANSPORT_IDLE_CLOSE,
  };

  explicit QuicError(const std::string_view reason = "");
  explicit QuicError(const ngtcp2_connection_close_error* ptr);
  explicit QuicError(const ngtcp2_connection_close_error& error);

  inline Type type() const;
  inline error_code code() const;
  inline const std::string_view reason() const;
  inline uint64_t frameType() const;
  inline const ngtcp2_connection_close_error& operator*() const;
  inline const ngtcp2_connection_close_error* operator->() const;
  inline operator const ngtcp2_connection_close_error*() const;

  // Returns false if the QuicError uses a no_error code with type
  // transport or application
  operator bool() const;

  // Equality comparison that ignores the reason but compares the
  // type, code, and frameType.
  inline bool operator==(const QuicError& other) const;
  inline bool operator!=(const QuicError& other) const;

  static QuicError ForTransport(
      error_code code,
      const std::string_view reason = "");
  static QuicError ForApplication(
      error_code code,
      const std::string_view reason = "");
  static QuicError ForVersionNegotiation(
      const std::string_view reason = "");
  static QuicError ForIdleClose(
      const std::string_view reason = "");
  static QuicError ForNgtcp2Error(
      int code,
      const std::string_view reason = "");
  static QuicError ForTlsAlert(
      int code,
      const std::string_view reason = "");

  static QuicError FromConnectionClose(ngtcp2_conn* session);

  static QuicError TRANSPORT_NO_ERROR;
  static QuicError APPLICATION_NO_ERROR;
  static QuicError VERSION_NEGOTIATION;
  static QuicError IDLE_CLOSE;

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(QuicError)
  SET_SELF_SIZE(QuicError)

  std::string ToString() const;

  v8::MaybeLocal<v8::Value> ToV8Value(Environment* env);

 private:
  const uint8_t* reason_c_str() const;

  std::string reason_;
  ngtcp2_connection_close_error error_;
  const ngtcp2_connection_close_error* ptr_ = nullptr;
};

// =============================================================================
// StatsBase is a base utility helper for classes (like Endpoint, Session, and
// Stream) that want to record statistics.

class StatsBase : public MemoryRetainer {
 public:
  StatsBase(Environment* env, size_t size);
  QUIC_NO_COPY_OR_MOVE(StatsBase)

  v8::Local<v8::BigUint64Array> ToBigUint64Array(Environment* env);

  inline void* Data() { return stats_store_->Data(); }

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(StatsBase)
  SET_SELF_SIZE(StatsBase)

 private:
  std::shared_ptr<v8::BackingStore> stats_store_;
};

template <typename Traits>
class StatsImpl final : public StatsBase {
 public:
  using Stats = typename Traits::Stats;
  using Base = typename Traits::Base;

  explicit StatsImpl(Environment* env)
      : StatsBase(env, sizeof(Stats)),
        stats_(new(Data()) Stats) {
    DCHECK_NOT_NULL(stats_);
    stats_->created_at = uv_hrtime();
  }

  struct StatsDebug final {
    Base& stats;
    inline explicit StatsDebug(Base& stats_) : stats(stats_) {}
    inline std::string ToString() const {
      std::string out = "Statistics:\n";
      const auto add_field = [&out](const char* name, uint64_t val) {
        out += "  ";
        out += std::string(name);
        out += ": ";
        out += std::to_string(val);
        out += "\n";
      };
      add_field("Duration", uv_hrtime() - stats.GetStat(&Stats::created_at));
      Traits::ToString(stats, add_field);
      return out;
    }
  };

  inline operator const StatsDebug() const { return StatsDebug(*this); }
  inline operator const Stats&() const { return *stats_; }

  // Increments the given stat field by the given amount or 1 if no amount is
  // specified.
  template <uint64_t Stats::*member>
  inline void Increment(uint64_t amount = 1) {
    stats_->*member += std::min(amount, kMaxUint64 - stats_->*member);
  }

  // Sets an entirely new value for the given stat field
  template <uint64_t Stats::*member>
  inline void Set(uint64_t value) {
    stats_->*member = value;
  }

  // Sets the given stat field to the current uv_hrtime()
  template <uint64_t Stats::*member>
  inline void RecordTimestamp() {
    stats_->*member = uv_hrtime();
  }

  // Gets the current value of the given stat field
  template <uint64_t Stats::*member>
  inline uint64_t Get() const { return stats_->*member; }

 private:
  Stats* stats_;
};

// =============================================================================

struct CallbackScopeBase {
  Environment* env;
  v8::Context::Scope context_scope;
  v8::TryCatch try_catch;

  explicit CallbackScopeBase(Environment* env);
  QUIC_NO_COPY_OR_MOVE(CallbackScopeBase)
  ~CallbackScopeBase();
};

template <typename T>
struct CallbackScope final : public CallbackScopeBase {
  BaseObjectPtr<T> ref;
  explicit CallbackScope(const T* ptr)
      : CallbackScopeBase(ptr->env()),
        ref(ptr) {}
};

// =============================================================================

void IllegalConstructor(const v8::FunctionCallbackInfo<v8::Value>& args);

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
