#ifndef SRC_DNS_DNS_CARES_H_
#define SRC_DNS_DNS_CARES_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"

#include "ares.h"

#include <vector>
#include <unordered_set>

#ifdef __POSIX__
# include <netdb.h>
#endif  // __POSIX__

#if defined(__ANDROID__) || \
    defined(__MINGW32__) || \
    defined(__OpenBSD__) || \
    defined(_MSC_VER)

# include <nameser.h>
#else
# include <arpa/nameser.h>
#endif

#ifndef T_CAA
#  define T_CAA    257 /* Certification Authority Authorization */
#endif

#if defined(__OpenBSD__)
# define AI_V4MAPPED 0
#endif

namespace node {
namespace dns {

void SafeFreeHostent(struct hostent* host);

using HostEntPointer = DeleteFnPtr<hostent, SafeFreeHostent>;
using DataPointer = DeleteFnPtr<void, ares_free_data>;

// Manage memory using standardard smart pointer std::unique_tr
struct AresStringDeleter {
  void operator()(char* ptr) const noexcept { ares_free_string(ptr); }
};
using AresStringPointer = std::unique_ptr<char[], AresStringDeleter>;

#define DNS_ESETSRVPENDING -1000

inline const char* ToErrorCodeString(int status) {
  switch (status) {
#define V(code) case ARES_##code: return #code;
    V(EADDRGETNETWORKPARAMS)
    V(EBADFAMILY)
    V(EBADFLAGS)
    V(EBADHINTS)
    V(EBADNAME)
    V(EBADQUERY)
    V(EBADRESP)
    V(EBADSTR)
    V(ECANCELLED)
    V(ECONNREFUSED)
    V(EDESTRUCTION)
    V(EFILE)
    V(EFORMERR)
    V(ELOADIPHLPAPI)
    V(ENODATA)
    V(ENOMEM)
    V(ENONAME)
    V(ENOTFOUND)
    V(ENOTIMP)
    V(ENOTINITIALIZED)
    V(EOF)
    V(EREFUSED)
    V(ESERVFAIL)
    V(ETIMEOUT)
#undef V
  }

  return "UNKNOWN_ARES_ERROR";
}

class DNSContext;

// The DNSService manages the state of the process-wide c-ares library.
// It ensures that the c-ares library reference counting is handled
// correctly.
struct DNSService {
  int status = ARES_SUCCESS;
  DNSService();
  ~DNSService();
};

class DNSChannel {
 public:
  struct Options {
    int timeout = 0;
  };

  DNSChannel(const Options& options);
  ~DNSChannel();

  ares_channel channel() { return channel_; }

  int last_status() const { return last_status_; }

 private:
  ares_channel channel_;
  int last_status_ = ARES_SUCCESS;
};

class NodeAresTask : public MemoryRetainer {
 public:
  static std::unique_ptr<NodeAresTask> Create(
      DNSContext* context,
      ares_socket_t sock);

  NodeAresTask(DNSContext* context, ares_socket_t sock)
      : context_(context),
        sock_(sock) {}

  void PollStart(Environment* env, bool read, bool write);

  DNSContext* context() { return context_; }
  ares_socket_t sock() { return sock_; }

  SET_NO_MEMORY_INFO();
  SET_MEMORY_INFO_NAME(NodeAresTask);
  SET_SELF_SIZE(NodeAresTask);

  static NodeAresTask* FromPollWatcher(uv_poll_t* poll);
  static void Close(Environment* env, NodeAresTask* task);

  struct Hash {
    inline size_t operator()(ares_socket_t sock) const {
      return std::hash<ares_socket_t>()(sock);
    }
  };

  struct Equal {
    bool operator()(ares_socket_t a, ares_socket_t b) const {
      return a == b;
    }
  };

  using Map = std::unordered_map<
      ares_socket_t,
      std::unique_ptr<NodeAresTask>,
      Hash,
      Equal>;

 private:
  DNSContext* context_;
  ares_socket_t sock_;
  uv_poll_t poll_watcher_;
};

class DNSContext : public AsyncWrap {
 public:
  struct Options {
    DNSChannel::Options channel_options;
  };

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Initialize(Environment* env, v8::Local<v8::Object> target);

  DNSContext(
      Environment* env,
      v8::Local<v8::Object> object,
      const Options& options);

  ~DNSContext();

  NodeAresTask* FindOrCreateTask(ares_socket_t sock);
  void RemoveTask(ares_socket_t sock);

  void IncrementQuery() { queries_count_++; }
  void DecrementQuery() { queries_count_--; }

  std::vector<v8::Local<v8::Value>> GetServers(Environment* env);
  int SetServers(Environment* env, v8::Local<v8::Array> list);
  void SetLocalAddress(
      Environment* env,
      const char* ip,
      const char* ipOther = nullptr);
  void Cancel();

  ares_channel channel() const { return channel_->channel(); }

  void Setup();
  void EnsureServers();
  void StartTimer();
  void CloseTimer();
  void OnTimeout();
  void OnSockState(ares_socket_t sock, int read, int write);
  void OnPoll(NodeAresTask* task, int status, int events);

  int last_status() const { return last_status_; }

  void set_last_query_ok(bool ok = true) {
    if (ok) {
      flags_ = static_cast<Flags>(
        static_cast<int>(flags_) |
        (1 << static_cast<int>(Flags::LAST_QUERY_OK)));
    } else {
      flags_ = static_cast<Flags>(
        static_cast<int>(flags_) &
        ~(1 << static_cast<int>(Flags::LAST_QUERY_OK)));
    }
  }

  void set_default_servers(bool ok = true) {
    if (ok) {
      flags_ = static_cast<Flags>(
        static_cast<int>(flags_) |
        (1 << static_cast<int>(Flags::DEFAULT_SERVERS)));
    } else {
      flags_ = static_cast<Flags>(
        static_cast<int>(flags_) &
        ~(1 << static_cast<int>(Flags::DEFAULT_SERVERS)));
    }
  }

  SET_NO_MEMORY_INFO();
  SET_MEMORY_INFO_NAME(DNSContext);
  SET_SELF_SIZE(DNSContext);

 private:
  enum class Flags {
    DEFAULT_SERVERS = 0,
    LAST_QUERY_OK = 1
  };

  bool CheckFlag(Flags flag) const {
    return static_cast<int>(flags_) & (1 << static_cast<int>(flag));
  }

  Options options_;
  std::unique_ptr<DNSChannel> channel_;
  Flags flags_;
  uv_timer_t* timer_;
  int last_status_ = ARES_SUCCESS;
  size_t queries_count_ = 0;

  NodeAresTask::Map tasks_;
};

struct ResponseData {
  int status;
  bool is_host;
  HostEntPointer host;
  MallocedBuffer<unsigned char> buf;

  ResponseData(
      int status,
      unsigned char* answer_buf,
      int answer_len);

  ResponseData(int status, HostEntPointer host);
};

#define DNS_RECORD_TYPES(V)                                                    \
  V(A, "resolve4", ns_t_a)                                                     \
  V(AAAA, "resolve6", ns_t_aaaa)                                               \
  V(Caa, "resolveCaa", T_CAA)                                                  \
  V(Cname, "resolveCname", ns_t_cname)                                         \
  V(Mx, "resolveMx", ns_t_mx)                                                  \
  V(Ns, "resolveNs", ns_t_ns)                                                  \
  V(Txt, "resolveTxt", ns_t_txt)                                               \
  V(Srv, "resolveSrv", ns_t_srv)                                               \
  V(Ptr, "resolvePtr", ns_t_ptr)                                               \
  V(Naptr, "resolveNaptr", ns_t_naptr)                                         \
  V(Soa, "resolveSoa", ns_t_soa)

#define V(key, _, __) struct Query##key##Traits;
  DNS_RECORD_TYPES(V)
  struct QueryAnyTraits;
  struct GetHostByAddrTraits;
#undef V

template <typename QueryTraits>
class QueryWrap : public AsyncWrap {
 public:
  QueryWrap(DNSContext* context, v8::Local<v8::Object> obj, const char* name)
      : AsyncWrap(context->env(), obj, AsyncWrap::PROVIDER_QUERYWRAP),
        context_(context),
        name_(name) {
    context->IncrementQuery();
  }

  ~QueryWrap() {
    CHECK_EQ(false, persistent().IsEmpty());
    context_->DecrementQuery();
  }

  int Send() {
    context_->EnsureServers();
    // TODO(@jasnell): Re-enable trace events
    // TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
    //   TRACING_CATEGORY_NODE2(dns, native), trace_name_, this,
    //   "name", TRACE_STR_COPY(name));
    return QueryTraits::Send(this);
  }

  ares_channel channel() const {
    return context_->channel();
  }

  const std::string& name() const { return name_; }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(QueryWrap)
  SET_SELF_SIZE(QueryWrap)

 private:
  void HandleError(int status) {
    const char* code = ToErrorCodeString(status);
    v8::Local<v8::Value> arg = OneByteString(env()->isolate(), code);
    // TODO(@jasnell): Re-enable trace events
    // TRACE_EVENT_NESTABLE_ASYNC_END1(
    //     TRACING_CATEGORY_NODE2(dns, native), trace_name_, this,
    //     "error", status);
    MakeCallback(env()->oncomplete_string(), 1, &arg);
  }

  void HandleResponse(const ResponseData& response_data) {
    context_->set_last_query_ok(response_data.status != ARES_ECONNREFUSED);

    v8::HandleScope handle_scope(env()->isolate());
    v8::Context::Scope context_scope(env()->context());

    if (response_data.status != ARES_SUCCESS)
      return HandleError(response_data.status);

    std::vector<v8::Local<v8::Value>> vec;
    v8::Local<v8::Value> extra;
    int res = QueryTraits::Parse(this, response_data, &vec, &extra);

    if (res != ARES_SUCCESS) {
      return HandleError(res);
    } else  if (vec.size() == 0) {
      return HandleError(ARES_ENODATA);
    }

    if (extra.IsEmpty())
      extra = v8::Null(env()->isolate());

    v8::Local<v8::Value> argv[] = {
      v8::Integer::New(env()->isolate(), 0),
      v8::Array::New(env()->isolate(), vec.data(), vec.size()),
      extra
    };

    // TODO(@jasnell): Re-enable trace events
    // TRACE_EVENT_NESTABLE_ASYNC_END0(
    //     TRACING_CATEGORY_NODE2(dns, native), trace_name_, this);

    MakeCallback(env()->oncomplete_string(), arraysize(argv), argv);
  }

  static void AresCallback(
      void* arg,
      int status,
      int timeouts,
      unsigned char* answer_buf,
      int answer_len) {
    QueryWrap<QueryTraits>* wrap = static_cast<QueryWrap<QueryTraits>*>(arg);
    if (wrap != nullptr)
      wrap->HandleResponse(ResponseData(status, answer_buf, answer_len));
  }

  BaseObjectPtr<DNSContext> context_;
  std::string name_;

#define V(key, _, __) friend struct Query##key##Traits;
  DNS_RECORD_TYPES(V)
#undef V
  friend struct QueryAnyTraits;
  friend struct GetHostByAddrTraits;
};

enum class DNSParseFlag {
  // Parsing in the context of a resolveAny
  ANY,
  // Parsing only this kind of record
  ONLY
};

#define V(key, traceName, type)                                                \
  struct Query##key##Traits {                                                  \
    static constexpr const char* TraceName = traceName;                        \
    static constexpr int QueryType = type;                                     \
    static int Send(QueryWrap<Query##key##Traits>* wrap) {                     \
      ares_query(                                                              \
        wrap->channel(),                                                       \
        wrap->name().c_str(),                                                  \
        ns_c_in,                                                               \
        type,                                                                  \
        QueryWrap<Query##key##Traits>::AresCallback,                           \
        wrap);                                                                 \
      return ARES_SUCCESS;                                                     \
    }                                                                          \
    static int Parse(                                                          \
      QueryWrap<Query##key##Traits>* wrap,                                     \
      const ResponseData& response_data,                                       \
      std::vector<v8::Local<v8::Value>>* vec,                                  \
      v8::Local<v8::Value>* extra);                                            \
  };                                                                           \
  using Query##key##Wrap = QueryWrap<Query##key##Traits>;

  DNS_RECORD_TYPES(V)

#undef V

struct QueryAnyTraits {
  static constexpr const char* TraceName = "resolveAny";
  static constexpr int QueryType = ns_t_any;
  static int Send(QueryWrap<QueryAnyTraits>* wrap) {
    ares_query(
      wrap->channel(),
      wrap->name().c_str(),
      ns_c_in,
      QueryType,
      QueryWrap<QueryAnyTraits>::AresCallback,
      wrap);
    return ARES_SUCCESS;
  }
  static int Parse(
      QueryWrap<QueryAnyTraits>* wrap,
      const ResponseData& response_data,
      std::vector<v8::Local<v8::Value>>* vec,
      v8::Local<v8::Value>* extra);
};

struct GetHostByAddrTraits {
  static constexpr const char* TraceName = "reverse";
  static constexpr int QueryType = -1;  // Unused
  static int Send(QueryWrap<GetHostByAddrTraits>* wrap);
  static int Parse(
      QueryWrap<GetHostByAddrTraits>* wrap,
      const ResponseData& response_data,
      std::vector<v8::Local<v8::Value>>* vec,
      v8::Local<v8::Value>* extra);

  static void Callback(
      void* arg,
      int status,
      int timeouts,
      struct hostent* host);
};

using QueryAnyWrap = QueryWrap<QueryAnyTraits>;
using GetHostByAddrWrap = QueryWrap<GetHostByAddrTraits>;

namespace cares {
void Initialize(Environment* env, v8::Local<v8::Object> target);
}  // namespace cares

}  // namespace dns

namespace per_process {
  extern struct dns::DNSService dns_service_;
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_DNS_DNS_CARES_H_
