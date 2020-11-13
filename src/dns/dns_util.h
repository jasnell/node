#ifndef SRC_DNS_DNS_UTIL_H_
#define SRC_DNS_DNS_UTIL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#define CARES_STATICLIB

#include "async_wrap.h"
#include "env.h"
#include "memory_tracker.h"
#include "node.h"
#include "util.h"

#include "ares.h"
#include "uv.h"
#include "v8.h"

namespace node {
namespace dns {

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

  NodeAresTask::Map tasks_;
};

}  // namespace dns

namespace per_process {
  extern struct dns::DNSService dns_service_;
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_DNS_DNS_UTIL_H_
