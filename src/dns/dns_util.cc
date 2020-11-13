#include "dns/dns_util.h"

#include "async_wrap-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "util-inl.h"

#include <unordered_map>

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace per_process {
struct dns::DNSService dns_service_;
};

namespace dns {

namespace {
const int kOptmask =
    ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_SOCK_STATE_CB;
const int kMaxTimeout = 1000;

void AresSockStateCallback(
    void* data,
    ares_socket_t sock,
    int read,
    int write) {
  DNSContext* context = static_cast<DNSContext*>(data);
  context->OnSockState(sock, read, write);
}

void AresTimeout(uv_timer_t* handle) {
  DNSContext* context = static_cast<DNSContext*>(handle->data);
  context->OnTimeout();
}

void AresPollCallback(uv_poll_t* watcher, int status, int events) {
  NodeAresTask* task = NodeAresTask::FromPollWatcher(watcher);
  task->context()->OnPoll(task, status, events);
}
}  // namespace

DNSService::DNSService() {
  status = ares_library_init(ARES_LIB_INIT_ALL);
}

DNSService::~DNSService() {
  if (status == ARES_SUCCESS)
    ares_library_cleanup();
}

DNSChannel::DNSChannel(const DNSChannel::Options& options) {
  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  opts.flags = ARES_FLAG_NOCHECKRESP;
  opts.sock_state_cb = AresSockStateCallback;
  opts.sock_state_cb_data = this;
  opts.timeout = options.timeout;
  last_status_ = ares_init_options(&channel_, &opts, kOptmask);
}

DNSChannel::~DNSChannel() {
  if (last_status_ == ARES_SUCCESS && channel_ != nullptr)
    ares_destroy(channel_);
}

void DNSContext::New(const FunctionCallbackInfo<Value>& args) {}

void DNSContext::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> ctx = env->NewFunctionTemplate(DNSContext::New);
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "DNSContext");
  ctx->SetClassName(class_name);
  ctx->Inherit(AsyncWrap::GetConstructorTemplate(env));
  ctx->InstanceTemplate()->SetInternalFieldCount(
      DNSContext::kInternalFieldCount);

  target->Set(
      env->context(),
      class_name,
      ctx->GetFunction(env->context()).ToLocalChecked()).Check();
}

DNSContext::DNSContext(
    Environment* env,
    Local<Object> object,
    const Options& options)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_DNSCONTEXT),
      options_(options) {
  MakeWeak();
  Setup();
  set_default_servers();
  set_last_query_ok();
}

DNSContext::~DNSContext() {
  for (auto iter = tasks_.begin(); iter != tasks_.end(); ++iter)
    RemoveTask(iter->first);
}

void DNSContext::Setup() {
  channel_ = std::make_unique<DNSChannel>(options_.channel_options);
  last_status_ = channel_->last_status();
}

void DNSContext::EnsureServers() {
  // If the last query is OK or servers are set by the user, do not check.
  if (CheckFlag(Flags::LAST_QUERY_OK) ||
      !CheckFlag(Flags::DEFAULT_SERVERS) ||
      last_status_ != ARES_SUCCESS) {
    return;
  }

  ares_addr_port_node* servers = nullptr;
  ares_get_servers_ports(channel_->channel(), &servers);
  if (servers == nullptr)
    return;

  DeleteFnPtr<void, ares_free_data> delete_me(servers);

  // If no server or multiple servers, ignore.
  // If the only server is not 127.0.0.1, ignore.
  if (servers->next != nullptr ||
      servers[0].family != AF_INET ||
      servers[0].addr.addr4.s_addr != htonl(INADDR_LOOPBACK) ||
      servers[0].tcp_port != 0 ||
      servers[0].udp_port != 0) {
    set_default_servers(false);
    return;
  }

  // Reset the timer and channel
  CloseTimer();
  Setup();
}

void DNSContext::OnTimeout() {
  ares_process_fd(channel_->channel(), ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

void DNSContext::StartTimer() {
  if (timer_ == nullptr) {
    timer_ = new uv_timer_t();
    timer_->data = static_cast<void*>(this);
    uv_timer_init(env()->event_loop(), timer_);
  } else if (uv_is_active(reinterpret_cast<uv_handle_t*>(timer_))) {
    return;
  }

  int timeout = options_.channel_options.timeout;
  if (timeout == 0)
    timeout = 1;
  if (timeout < 0 || timeout > kMaxTimeout)
    timeout = kMaxTimeout;
  uv_timer_start(timer_, AresTimeout, timeout, timeout);
}

void DNSContext::CloseTimer() {
  if (timer_ == nullptr)
    return;

  env()->CloseHandle(timer_, [](uv_timer_t* handle) {
    std::unique_ptr<uv_timer_t> delete_me(handle);
  });
  timer_ = nullptr;
}

NodeAresTask* DNSContext::FindOrCreateTask(ares_socket_t sock) {
  NodeAresTask* task;
  auto it = tasks_.find(sock);
  if (it != tasks_.end()) {
     task = it->second.get();
  } else {
    task = (tasks_[sock] = NodeAresTask::Create(this, sock)).get();
  }
  StartTimer();
  return task;
}

void DNSContext::RemoveTask(ares_socket_t sock) {
  auto it = tasks_.find(sock);
  if (it != tasks_.end()) {
    NodeAresTask::Close(env(), it->second.release());
    tasks_.erase(it);
  }

  if (tasks_.empty())
    CloseTimer();
}

void DNSContext::OnSockState(ares_socket_t sock, int read, int write) {
  if (read || write) {
    NodeAresTask* task = FindOrCreateTask(sock);
    if (task != nullptr)
      task->PollStart(env(), read, write);
  } else {
    RemoveTask(sock);
  }
}

void DNSContext::OnPoll(NodeAresTask* task, int status, int events) {
  uv_timer_again(timer_);
  ares_process_fd(
      channel_->channel(),
      status < 0 || events & UV_READABLE ? task->sock() : ARES_SOCKET_BAD,
      status < 0 || events & UV_WRITABLE ? task->sock() : ARES_SOCKET_BAD);
}

std::unique_ptr<NodeAresTask> NodeAresTask::Create(
    DNSContext* context,
    ares_socket_t sock) {
  std::unique_ptr<NodeAresTask> task =
      std::make_unique<NodeAresTask>(context, sock);

  if (uv_poll_init_socket(
          context->env()->event_loop(),
          &task->poll_watcher_,
          sock) < 0) {
    return std::unique_ptr<NodeAresTask>();
  }

  return task;
}

void NodeAresTask::Close(Environment* env, NodeAresTask* task) {
  env->CloseHandle(&task->poll_watcher_, [](uv_poll_t* watcher) {
    std::unique_ptr<NodeAresTask> delete_me(
        ContainerOf(&NodeAresTask::poll_watcher_, watcher));
  });
}

NodeAresTask* NodeAresTask::FromPollWatcher(uv_poll_t* handle) {
  return ContainerOf(&NodeAresTask::poll_watcher_, handle);
}

void NodeAresTask::PollStart(Environment* env, bool read, bool write) {
  uv_poll_start(
      &poll_watcher_,
      (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0),
      AresPollCallback);
}

void Initialize(
    Local<Object> target,
    Local<Value> unused,
    Local<Context> context,
    void* priv) {
  Environment* env = Environment::GetCurrent(context);
  DNSContext::Initialize(env, target);
}

}  // namespace dns
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(dns, node::dns::Initialize);
