// Prototype: a fork server ("zygote") for fast process startup.
//
// A zygote is a Node.js process that has bootstrapped and run its --require
// preloads but has no entry script. serve() listens on a Unix domain socket
// and forks a child as soon as it accepts a connection. The child reads the
// client's request and becomes the client's program: it adopts the client's
// stdio file descriptors (passed via SCM_RIGHTS), cwd, umask, argv and
// environment, then returns to JavaScript to run the requested program. The
// zygote never reads requests itself, so clients are served in parallel; it
// reports each child's pid and wait status back to its client.
//
// fork() is only safe while no other thread holds a lock, so serve() first
// joins the V8 platform threads and refuses to run while any thread that is
// not known to be fork-tolerant is alive. The zygote never runs JavaScript
// again after entering the accept loop; only children restart the platform.
//
// The client is `node --connect=<socket> <script> [args...]` or
// `node --connect=<socket> -e|-p <code> [args...]` (RunClient()), which runs
// right after option parsing, before V8 and OpenSSL are initialized.
//
// Wire protocol (host byte order, local sockets only):
//   request:  RequestHeader, then payload_size bytes of NUL-terminated
//             strings: cwd, argv[0..argc), env[0..envc). The first sendmsg()
//             carries SCM_RIGHTS with the client's fds 0, 1 and 2. With
//             kModeScript, argv[0] is the main module; with kModeEval and
//             kModePrint, argv[0] is the code to evaluate (-e, -p). The
//             remaining argv strings are the program's arguments.
//   replies:  Reply{'P', pid} once the child is forked, then
//             Reply{'X', wait status} once it has terminated.

#include "node_zygote.h"
#include "env-inl.h"
#include "node_errors.h"
#include "node_external_reference.h"
#include "node_internals.h"
#include "node_v8_platform-inl.h"
#include "util-inl.h"
#include "uv.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef __linux__
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif  // __linux__

namespace node {
namespace zygote {

using v8::Array;
using v8::Context;
using v8::Float64Array;
using v8::FunctionCallbackInfo;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Value;

// Fills a Float64Array with uniformly distributed doubles in [0, 1) from the
// OS CSPRNG. Children use it to reseed Math.random(), whose state would
// otherwise be identical in every process forked from the same zygote.
static void FillRandom(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsFloat64Array());
  Local<Float64Array> array = args[0].As<Float64Array>();
  const size_t length = array->Length();
  std::vector<uint64_t> bits(length);
  CHECK_EQ(uv_random(nullptr,
                     nullptr,
                     bits.data(),
                     length * sizeof(bits[0]),
                     0,
                     nullptr),
           0);
  uint8_t* data =
      static_cast<uint8_t*>(array->Buffer()->Data()) + array->ByteOffset();
  for (size_t i = 0; i < length; i++) {
    const double value = static_cast<double>(bits[i] >> 11) * 0x1.0p-53;
    memcpy(data + i * sizeof(value), &value, sizeof(value));
  }
}

#ifdef __linux__

constexpr uint32_t kRequestMagic = 0x4e5a5947;  // "NZYG"
constexpr uint32_t kReplyPid = 'P';
constexpr uint32_t kReplyExit = 'X';
constexpr uint32_t kMaxPayloadSize = 1 << 20;
// Exit status of a child whose request could not be read or was invalid.
constexpr int kInvalidRequestExitCode = 125;

// RequestHeader::mode.
constexpr uint32_t kModeScript = 0;
constexpr uint32_t kModeEval = 1;
constexpr uint32_t kModePrint = 2;

struct RequestHeader {
  uint32_t magic;
  uint32_t mode;
  uint32_t argc;
  uint32_t envc;
  uint32_t umask;
  uint32_t payload_size;
};

struct Reply {
  uint32_t type;
  int32_t value;
};

struct Request {
  int fds[3] = {-1, -1, -1};
  uint32_t mode = kModeScript;
  mode_t umask = 022;
  std::string cwd;
  std::vector<std::string> argv;
  std::vector<std::string> env;

  void CloseFds() {
    for (int& fd : fds) {
      if (fd >= 0) close(fd);
      fd = -1;
    }
  }
};

struct Child {
  pid_t pid;
  int conn_fd;
  int pidfd;
  bool client_gone;
};

static bool ReadFully(int fd, char* buf, size_t len) {
  while (len > 0) {
    ssize_t n = read(fd, buf, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    buf += n;
    len -= n;
  }
  return true;
}

static void SendReply(int fd, uint32_t type, int32_t value) {
  const Reply reply{type, value};
  // The client may already be gone; there is nobody to report errors to.
  USE(send(fd, &reply, sizeof(reply), MSG_NOSIGNAL));
}

static bool ReadRequest(int conn, Request* req) {
  RequestHeader header;
  char control[CMSG_SPACE(sizeof(int) * 3)];
  iovec iov{&header, sizeof(header)};
  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  ssize_t n;
  do {
    n = recvmsg(conn, &msg, MSG_CMSG_CLOEXEC);
  } while (n < 0 && errno == EINTR);
  if (n <= 0) return false;

  for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
      continue;
    }
    const size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t i = 0; i < count; i++) {
      int fd;
      memcpy(&fd, CMSG_DATA(cmsg) + i * sizeof(int), sizeof(fd));
      if (i < 3 && req->fds[i] == -1) {
        req->fds[i] = fd;
      } else {
        close(fd);
      }
    }
  }

  const bool ok =
      !(msg.msg_flags & MSG_CTRUNC) && req->fds[0] >= 0 &&
      req->fds[1] >= 0 && req->fds[2] >= 0 &&
      (static_cast<size_t>(n) == sizeof(header) ||
       ReadFully(conn,
                 reinterpret_cast<char*>(&header) + n,
                 sizeof(header) - n)) &&
      header.magic == kRequestMagic && header.mode <= kModePrint &&
      header.argc > 0 && header.payload_size <= kMaxPayloadSize;
  if (!ok) {
    req->CloseFds();
    return false;
  }

  std::string payload(header.payload_size, '\0');
  if (!ReadFully(conn, payload.data(), payload.size()) ||
      (!payload.empty() && payload.back() != '\0')) {
    req->CloseFds();
    return false;
  }

  std::vector<std::string> strings;
  for (size_t start = 0; start < payload.size();) {
    size_t end = payload.find('\0', start);
    strings.emplace_back(payload, start, end - start);
    start = end + 1;
  }
  if (strings.size() != 1 + static_cast<size_t>(header.argc) + header.envc) {
    req->CloseFds();
    return false;
  }

  req->mode = header.mode;
  req->umask = static_cast<mode_t>(header.umask & 0777);
  req->cwd = std::move(strings[0]);
  req->argv.assign(std::make_move_iterator(strings.begin() + 1),
                   std::make_move_iterator(strings.begin() + 1 + header.argc));
  req->env.assign(std::make_move_iterator(strings.begin() + 1 + header.argc),
                  std::make_move_iterator(strings.end()));
  return true;
}

// Lists threads other than the calling one that make fork() unsafe. Idle
// libuv threadpool threads are tolerated: they hold no locks while the loop
// has no active requests, and libuv re-creates the pool in the child.
static std::string ForkUnsafeThreads() {
  DIR* dir = opendir("/proc/self/task");
  if (dir == nullptr) return "(cannot read /proc/self/task)";
  const std::string self = std::to_string(syscall(SYS_gettid));
  std::string result;
  while (dirent* entry = readdir(dir)) {
    if (entry->d_name[0] == '.' || self == entry->d_name) continue;
    const std::string path =
        std::string("/proc/self/task/") + entry->d_name + "/comm";
    char name[32] = "?";
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      ssize_t n = read(fd, name, sizeof(name) - 1);
      close(fd);
      if (n > 0) name[name[n - 1] == '\n' ? n - 1 : n] = '\0';
    }
    if (strcmp(name, "libuv-worker") == 0) continue;
    if (!result.empty()) result += ", ";
    result += name;
  }
  closedir(dir);
  return result;
}

// On Linux, V8 marks every mapping it creates MADV_DONTFORK
// (V8_ENABLE_PRIVATE_MAPPING_FORK_OPTIMIZATION) so that fork()+exec() from
// child_process stays cheap. A zygote's children need that memory: the whole
// point is to inherit the warm heap. Undo the advice for everything mapped so
// far; the zygote does not allocate after it starts serving. Mappings created
// later by the children keep the optimization for their own spawn() calls.
static void MakeMappingsInheritable() {
  FILE* maps = fopen("/proc/self/maps", "re");
  CHECK_NOT_NULL(maps);
  char* line = nullptr;
  size_t capacity = 0;
  while (getline(&line, &capacity, maps) > 0) {
    uintptr_t start;
    uintptr_t end;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end) != 2) continue;
    // Special mappings such as [vsyscall] reject this; that is fine.
    madvise(reinterpret_cast<void*>(start), end - start, MADV_DOFORK);
  }
  free(line);
  fclose(maps);
}

static int Listen(const std::string& path, std::string* error) {
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    *error = "socket path too long";
    return -1;
  }
  memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  // Non-blocking, so that the accept loop can drain the backlog.
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    *error = std::string("socket(): ") + strerror(errno);
    return -1;
  }
  unlink(path.c_str());  // Remove a stale socket from a previous zygote.
  // Only the owner may connect; accepted peers are checked again below.
  const mode_t old_umask = umask(0177);
  const int r = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  umask(old_umask);
  if (r != 0 || listen(fd, 128) != 0) {
    *error = std::string("bind()/listen(): ") + strerror(errno);
    close(fd);
    return -1;
  }
  return fd;
}

// Runs the accept loop. Returns (in a forked child only) an array
// [pid, cwd, argv, env, mode] describing the program the child should become.
static void Serve(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  CHECK(env->is_main_thread());
  CHECK(env->owns_process_state());
  CHECK(args[0]->IsString());
  const std::string path = Utf8Value(isolate, args[0]).ToString();

  if (env->event_loop()->active_reqs.count != 0) {
    return THROW_ERR_INVALID_STATE(
        env, "zygote: cannot fork while the event loop has active requests");
  }

  std::string error;
  const int listen_fd = Listen(path, &error);
  if (listen_fd < 0) {
    return THROW_ERR_INVALID_STATE(env, "zygote: %s", error);
  }

  // Collect the preloads' garbage once here, instead of in every child (each
  // child would copy the pages its collector touches).
  isolate->LowMemoryNotification();

  NodePlatform* platform = per_process::v8_platform.Platform();
  platform->StopWorkerThreadsForFork();

  const std::string unsafe_threads = ForkUnsafeThreads();
  if (!unsafe_threads.empty()) {
    platform->RestartWorkerThreadsAfterFork();
    close(listen_fd);
    unlink(path.c_str());
    return THROW_ERR_INVALID_STATE(
        env, "zygote: cannot fork while these threads are alive: %s",
        unsafe_threads);
  }

  MakeMappingsInheritable();

  std::vector<Child> children;
  std::vector<pollfd> pollfds;
  for (;;) {
    pollfds.clear();
    pollfds.push_back({listen_fd, POLLIN, 0});
    for (const Child& child : children) {
      pollfds.push_back({child.pidfd, POLLIN, 0});
      // Hangup only: the child reads its request from this socket, so the
      // zygote must not consume data from it.
      pollfds.push_back(
          {child.client_gone ? -1 : child.conn_fd, POLLRDHUP, 0});
    }
    if (poll(pollfds.data(), pollfds.size(), -1) < 0) {
      CHECK_EQ(errno, EINTR);
      continue;
    }

    for (size_t i = children.size(); i-- > 0;) {
      Child& child = children[i];
      if (pollfds[1 + 2 * i].revents & POLLIN) {
        int status = 0;
        while (waitpid(child.pid, &status, 0) < 0 && errno == EINTR) {}
        SendReply(child.conn_fd, kReplyExit, status);
        close(child.conn_fd);
        close(child.pidfd);
        children.erase(children.begin() + i);
        continue;
      }
      if (pollfds[2 + 2 * i].revents & (POLLRDHUP | POLLHUP | POLLERR)) {
        // The client disappeared: hang up the child's session, as a terminal
        // would. Until the child calls setsid() it has no process group.
        child.client_gone = true;
        if (kill(-child.pid, SIGHUP) != 0) kill(child.pid, SIGHUP);
      }
    }

    if (!(pollfds[0].revents & POLLIN)) continue;

    // Fork a child for every pending connection. Each child reads its own
    // request, so a slow client delays only its own program.
    for (;;) {
      const int conn = accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
      if (conn < 0) {
        if (errno == EINTR || errno == ECONNABORTED) continue;
        break;  // EAGAIN: the backlog is drained.
      }
      ucred cred{};
      socklen_t cred_len = sizeof(cred);
      if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0 ||
          cred.uid != geteuid()) {
        close(conn);
        continue;
      }

      const pid_t pid = fork();
      if (pid < 0) {
        SendReply(conn, kReplyExit, W_EXITCODE(127, 0));
        close(conn);
        continue;
      }

      if (pid > 0) {
        SendReply(conn, kReplyPid, pid);
        const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
        CHECK_GE(pidfd, 0);
        children.push_back({pid, conn, pidfd, false});
        continue;
      }

      // Child.
      close(listen_fd);
      for (const Child& child : children) {
        close(child.conn_fd);
        close(child.pidfd);
      }
      const timeval timeout{1, 0};
      Request req;
      if (setsockopt(
              conn, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
          !ReadRequest(conn, &req)) {
        // Nothing has run in this process yet; skip the zygote's exit hooks.
        _exit(kInvalidRequestExitCode);
      }
      close(conn);
      for (int i = 0; i < 3; i++) {
        // Node.js keeps fds 0-2 open, so the received fds are all > 2.
        CHECK_GT(req.fds[i], 2);
        CHECK_EQ(dup2(req.fds[i], i), i);
      }
      req.CloseFds();
      // New session: no controlling terminal and a process group the client
      // can signal as a whole.
      setsid();
      umask(req.umask);
      CHECK_EQ(uv_loop_fork(env->event_loop()), 0);
      platform->RestartWorkerThreadsAfterFork();

      Local<Context> context = env->context();
      Local<Value> cwd;
      Local<Value> argv;
      Local<Value> environ;
      if (!ToV8Value(context, req.cwd, isolate).ToLocal(&cwd) ||
          !ToV8Value(context, req.argv, isolate).ToLocal(&argv) ||
          !ToV8Value(context, req.env, isolate).ToLocal(&environ)) {
        return;
      }
      Local<Value> result[] = {Integer::New(isolate, getpid()),
                               cwd,
                               argv,
                               environ,
                               Integer::NewFromUnsigned(isolate, req.mode)};
      args.GetReturnValue().Set(
          Array::New(isolate, result, arraysize(result)));
      return;
    }
  }
}

// Client side: `node --connect=<socket> <script> [args...]`.

static volatile sig_atomic_t client_child_pid = 0;
static volatile sig_atomic_t client_pending_signal = 0;

static void ForwardSignalToChild(int signo) {
  const pid_t pid = client_child_pid;
  if (pid <= 0) {
    client_pending_signal = signo;
    return;
  }
  const int saved_errno = errno;
  // The child calls setsid() right after fork(); until it does, its process
  // group does not exist.
  if (kill(-pid, signo) != 0) kill(pid, signo);
  errno = saved_errno;
}

ExitCode RunClient(const std::string& socket_path,
                   const std::vector<std::string>& args,
                   const std::optional<std::string>& eval_code,
                   bool print_eval) {
  // Exit code for failures of the client itself, as opposed to the child.
  constexpr ExitCode kClientFailure = static_cast<ExitCode>(125);
  const char* self = args[0].c_str();

  // argv[0] of the request is the main module, or the code to evaluate.
  uint32_t mode = kModeScript;
  std::vector<std::string> request_argv;
  if (eval_code.has_value()) {
    mode = print_eval ? kModePrint : kModeEval;
    request_argv.push_back(*eval_code);
  } else if (args.size() < 2) {
    fprintf(stderr,
            "%s: --connect requires a script, --eval or --print\n",
            self);
    return ExitCode::kInvalidCommandLineArgument;
  }
  request_argv.insert(request_argv.end(), args.begin() + 1, args.end());

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socket_path.size() >= sizeof(addr.sun_path)) {
    fprintf(stderr, "%s: --connect: socket path too long\n", self);
    return ExitCode::kInvalidCommandLineArgument;
  }
  memcpy(addr.sun_path, socket_path.c_str(), socket_path.size() + 1);

  const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0) {
    fprintf(stderr, "%s: socket(): %s\n", self, strerror(errno));
    return kClientFailure;
  }
  auto close_sock = OnScopeLeave([sock]() { close(sock); });
  if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    fprintf(stderr,
            "%s: cannot connect to %s: %s\n",
            self,
            socket_path.c_str(),
            strerror(errno));
    return kClientFailure;
  }

  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == nullptr) {
    fprintf(stderr, "%s: getcwd(): %s\n", self, strerror(errno));
    return kClientFailure;
  }

  // Payload: cwd, argv, environment; each string including its terminating
  // NUL.
  std::string payload(cwd, strlen(cwd) + 1);
  for (const std::string& arg : request_argv) {
    payload.append(arg.c_str(), arg.size() + 1);
  }
  uint32_t envc = 0;
  for (char** entry = ::environ; *entry != nullptr; entry++, envc++) {
    payload.append(*entry, strlen(*entry) + 1);
  }
  if (payload.size() > kMaxPayloadSize) {
    fprintf(stderr, "%s: --connect: request too large\n", self);
    return kClientFailure;
  }

  const mode_t mask = umask(0);
  umask(mask);
  const RequestHeader header{kRequestMagic,
                             mode,
                             static_cast<uint32_t>(request_argv.size()),
                             envc,
                             static_cast<uint32_t>(mask),
                             static_cast<uint32_t>(payload.size())};
  std::string message(reinterpret_cast<const char*>(&header), sizeof(header));
  message += payload;

  // From here on, signals are forwarded to the child, or recorded until its
  // pid is known. PlatformInit() leaves SIGUSR1 blocked.
  struct sigaction sa {};
  sa.sa_handler = ForwardSignalToChild;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  for (int signo :
       {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH, SIGUSR1, SIGUSR2}) {
    CHECK_EQ(sigaction(signo, &sa, nullptr), 0);
  }
  sigset_t usr1;
  sigemptyset(&usr1);
  sigaddset(&usr1, SIGUSR1);
  CHECK_EQ(pthread_sigmask(SIG_UNBLOCK, &usr1, nullptr), 0);

  // The first chunk carries fds 0-2 as ancillary data.
  const int fds[3] = {0, 1, 2};
  char control[CMSG_SPACE(sizeof(fds))];
  memset(control, 0, sizeof(control));
  iovec iov{message.data(), message.size()};
  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
  memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

  for (size_t sent = 0; sent < message.size();) {
    const ssize_t n = sent == 0 ? sendmsg(sock, &msg, MSG_NOSIGNAL)
                                : send(sock,
                                       message.data() + sent,
                                       message.size() - sent,
                                       MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      fprintf(stderr,
              "%s: cannot send to %s: %s\n",
              self,
              socket_path.c_str(),
              strerror(errno));
      return kClientFailure;
    }
    sent += n;
  }

  for (;;) {
    Reply reply;
    if (!ReadFully(sock, reinterpret_cast<char*>(&reply), sizeof(reply))) {
      fprintf(stderr,
              "%s: lost connection to the zygote at %s\n",
              self,
              socket_path.c_str());
      return kClientFailure;
    }
    if (reply.type == kReplyPid) {
      client_child_pid = reply.value;
      if (client_pending_signal != 0) {
        ForwardSignalToChild(client_pending_signal);
      }
      continue;
    }
    if (reply.type != kReplyExit) continue;

    const int status = reply.value;
    if (WIFEXITED(status)) {
      return static_cast<ExitCode>(WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      // Terminate the way the child did. atexit() handlers do not run on
      // signal death, so restore the stdio state first.
      const int signo = WTERMSIG(status);
      ResetStdio();
      signal(signo, SIG_DFL);
      sigset_t set;
      sigemptyset(&set);
      sigaddset(&set, signo);
      pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
      raise(signo);
      return static_cast<ExitCode>(128 + signo);
    }
    return kClientFailure;
  }
}

#else  // !__linux__

static void Serve(const FunctionCallbackInfo<Value>& args) {
  THROW_ERR_INVALID_STATE(Environment::GetCurrent(args),
                          "zygote: this prototype only supports Linux");
}

ExitCode RunClient(const std::string& socket_path,
                   const std::vector<std::string>& args,
                   const std::optional<std::string>& eval_code,
                   bool print_eval) {
  fprintf(stderr, "%s: --connect is only supported on Linux\n",
          args[0].c_str());
  return ExitCode::kInvalidCommandLineArgument;
}

#endif  // __linux__

static void Initialize(Local<Object> target,
                       Local<Value> unused,
                       Local<Context> context,
                       void* priv) {
  SetMethod(context, target, "serve", Serve);
  SetMethod(context, target, "fillRandom", FillRandom);
}

static void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(Serve);
  registry->Register(FillRandom);
}

}  // namespace zygote
}  // namespace node

NODE_BINDING_CONTEXT_AWARE_INTERNAL(zygote, node::zygote::Initialize)
NODE_BINDING_EXTERNAL_REFERENCE(zygote,
                                node::zygote::RegisterExternalReferences)
