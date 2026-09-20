// Prototype: a fork server ("zygote") for fast process startup.
//
// A zygote is a Node.js process that has bootstrapped and run its --require
// preloads but has no entry script. serve() listens on a Unix domain socket
// or a TCP port.
//
// Unix domain socket: the zygote forks a child as soon as it accepts a
// connection. The child reads the client's request and becomes the client's
// program: it adopts the client's stdio file descriptors (passed via
// SCM_RIGHTS), cwd, umask, argv and environment, then returns to JavaScript to
// run the requested program. The zygote never reads requests itself, so
// clients are served in parallel; it reports each child's pid and wait status
// back to its client.
//
// TCP: file descriptors and peer credentials cannot cross a TCP connection.
// The zygote checks a shared token (NODE_ZYGOTE_TOKEN) without blocking, then
// forks a relay process. The relay reads the request, forks the program child
// with pipes on its fds 0-2, and exchanges stdin, stdout, stderr, signals and
// the exit status with the client as frames.
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
// Wire protocol (host byte order):
//   request:  RequestHeader, then payload_size bytes of NUL-terminated
//             strings: cwd, argv[0..argc), env[0..envc). The first sendmsg()
//             carries SCM_RIGHTS with the client's fds 0, 1 and 2. With
//             kModeScript, argv[0] is the main module; with kModeEval and
//             kModePrint, argv[0] is the code to evaluate (-e, -p). The
//             remaining argv strings are the program's arguments.
//   replies:  Reply{'P', pid} once the child is forked, then
//             Reply{'X', wait status} once it has terminated.
// Over TCP the request is preceded by AuthHeader and the token, carries no
// file descriptors, and is followed by frames (see FrameHeader).

#include "node_zygote.h"
#include "env-inl.h"
#include "node_errors.h"
#include "node_external_reference.h"
#include "node_internals.h"
#include "node_v8_platform-inl.h"
#include "util-inl.h"
#include "uv.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef __linux__
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

// TCP transport. The client first sends AuthHeader and the token, which the
// zygote checks before forking a relay process for the connection. The request
// follows, without file descriptors. After that both sides exchange frames: a
// FrameHeader followed by `size` bytes.
constexpr uint32_t kAuthMagic = 0x4e5a5954;  // "NZYT"
constexpr size_t kMinTokenSize = 16;
constexpr size_t kMaxTokenSize = 256;
constexpr uint64_t kAuthTimeoutNs = 1000000000;
// Readers stop reading once this much data is waiting to be written.
constexpr size_t kMaxBuffered = 1 << 20;
constexpr uint32_t kMaxFrameSize = 1 << 20;

// Frames from the client to the relay.
constexpr uint32_t kFrameStdin = 'I';     // data for the program's stdin
constexpr uint32_t kFrameStdinEnd = 'C';  // end of the program's stdin
constexpr uint32_t kFrameSignal = 'S';    // int32 signal number
// Frames from the relay to the client.
constexpr uint32_t kFramePid = 'P';     // int32 pid of the program
constexpr uint32_t kFrameStdout = 'O';  // data the program wrote to stdout
constexpr uint32_t kFrameStderr = 'E';  // data the program wrote to stderr
constexpr uint32_t kFrameExit = 'X';    // int32 wait status of the program

struct AuthHeader {
  uint32_t magic;
  uint32_t token_size;
};

struct FrameHeader {
  uint32_t type;
  uint32_t size;
};

struct PendingConnection {
  int fd;
  uint64_t deadline;  // uv_hrtime()
  std::string received;
};

struct Relay {
  pid_t pid;
  int pidfd;
};

static void SetNonBlocking(int fd, bool non_blocking) {
  const int flags = fcntl(fd, F_GETFL);
  CHECK_NE(flags, -1);
  CHECK_NE(fcntl(fd,
                 F_SETFL,
                 non_blocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)),
           -1);
}

static void AppendFrame(std::string* out,
                        uint32_t type,
                        const char* data,
                        size_t size) {
  const FrameHeader header{type, static_cast<uint32_t>(size)};
  out->append(reinterpret_cast<const char*>(&header), sizeof(header));
  if (size > 0) out->append(data, size);
}

static void AppendInt32Frame(std::string* out, uint32_t type, int32_t value) {
  AppendFrame(out, type, reinterpret_cast<const char*>(&value), sizeof(value));
}

// Calls `fn(type, data, size)` for each complete frame at the start of `*in`
// and removes those frames. Returns false on a frame larger than
// kMaxFrameSize.
template <typename Fn>
static bool ConsumeFrames(std::string* in, Fn&& fn) {
  size_t offset = 0;
  bool ok = true;
  while (in->size() - offset >= sizeof(FrameHeader)) {
    FrameHeader header;
    memcpy(&header, in->data() + offset, sizeof(header));
    if (header.size > kMaxFrameSize) {
      ok = false;
      break;
    }
    if (in->size() - offset - sizeof(header) < header.size) break;
    fn(header.type, in->data() + offset + sizeof(header), header.size);
    offset += sizeof(header) + header.size;
  }
  in->erase(0, offset);
  return ok;
}

// Sends `*data` on a non-blocking socket, waiting up to `timeout_ms` whenever
// the socket is full. Errors are ignored; the peer may be gone.
static void FlushSocket(int fd, std::string* data, int timeout_ms) {
  while (!data->empty()) {
    const ssize_t n =
        send(fd, data->data(), data->size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n > 0) {
      data->erase(0, n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && errno == EAGAIN) {
      pollfd pfd{fd, POLLOUT, 0};
      if (poll(&pfd, 1, timeout_ms) > 0) continue;
    }
    return;
  }
}

static bool TokensEqual(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); i++) {
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return diff == 0;
}

// `<host>:<port>` without a '/', with IPv6 hosts in brackets, is a TCP
// address; anything else is a Unix domain socket path.
static bool ParseTcpAddress(const std::string& address,
                            std::string* host,
                            std::string* port) {
  if (address.find('/') != std::string::npos) return false;
  const size_t colon = address.rfind(':');
  if (colon == std::string::npos || colon == 0 ||
      colon + 1 == address.size()) {
    return false;
  }
  std::string digits = address.substr(colon + 1);
  if (!std::all_of(digits.begin(), digits.end(), [](char c) {
        return c >= '0' && c <= '9';
      })) {
    return false;
  }
  std::string name = address.substr(0, colon);
  if (name.size() > 2 && name.front() == '[' && name.back() == ']') {
    name = name.substr(1, name.size() - 2);
  } else if (name.find(':') != std::string::npos) {
    return false;
  }
  *host = std::move(name);
  *port = std::move(digits);
  return true;
}

static bool IsValidPort(const std::string& digits) {
  if (digits.empty() || digits.size() > 5) return false;
  const auto value = strtoul(digits.c_str(), nullptr, 10);
  return value >= 1 && value <= 65535;
}

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

// Reads RequestHeader and payload. With `expect_fds` (Unix domain sockets) the
// client's fds 0-2 must arrive as SCM_RIGHTS data with the first bytes.
static bool ReadRequest(int conn, Request* req, bool expect_fds) {
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

  if (!expect_fds) req->CloseFds();
  const bool ok =
      !(msg.msg_flags & MSG_CTRUNC) &&
      (!expect_fds ||
       (req->fds[0] >= 0 && req->fds[1] >= 0 && req->fds[2] >= 0)) &&
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

static int ListenUnix(const std::string& path, std::string* error) {
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

static int ListenTcp(const std::string& host,
                     const std::string& port,
                     std::string* error) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  addrinfo* addresses = nullptr;
  const int gai = getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
  if (gai != 0) {
    *error = std::string("getaddrinfo(): ") + gai_strerror(gai);
    return -1;
  }
  int fd = -1;
  *error = "no address to listen on";
  for (addrinfo* ai = addresses; ai != nullptr; ai = ai->ai_next) {
    // Non-blocking, so that the accept loop can drain the backlog.
    fd = socket(ai->ai_family,
                ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                ai->ai_protocol);
    if (fd < 0) {
      *error = std::string("socket(): ") + strerror(errno);
      continue;
    }
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 128) == 0) {
      break;
    }
    *error = std::string("bind()/listen(): ") + strerror(errno);
    close(fd);
    fd = -1;
  }
  freeaddrinfo(addresses);
  return fd;
}

// Accept loop for a Unix domain socket. Returns only in a forked child, with
// the client's stdio installed on fds 0-2.
static Request ServeUnix(int listen_fd) {
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
          !ReadRequest(conn, &req, true)) {
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
      return req;
    }
  }
}

enum class AuthResult { kIncomplete, kAccepted, kRejected };

// Reads as much of the AuthHeader and token as is available, never past them.
static AuthResult ReadAuth(PendingConnection* conn, const std::string& token) {
  for (;;) {
    size_t wanted = sizeof(AuthHeader);
    if (conn->received.size() >= sizeof(AuthHeader)) {
      AuthHeader header;
      memcpy(&header, conn->received.data(), sizeof(header));
      if (header.magic != kAuthMagic || header.token_size != token.size()) {
        return AuthResult::kRejected;
      }
      wanted += header.token_size;
      if (conn->received.size() == wanted) {
        return TokensEqual(conn->received.substr(sizeof(AuthHeader)), token)
                   ? AuthResult::kAccepted
                   : AuthResult::kRejected;
      }
    }
    char buf[512];
    const ssize_t n =
        recv(conn->fd,
             buf,
             std::min(sizeof(buf), wanted - conn->received.size()),
             MSG_DONTWAIT);
    if (n > 0) {
      conn->received.append(buf, n);
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
      return AuthResult::kIncomplete;
    }
    return AuthResult::kRejected;
  }
}

// Copies data between the connection and the program's stdio pipes, applies
// signal frames, and sends the program's wait status once it has exited.
static void PumpRelay(
    int conn, pid_t child, int stdin_fd, int stdout_fd, int stderr_fd) {
  const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, child, 0));
  CHECK_GE(pidfd, 0);
  SetNonBlocking(conn, true);
  SetNonBlocking(stdin_fd, true);
  SetNonBlocking(stdout_fd, true);
  SetNonBlocking(stderr_fd, true);

  std::string to_client;
  AppendInt32Frame(&to_client, kFramePid, child);
  std::string from_client;
  std::string to_stdin;
  bool stdin_end = false;
  bool client_gone = false;
  std::vector<char> buffer(1 << 16);

  const auto hang_up = [&]() {
    client_gone = true;
    to_client.clear();
    to_stdin.clear();
    stdin_end = true;
    if (kill(-child, SIGHUP) != 0) kill(child, SIGHUP);
  };
  // Returns true if data was read.
  const auto read_output = [&](int* fd, uint32_t type) {
    const ssize_t n = read(*fd, buffer.data(), buffer.size());
    if (n > 0) {
      if (!client_gone) AppendFrame(&to_client, type, buffer.data(), n);
      return true;
    }
    if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
      close(*fd);
      *fd = -1;
    }
    return false;
  };

  for (;;) {
    if (stdin_fd >= 0 && stdin_end && to_stdin.empty()) {
      close(stdin_fd);
      stdin_fd = -1;
    }
    const bool room = to_client.size() < kMaxBuffered;
    int16_t conn_events = 0;
    if (!client_gone) {
      if (to_stdin.size() < kMaxBuffered) conn_events |= POLLIN;
      if (!to_client.empty()) conn_events |= POLLOUT;
    }
    pollfd fds[] = {
        {conn_events != 0 ? conn : -1, conn_events, 0},
        {stdin_fd >= 0 && !to_stdin.empty() ? stdin_fd : -1, POLLOUT, 0},
        {stdout_fd >= 0 && room ? stdout_fd : -1, POLLIN, 0},
        {stderr_fd >= 0 && room ? stderr_fd : -1, POLLIN, 0},
        {pidfd, POLLIN, 0},
    };
    if (poll(fds, arraysize(fds), -1) < 0) {
      CHECK_EQ(errno, EINTR);
      continue;
    }

    if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      const ssize_t n = recv(conn, buffer.data(), buffer.size(), MSG_DONTWAIT);
      if (n > 0) {
        from_client.append(buffer.data(), n);
        const bool ok = ConsumeFrames(
            &from_client, [&](uint32_t type, const char* data, uint32_t size) {
              if (type == kFrameStdin) {
                if (!stdin_end) to_stdin.append(data, size);
              } else if (type == kFrameStdinEnd) {
                stdin_end = true;
              } else if (type == kFrameSignal && size == sizeof(int32_t)) {
                int32_t signo;
                memcpy(&signo, data, sizeof(signo));
                if (signo > 0 && signo < NSIG && kill(-child, signo) != 0) {
                  kill(child, signo);
                }
              }
            });
        if (!ok) hang_up();
      } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
        hang_up();
      }
    }
    if (!client_gone && (fds[0].revents & POLLOUT)) {
      const ssize_t n = send(conn,
                             to_client.data(),
                             to_client.size(),
                             MSG_NOSIGNAL | MSG_DONTWAIT);
      if (n > 0) {
        to_client.erase(0, n);
      } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
        hang_up();
      }
    }
    if (fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) {
      const ssize_t n = write(stdin_fd, to_stdin.data(), to_stdin.size());
      if (n > 0) {
        to_stdin.erase(0, n);
      } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
        // The program closed its end of the pipe.
        to_stdin.clear();
        stdin_end = true;
      }
    }
    if (fds[2].revents & (POLLIN | POLLHUP | POLLERR)) {
      read_output(&stdout_fd, kFrameStdout);
    }
    if (fds[3].revents & (POLLIN | POLLHUP | POLLERR)) {
      read_output(&stderr_fd, kFrameStderr);
    }

    if (fds[4].revents & POLLIN) {
      int status = 0;
      while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
      // Forward what is already in the pipes. Output that other processes
      // holding the pipes write later is not forwarded.
      while (stdout_fd >= 0 && read_output(&stdout_fd, kFrameStdout)) {}
      while (stderr_fd >= 0 && read_output(&stderr_fd, kFrameStderr)) {}
      if (!client_gone) {
        AppendInt32Frame(&to_client, kFrameExit, status);
        FlushSocket(conn, &to_client, 5000);
      }
      return;
    }
  }
}

// Runs in a relay process forked for an authenticated TCP connection. Reads
// the request, forks the program child with pipes on its fds 0-2, and copies
// data between the pipes and the connection until the program has exited.
// Returns only in the program child; the relay itself exits.
static Request RunRelay(int conn) {
  Request req;
  SetNonBlocking(conn, false);
  const timeval timeout{1, 0};
  if (setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) !=
          0 ||
      !ReadRequest(conn, &req, false)) {
    std::string reply;
    AppendInt32Frame(
        &reply, kFrameExit, W_EXITCODE(kInvalidRequestExitCode, 0));
    FlushSocket(conn, &reply, 1000);
    _exit(0);
  }
  const int one = 1;
  setsockopt(conn, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  int stdin_pipe[2];
  int stdout_pipe[2];
  int stderr_pipe[2];
  CHECK_EQ(pipe2(stdin_pipe, O_CLOEXEC), 0);
  CHECK_EQ(pipe2(stdout_pipe, O_CLOEXEC), 0);
  CHECK_EQ(pipe2(stderr_pipe, O_CLOEXEC), 0);

  const pid_t child = fork();
  if (child < 0) {
    std::string reply;
    AppendInt32Frame(&reply, kFrameExit, W_EXITCODE(127, 0));
    FlushSocket(conn, &reply, 1000);
    _exit(0);
  }
  if (child == 0) {
    close(conn);
    // The relay keeps fds 0-2 open, so the pipe fds are all > 2.
    CHECK_EQ(dup2(stdin_pipe[0], 0), 0);
    CHECK_EQ(dup2(stdout_pipe[1], 1), 1);
    CHECK_EQ(dup2(stderr_pipe[1], 2), 2);
    for (int fd : {stdin_pipe[0],
                   stdin_pipe[1],
                   stdout_pipe[0],
                   stdout_pipe[1],
                   stderr_pipe[0],
                   stderr_pipe[1]}) {
      close(fd);
    }
    return req;
  }
  close(stdin_pipe[0]);
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);
  PumpRelay(conn, child, stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);
  _exit(0);
}

// Accept loop for a TCP socket. A connection must send the token within
// kAuthTimeoutNs before the zygote forks a relay for it. Returns only in a
// program child, with the relay's pipes installed on fds 0-2.
static Request ServeTcp(int listen_fd, const std::string& token) {
  std::vector<PendingConnection> pending;
  std::vector<Relay> relays;
  std::vector<pollfd> pollfds;
  for (;;) {
    pollfds.clear();
    pollfds.push_back({listen_fd, POLLIN, 0});
    for (const Relay& relay : relays) {
      pollfds.push_back({relay.pidfd, POLLIN, 0});
    }
    const size_t relay_count = relays.size();
    int timeout_ms = -1;
    const uint64_t now = uv_hrtime();
    for (const PendingConnection& conn : pending) {
      pollfds.push_back({conn.fd, POLLIN, 0});
      const int remaining_ms =
          conn.deadline > now
              ? static_cast<int>((conn.deadline - now) / 1000000) + 1
              : 0;
      if (timeout_ms < 0 || remaining_ms < timeout_ms) {
        timeout_ms = remaining_ms;
      }
    }
    if (poll(pollfds.data(), pollfds.size(), timeout_ms) < 0) {
      CHECK_EQ(errno, EINTR);
      continue;
    }

    for (size_t i = relay_count; i-- > 0;) {
      if (!(pollfds[1 + i].revents & POLLIN)) continue;
      int status = 0;
      while (waitpid(relays[i].pid, &status, 0) < 0 && errno == EINTR) {}
      close(relays[i].pidfd);
      relays.erase(relays.begin() + i);
    }

    const uint64_t after_poll = uv_hrtime();
    for (size_t i = pending.size(); i-- > 0;) {
      AuthResult result = AuthResult::kIncomplete;
      if (pollfds[1 + relay_count + i].revents != 0) {
        result = ReadAuth(&pending[i], token);
      }
      if (result == AuthResult::kIncomplete &&
          after_poll >= pending[i].deadline) {
        result = AuthResult::kRejected;
      }
      if (result == AuthResult::kIncomplete) continue;
      const int fd = pending[i].fd;
      pending.erase(pending.begin() + i);
      if (result == AuthResult::kRejected) {
        close(fd);
        continue;
      }

      const pid_t pid = fork();
      if (pid < 0) {
        close(fd);
        continue;
      }
      if (pid == 0) {
        close(listen_fd);
        for (const PendingConnection& other : pending) close(other.fd);
        for (const Relay& relay : relays) close(relay.pidfd);
        return RunRelay(fd);
      }
      close(fd);
      const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
      CHECK_GE(pidfd, 0);
      relays.push_back({pid, pidfd});
    }

    if (!(pollfds[0].revents & POLLIN)) continue;
    for (;;) {
      const int fd =
          accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (fd < 0) {
        if (errno == EINTR || errno == ECONNABORTED) continue;
        break;  // EAGAIN: the backlog is drained.
      }
      pending.push_back({fd, uv_hrtime() + kAuthTimeoutNs, {}});
    }
  }
}

// Runs the accept loop for a Unix domain socket path or a TCP `host:port`.
// Returns (in a forked child only) an array [pid, cwd, argv, env, mode]
// describing the program the child should become.
static void Serve(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  CHECK(env->is_main_thread());
  CHECK(env->owns_process_state());
  CHECK(args[0]->IsString());
  CHECK(args[1]->IsString());
  const std::string address = Utf8Value(isolate, args[0]).ToString();
  const std::string token = Utf8Value(isolate, args[1]).ToString();

  std::string host;
  std::string port;
  const bool tcp = ParseTcpAddress(address, &host, &port);
  if (tcp && !IsValidPort(port)) {
    return THROW_ERR_INVALID_STATE(env, "zygote: invalid port in %s", address);
  }
  if (tcp && (token.size() < kMinTokenSize || token.size() > kMaxTokenSize)) {
    return THROW_ERR_INVALID_STATE(
        env,
        "zygote: a TCP address requires NODE_ZYGOTE_TOKEN with 16 to 256 "
        "characters");
  }

  if (env->event_loop()->active_reqs.count != 0) {
    return THROW_ERR_INVALID_STATE(
        env, "zygote: cannot fork while the event loop has active requests");
  }

  std::string error;
  const int listen_fd =
      tcp ? ListenTcp(host, port, &error) : ListenUnix(address, &error);
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
    if (!tcp) unlink(address.c_str());
    return THROW_ERR_INVALID_STATE(
        env, "zygote: cannot fork while these threads are alive: %s",
        unsafe_threads);
  }

  MakeMappingsInheritable();

  // Only children that become programs get past this point.
  Request req = tcp ? ServeTcp(listen_fd, token) : ServeUnix(listen_fd);

  // New session: no controlling terminal and a process group that can be
  // signaled as a whole.
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
  args.GetReturnValue().Set(Array::New(isolate, result, arraysize(result)));
}

// Client side: `node --connect=<address> ...`.

// Exit code for failures of the client itself, as opposed to the child.
constexpr ExitCode kClientFailure = static_cast<ExitCode>(125);

constexpr int kForwardedSignals[] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH, SIGUSR1, SIGUSR2};

// Unix domain sockets: the client signals the child directly.
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

// TCP: signals are handed to the client's poll loop, which sends them as
// frames.
static int client_signal_pipe = -1;

static void WriteSignalToPipe(int signo) {
  const int saved_errno = errno;
  const unsigned char byte = static_cast<unsigned char>(signo);
  USE(write(client_signal_pipe, &byte, 1));
  errno = saved_errno;
}

static void InstallSignalHandlers(void (*handler)(int)) {
  struct sigaction sa {};
  sa.sa_handler = handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  for (int signo : kForwardedSignals) {
    CHECK_EQ(sigaction(signo, &sa, nullptr), 0);
  }
  // PlatformInit() leaves SIGUSR1 blocked.
  sigset_t usr1;
  sigemptyset(&usr1);
  sigaddset(&usr1, SIGUSR1);
  CHECK_EQ(pthread_sigmask(SIG_UNBLOCK, &usr1, nullptr), 0);
}

// Returns the child's exit code, or terminates the process with the signal
// that terminated the child.
static ExitCode ExitCodeFromWaitStatus(int status) {
  if (WIFEXITED(status)) {
    return static_cast<ExitCode>(WEXITSTATUS(status));
  }
  if (WIFSIGNALED(status)) {
    // atexit() handlers do not run on signal death, so restore the stdio
    // state first.
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

// Serializes RequestHeader and payload. Prints an error and returns false on
// failure.
static bool BuildRequest(const char* self,
                         uint32_t mode,
                         const std::vector<std::string>& argv,
                         std::string* message) {
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == nullptr) {
    fprintf(stderr, "%s: getcwd(): %s\n", self, strerror(errno));
    return false;
  }

  // Payload: cwd, argv, environment; each string including its terminating
  // NUL.
  std::string payload(cwd, strlen(cwd) + 1);
  for (const std::string& arg : argv) {
    payload.append(arg.c_str(), arg.size() + 1);
  }
  uint32_t envc = 0;
  for (char** entry = ::environ; *entry != nullptr; entry++, envc++) {
    payload.append(*entry, strlen(*entry) + 1);
  }
  if (payload.size() > kMaxPayloadSize) {
    fprintf(stderr, "%s: --connect: request too large\n", self);
    return false;
  }

  const mode_t mask = umask(0);
  umask(mask);
  const RequestHeader header{kRequestMagic,
                             mode,
                             static_cast<uint32_t>(argv.size()),
                             envc,
                             static_cast<uint32_t>(mask),
                             static_cast<uint32_t>(payload.size())};
  message->assign(reinterpret_cast<const char*>(&header), sizeof(header));
  *message += payload;
  return true;
}

// Writes all of `data` to `fd`, waiting whenever it is full. Returns false if
// the descriptor stopped accepting data.
static bool WriteAll(int fd, const char* data, size_t size) {
  while (size > 0) {
    const ssize_t n = write(fd, data, size);
    if (n > 0) {
      data += n;
      size -= n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && errno == EAGAIN) {
      pollfd pfd{fd, POLLOUT, 0};
      poll(&pfd, 1, -1);
      continue;
    }
    return false;
  }
  return true;
}

static ExitCode RunUnixClient(const char* self,
                              const std::string& socket_path,
                              uint32_t mode,
                              const std::vector<std::string>& request_argv) {
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

  std::string message;
  if (!BuildRequest(self, mode, request_argv, &message)) {
    return kClientFailure;
  }

  // From here on, signals are forwarded to the child, or recorded until its
  // pid is known.
  InstallSignalHandlers(ForwardSignalToChild);

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
    return ExitCodeFromWaitStatus(reply.value);
  }
}

static ExitCode RunTcpClient(const char* self,
                             const std::string& address,
                             const std::string& host,
                             const std::string& port,
                             uint32_t mode,
                             const std::vector<std::string>& request_argv) {
  if (!IsValidPort(port)) {
    fprintf(stderr, "%s: --connect: invalid port in %s\n", self,
            address.c_str());
    return ExitCode::kInvalidCommandLineArgument;
  }
  const char* token = getenv("NODE_ZYGOTE_TOKEN");
  const size_t token_size = token != nullptr ? strlen(token) : 0;
  if (token_size < kMinTokenSize || token_size > kMaxTokenSize) {
    fprintf(stderr,
            "%s: --connect=%s requires NODE_ZYGOTE_TOKEN with 16 to 256 "
            "characters\n",
            self,
            address.c_str());
    return ExitCode::kInvalidCommandLineArgument;
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  addrinfo* addresses = nullptr;
  const int gai = getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
  if (gai != 0) {
    fprintf(stderr, "%s: cannot resolve %s: %s\n", self, host.c_str(),
            gai_strerror(gai));
    return kClientFailure;
  }
  int sock = -1;
  int connect_errno = 0;
  for (addrinfo* ai = addresses; ai != nullptr && sock < 0; ai = ai->ai_next) {
    sock = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
                  ai->ai_protocol);
    if (sock < 0) {
      connect_errno = errno;
    } else if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0) {
      connect_errno = errno;
      close(sock);
      sock = -1;
    }
  }
  freeaddrinfo(addresses);
  if (sock < 0) {
    fprintf(stderr, "%s: cannot connect to %s: %s\n", self, address.c_str(),
            strerror(connect_errno));
    return kClientFailure;
  }
  auto close_sock = OnScopeLeave([sock]() { close(sock); });
  const int one = 1;
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  std::string request;
  if (!BuildRequest(self, mode, request_argv, &request)) {
    return kClientFailure;
  }
  const AuthHeader auth{kAuthMagic, static_cast<uint32_t>(token_size)};
  std::string to_server(reinterpret_cast<const char*>(&auth), sizeof(auth));
  to_server.append(token, token_size);
  to_server += request;

  int signal_pipe[2];
  CHECK_EQ(pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK), 0);
  client_signal_pipe = signal_pipe[1];
  InstallSignalHandlers(WriteSignalToPipe);
  SetNonBlocking(sock, true);

  const auto lost_connection = [&]() {
    fprintf(stderr, "%s: lost connection to the zygote at %s\n", self,
            address.c_str());
    return kClientFailure;
  };

  std::string from_server;
  std::vector<char> buffer(1 << 16);
  bool stdin_open = true;
  bool stdout_open = true;
  bool stderr_open = true;
  std::optional<int32_t> exit_status;
  for (;;) {
    pollfd fds[] = {
        {sock, static_cast<int16_t>(POLLIN | (to_server.empty() ? 0 : POLLOUT)),
         0},
        {stdin_open && to_server.size() < kMaxBuffered ? 0 : -1, POLLIN, 0},
        {signal_pipe[0], POLLIN, 0},
    };
    if (poll(fds, arraysize(fds), -1) < 0) {
      if (errno == EINTR) continue;
      return lost_connection();
    }

    if (fds[2].revents & POLLIN) {
      unsigned char signals[64];
      const ssize_t n = read(signal_pipe[0], signals, sizeof(signals));
      for (ssize_t i = 0; i < n; i++) {
        AppendInt32Frame(&to_server, kFrameSignal, signals[i]);
      }
    }
    if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      const ssize_t n = read(0, buffer.data(), buffer.size());
      if (n > 0) {
        AppendFrame(&to_server, kFrameStdin, buffer.data(), n);
      } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
        AppendFrame(&to_server, kFrameStdinEnd, nullptr, 0);
        stdin_open = false;
      }
    }
    if (fds[0].revents & POLLOUT) {
      const ssize_t n =
          send(sock, to_server.data(), to_server.size(), MSG_NOSIGNAL);
      if (n > 0) {
        to_server.erase(0, n);
      } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
        return lost_connection();
      }
    }
    if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      const ssize_t n = recv(sock, buffer.data(), buffer.size(), 0);
      if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
        return lost_connection();
      }
      if (n > 0) {
        from_server.append(buffer.data(), n);
        const bool ok = ConsumeFrames(
            &from_server, [&](uint32_t type, const char* data, uint32_t size) {
              if (type == kFrameStdout) {
                if (stdout_open) stdout_open = WriteAll(1, data, size);
              } else if (type == kFrameStderr) {
                if (stderr_open) stderr_open = WriteAll(2, data, size);
              } else if (type == kFrameExit && size == sizeof(int32_t)) {
                int32_t status;
                memcpy(&status, data, sizeof(status));
                exit_status = status;
              }
            });
        if (exit_status.has_value()) {
          return ExitCodeFromWaitStatus(*exit_status);
        }
        if (!ok) return lost_connection();
      }
    }
  }
}

ExitCode RunClient(const std::string& address,
                   const std::vector<std::string>& args,
                   const std::optional<std::string>& eval_code,
                   bool print_eval) {
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

  std::string host;
  std::string port;
  if (ParseTcpAddress(address, &host, &port)) {
    return RunTcpClient(self, address, host, port, mode, request_argv);
  }
  return RunUnixClient(self, address, mode, request_argv);
}

#else  // !__linux__

static void Serve(const FunctionCallbackInfo<Value>& args) {
  THROW_ERR_INVALID_STATE(Environment::GetCurrent(args),
                          "zygote: this prototype only supports Linux");
}

ExitCode RunClient(const std::string& address,
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
