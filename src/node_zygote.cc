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
// Connections use TLS 1.3 with an external pre-shared key derived from a
// shared token (NODE_ZYGOTE_TOKEN), so that neither side needs a certificate:
// the handshake proves to each side that the other knows the key, and its
// (EC)DHE exchange gives forward secrecy. The zygote completes the handshake
// without blocking, then forks a relay process. The relay reads the request,
// forks the program child with pipes on its fds 0-2, and exchanges stdin,
// stdout, stderr, signals and the exit status with the client as frames.
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
// Wire protocol (all integers are big-endian, i.e. in network byte order, so
// that a client and a zygote on different machines agree):
//   request:  RequestHeader, then payload_size bytes of NUL-terminated
//             strings: cwd, argv[0..argc), env[0..envc). The first sendmsg()
//             carries SCM_RIGHTS with the client's fds 0, 1 and 2. With
//             kModeScript, argv[0] is the main module; with kModeEval and
//             kModePrint, argv[0] is the code to evaluate (-e, -p). The
//             remaining argv strings are the program's arguments.
//   replies:  Reply{'P', pid} once the child is forked, then
//             Reply{'X', wait status} once it has terminated.
// Over TCP everything is sent inside the TLS connection: the request, without
// file descriptors, and then frames (see FrameHeader) instead of replies.

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
#include <string_view>
#include <vector>

#ifdef __linux__
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif  // __linux__

#if HAVE_OPENSSL
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#endif  // HAVE_OPENSSL

// The TCP transport needs OpenSSL's TLS 1.3 external PSK API, which BoringSSL
// does not have.
#if HAVE_OPENSSL && !defined(OPENSSL_IS_BORINGSSL)
#define NODE_ZYGOTE_HAVE_TLS 1
#else
#define NODE_ZYGOTE_HAVE_TLS 0
#endif

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

// The token only authenticates a TCP client to the zygote; the program has no
// use for it. Clients do not forward it, and the zygote drops it from requests
// sent by clients that do.
constexpr std::string_view kTokenEnvPrefix = "NODE_ZYGOTE_TOKEN=";

static bool IsTokenEnvEntry(std::string_view entry) {
  return entry.starts_with(kTokenEnvPrefix);
}

// Returns the value of NODE_ZYGOTE_TOKEN and removes the variable, wiping the
// value where it was stored. The zygote derives the TLS key from the token
// once; nothing else in it or in the processes it forks needs the token.
static std::string TakeTokenFromEnvironment() {
  char* value = getenv("NODE_ZYGOTE_TOKEN");
  if (value == nullptr) return {};
  std::string token(value);
  // getenv() points into the variable's storage, such as the initial
  // environment block that /proc/<pid>/environ shows. unsetenv() would only
  // drop the pointer to it.
  explicit_bzero(value, strlen(value));
  unsetenv("NODE_ZYGOTE_TOKEN");
  return token;
}

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

// TCP transport. The client and the zygote complete a TLS handshake keyed by
// the shared token before the zygote forks a relay process for the
// connection. The request follows, without file descriptors. After that both
// sides exchange frames: a FrameHeader followed by `size` bytes.
// The TLS key is derived from the token, and a recorded handshake allows an
// offline guessing attack on it, so the token must be long and random. 32
// characters is what 24 random bytes (192 bits) take in base64. The length
// cannot prove that a token is random, but it rules out short passwords.
constexpr size_t kMinTokenSize = 32;
constexpr size_t kMaxTokenSize = 256;

#if NODE_ZYGOTE_HAVE_TLS
// How long a TCP peer has to complete the TLS handshake with the zygote, and
// then to send its request to the relay. Generous, because the connection may
// cross a slow network.
constexpr uint64_t kHandshakeTimeoutNs = 10000000000;
constexpr uint64_t kRequestTimeoutNs = 10000000000;
// The client gives the zygote a little longer than the zygote gives it.
constexpr uint64_t kClientHandshakeTimeoutNs = 12000000000;
// At most this many TLS handshakes are in progress in the zygote at a time.
// When another connection arrives, the oldest one is dropped: a peer that
// opens connections slowly and never completes them cannot keep others out.
constexpr size_t kMaxPendingHandshakes = 64;
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

struct FrameHeader {
  uint32_t type;
  uint32_t size;
};

struct Relay {
  pid_t pid;
  int pidfd;
};

// How long the accept loops stop accepting after running out of a resource
// (usually file descriptors). The listening socket stays readable meanwhile,
// so polling it would spin.
constexpr uint64_t kAcceptBackoffNs = 100000000;

enum class AcceptResult { kAccepted, kDrained, kBackOff };

// Accepts one connection on the non-blocking `listen_fd` into `*conn`.
static AcceptResult AcceptConnection(int listen_fd, int flags, int* conn) {
  for (;;) {
    *conn = accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC | flags);
    if (*conn >= 0) return AcceptResult::kAccepted;
    switch (errno) {
      case EAGAIN:
        return AcceptResult::kDrained;
      case EINTR:
      case ECONNABORTED:
      // Linux reports pending network errors of the new connection from
      // accept(); see accept(2). The next connection may be fine.
      case ENETDOWN:
      case EPROTO:
      case ENOPROTOOPT:
      case EHOSTDOWN:
      case ENONET:
      case EHOSTUNREACH:
      case EOPNOTSUPP:
      case ENETUNREACH:
      case EPERM:  // Rejected by a firewall rule.
        continue;
      default:  // EMFILE, ENFILE, ENOBUFS, ENOMEM.
        return AcceptResult::kBackOff;
    }
  }
}

// Returns the poll() timeout in ms until `deadline`, at least 0.
static int MsUntil(uint64_t deadline, uint64_t now) {
  return deadline > now ? static_cast<int>((deadline - now) / 1000000) + 1 : 0;
}

// Combines poll() timeouts, where -1 means none.
static int EarlierTimeout(int a, int b) {
  if (a < 0) return b;
  if (b < 0) return a;
  return a < b ? a : b;
}

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
  const FrameHeader header{htonl(type), htonl(static_cast<uint32_t>(size))};
  out->append(reinterpret_cast<const char*>(&header), sizeof(header));
  if (size > 0) out->append(data, size);
}

static void AppendInt32Frame(std::string* out, uint32_t type, int32_t value) {
  const uint32_t wire = htonl(static_cast<uint32_t>(value));
  AppendFrame(out, type, reinterpret_cast<const char*>(&wire), sizeof(wire));
}

// The value of a frame written by AppendInt32Frame().
static int32_t ReadInt32Frame(const char* data) {
  uint32_t wire;
  memcpy(&wire, data, sizeof(wire));
  return static_cast<int32_t>(ntohl(wire));
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
    header.type = ntohl(header.type);
    header.size = ntohl(header.size);
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

// Waits until `fd` reports one of `events`. Returns false once `deadline`
// (uv_hrtime()) has passed, or on error.
static bool WaitFor(int fd, int16_t events, uint64_t deadline) {
  for (;;) {
    const uint64_t now = uv_hrtime();
    if (now >= deadline) return false;
    pollfd pfd{fd, events, 0};
    const int r =
        poll(&pfd, 1, static_cast<int>((deadline - now) / 1000000) + 1);
    if (r > 0) return true;
    if (r < 0 && errno != EINTR) return false;
  }
}

// TLS 1.3 with an external pre-shared key (RFC 8446, section 2.2). OpenSSL
// clients only offer the psk_dhe_ke mode, so every handshake still performs
// an (EC)DHE exchange. Neither side has a certificate. A handshake with a
// different key fails when the server checks the client's PSK binder.
//
// The key is derived from the token, which therefore must be random: a
// recorded handshake allows an offline guessing attack on the token.
constexpr char kPskIdentity[] = "node-zygote-v1";
constexpr char kPskLabel[] = "node zygote tls psk v1";
// TLS_AES_128_GCM_SHA256, whose hash the PSK is used with.
constexpr unsigned char kPskCipherId[] = {0x13, 0x01};

// SHA-256(kPskLabel, NUL, token). Set by SetTlsKey().
static unsigned char tls_psk[32];

static bool SetTlsKey(const std::string& token) {
  std::string input(kPskLabel, sizeof(kPskLabel));  // Including the NUL.
  input += token;
  unsigned int size = 0;
  const int r = EVP_Digest(
      input.data(), input.size(), tls_psk, &size, EVP_sha256(), nullptr);
  OPENSSL_cleanse(input.data(), input.size());
  return r == 1 && size == sizeof(tls_psk);
}

static void ForgetTlsKey() {
  OPENSSL_cleanse(tls_psk, sizeof(tls_psk));
}

// Drains OpenSSL's error queue into a message.
static std::string TlsError() {
  std::string result;
  while (const unsigned long err = ERR_get_error()) {  // NOLINT(runtime/int)
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    if (!result.empty()) result += "; ";
    result += buf;
  }
  return result.empty() ? "unknown error" : result;
}

static SSL_SESSION* NewPskSession(SSL* ssl) {
  const SSL_CIPHER* cipher = SSL_CIPHER_find(ssl, kPskCipherId);
  if (cipher == nullptr) return nullptr;
  SSL_SESSION* session = SSL_SESSION_new();
  if (session == nullptr ||
      SSL_SESSION_set1_master_key(session, tls_psk, sizeof(tls_psk)) != 1 ||
      SSL_SESSION_set_cipher(session, cipher) != 1 ||
      SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION) != 1) {
    SSL_SESSION_free(session);
    return nullptr;
  }
  return session;
}

// Server: the PSK for the identity the client offered. Without one the
// handshake fails, as the zygote has no certificate to fall back to.
static int FindPskSession(SSL* ssl,
                          const unsigned char* identity,
                          size_t identity_len,
                          SSL_SESSION** session) {
  *session = nullptr;
  if (identity_len != sizeof(kPskIdentity) - 1 ||
      memcmp(identity, kPskIdentity, identity_len) != 0) {
    return 1;
  }
  *session = NewPskSession(ssl);
  return *session != nullptr;
}

// Client: the PSK to offer.
static int UsePskSession(SSL* ssl,
                         const EVP_MD* md,
                         const unsigned char** identity,
                         size_t* identity_len,
                         SSL_SESSION** session) {
  *session = nullptr;
  // After a HelloRetryRequest, the PSK must use the digest of the cipher
  // suite the server picked. Only TLS_AES_128_GCM_SHA256 is enabled.
  if (md != nullptr && EVP_MD_type(md) != NID_sha256) return 1;
  *session = NewPskSession(ssl);
  if (*session == nullptr) return 0;
  *identity = reinterpret_cast<const unsigned char*>(kPskIdentity);
  *identity_len = sizeof(kPskIdentity) - 1;
  return 1;
}

using SslCtxPointer = DeleteFnPtr<SSL_CTX, SSL_CTX_free>;
using SslPointer = DeleteFnPtr<SSL, SSL_free>;

static SslCtxPointer NewTlsContext(bool server) {
  SslCtxPointer ctx(
      SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()));
  if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_ciphersuites(ctx.get(), "TLS_AES_128_GCM_SHA256") != 1) {
    return nullptr;
  }
  // Write() may be retried with what is left of a buffer whose start has
  // been consumed in the meantime.
  SSL_CTX_set_mode(
      ctx.get(),
      SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  // TlsConnection::HasBufferedData() relies on this.
  SSL_CTX_set_read_ahead(ctx.get(), 0);
  // Always combine the PSK with an (EC)DHE exchange, for forward secrecy,
  // even if the OpenSSL configuration allows psk_ke.
  uint64_t no_dhe = SSL_OP_ALLOW_NO_DHE_KEX;
#ifdef SSL_OP_PREFER_NO_DHE_KEX
  no_dhe |= SSL_OP_PREFER_NO_DHE_KEX;
#endif
  SSL_CTX_clear_options(ctx.get(), no_dhe);
  // Every connection uses the same external PSK; there is nothing to resume,
  // and no early data.
  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_max_early_data(ctx.get(), 0);
  if (server) {
    SSL_CTX_set_psk_find_session_callback(ctx.get(), FindPskSession);
    SSL_CTX_set_num_tickets(ctx.get(), 0);
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);
  } else {
    SSL_CTX_set_psk_use_session_callback(ctx.get(), UsePskSession);
    // The zygote has no certificate. With an empty trust store, a server
    // that presents one instead of knowing the PSK fails verification.
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  }
  return ctx;
}

// A TLS connection on a non-blocking socket.
class TlsConnection {
 public:
  // Read() and Write() return the number of bytes transferred, kWouldBlock or
  // kClosed (closed by the peer, or failed).
  static constexpr ssize_t kWouldBlock = 0;
  static constexpr ssize_t kClosed = -1;

  TlsConnection(SSL* ssl, int fd) : ssl_(ssl), fd_(fd) {}

  int fd() const { return fd_; }

  ssize_t Read(char* buf, size_t size) {
    ERR_clear_error();
    const int n = SSL_read(ssl_, buf, ClampSize(size));
    if (n <= 0) return Blocked(n, &read_events_);
    read_events_ = POLLIN;
    return n;
  }

  ssize_t Write(const char* data, size_t size) {
    ERR_clear_error();
    const int n = SSL_write(ssl_, data, ClampSize(size));
    if (n <= 0) return Blocked(n, &write_events_);
    write_events_ = POLLOUT;
    return n;
  }

  // Writes as much of `*data` as the socket takes, and removes it from
  // `*data`. Each SSL_write() sends at most a few records. Returns false if
  // the connection is closed.
  bool WriteSome(std::string* data) {
    while (!data->empty()) {
      const ssize_t n = Write(data->data(), data->size());
      if (n == kClosed) return false;
      if (n == kWouldBlock) break;
      data->erase(0, n);
    }
    return true;
  }

  // The poll() events on fd() that let the last Read() or Write() that
  // returned kWouldBlock make progress. A TLS read can need to write, and
  // vice versa.
  int16_t read_events() const { return read_events_; }
  int16_t write_events() const { return write_events_; }

  // Read() can return data that OpenSSL has already decrypted, even though
  // fd() is not readable: a reader that stopped early (or read exactly what
  // it needed) left the rest of a record behind. Unlike SSL_has_pending(),
  // this does not count a record that has only partly arrived; for that one,
  // fd() becomes readable once the rest arrives. That holds because read-ahead
  // is off, so OpenSSL never reads past the current record.
  bool HasBufferedData() const { return SSL_pending(ssl_) > 0; }

  // Sends close_notify without waiting for the peer's. Best effort.
  void Shutdown() {
    ERR_clear_error();
    SSL_shutdown(ssl_);
    ERR_clear_error();
  }

 private:
  static int ClampSize(size_t size) {
    return static_cast<int>(std::min<size_t>(size, 1 << 20));
  }

  ssize_t Blocked(int result, int16_t* events) {
    switch (SSL_get_error(ssl_, result)) {
      case SSL_ERROR_WANT_READ:
        *events = POLLIN;
        return kWouldBlock;
      case SSL_ERROR_WANT_WRITE:
        *events = POLLOUT;
        return kWouldBlock;
      default:
        ERR_clear_error();
        return kClosed;
    }
  }

  SSL* ssl_;
  int fd_;
  int16_t read_events_ = POLLIN;
  int16_t write_events_ = POLLOUT;
};

static bool TlsReadFully(TlsConnection* conn,
                         char* buf,
                         size_t size,
                         uint64_t deadline) {
  while (size > 0) {
    const ssize_t n = conn->Read(buf, size);
    if (n == TlsConnection::kClosed) return false;
    if (n > 0) {
      buf += n;
      size -= n;
    } else if (!WaitFor(conn->fd(), conn->read_events(), deadline)) {
      return false;
    }
  }
  return true;
}

// Sends `*data` until `deadline`. Errors are ignored; the peer may be gone.
static void TlsFlush(TlsConnection* conn,
                     std::string* data,
                     uint64_t deadline) {
  while (conn->WriteSome(data) && !data->empty() &&
         WaitFor(conn->fd(), conn->write_events(), deadline)) {
  }
}

#endif  // NODE_ZYGOTE_HAVE_TLS

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
  const Reply reply{htonl(type),
                    static_cast<int32_t>(htonl(static_cast<uint32_t>(value)))};
  // The client may already be gone; there is nobody to report errors to.
  USE(send(fd, &reply, sizeof(reply), MSG_NOSIGNAL));
}

// Converts `*header`, as received, to host byte order and checks it.
static bool DecodeRequestHeader(RequestHeader* header) {
  header->magic = ntohl(header->magic);
  header->mode = ntohl(header->mode);
  header->argc = ntohl(header->argc);
  header->envc = ntohl(header->envc);
  header->umask = ntohl(header->umask);
  header->payload_size = ntohl(header->payload_size);
  return header->magic == kRequestMagic && header->mode <= kModePrint &&
         header->argc > 0 && header->payload_size <= kMaxPayloadSize;
}

// Fills in `req` from a valid `header` and its `payload`.
static bool ParseRequest(const RequestHeader& header,
                         const std::string& payload,
                         Request* req) {
  if (!payload.empty() && payload.back() != '\0') return false;
  std::vector<std::string> strings;
  for (size_t start = 0; start < payload.size();) {
    size_t end = payload.find('\0', start);
    strings.emplace_back(payload, start, end - start);
    start = end + 1;
  }
  if (strings.size() != 1 + static_cast<size_t>(header.argc) + header.envc) {
    return false;
  }

  req->mode = header.mode;
  req->umask = static_cast<mode_t>(header.umask & 0777);
  req->cwd = std::move(strings[0]);
  req->argv.assign(std::make_move_iterator(strings.begin() + 1),
                   std::make_move_iterator(strings.begin() + 1 + header.argc));
  req->env.assign(std::make_move_iterator(strings.begin() + 1 + header.argc),
                  std::make_move_iterator(strings.end()));
  std::erase_if(req->env, IsTokenEnvEntry);
  return true;
}

// Reads a request from a Unix domain socket. The client's fds 0-2 must arrive
// as SCM_RIGHTS data with the first bytes.
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

  const bool header_ok =
      !(msg.msg_flags & MSG_CTRUNC) && req->fds[0] >= 0 && req->fds[1] >= 0 &&
      req->fds[2] >= 0 &&
      (static_cast<size_t>(n) == sizeof(header) ||
       ReadFully(
           conn, reinterpret_cast<char*>(&header) + n, sizeof(header) - n)) &&
      DecodeRequestHeader(&header);
  if (!header_ok) {
    req->CloseFds();
    return false;
  }
  std::string payload(header.payload_size, '\0');
  if (!ReadFully(conn, payload.data(), payload.size()) ||
      !ParseRequest(header, payload, req)) {
    req->CloseFds();
    return false;
  }
  return true;
}

#if NODE_ZYGOTE_HAVE_TLS
// Reads a request from a TLS connection before `deadline`.
static bool ReadRequest(TlsConnection* conn, uint64_t deadline, Request* req) {
  RequestHeader header;
  if (!TlsReadFully(
          conn, reinterpret_cast<char*>(&header), sizeof(header), deadline) ||
      !DecodeRequestHeader(&header)) {
    return false;
  }
  std::string payload(header.payload_size, '\0');
  return TlsReadFully(conn, payload.data(), payload.size(), deadline) &&
         ParseRequest(header, payload, req);
}
#endif  // NODE_ZYGOTE_HAVE_TLS

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

// Makes `addr` free for bind(): removes it if it is a socket that nobody
// listens on any more, such as the one left behind by a zygote that was
// killed. Refuses to touch anything else, including symbolic links and sockets
// that are still in use. Returns false and sets `*error` if `addr` cannot be
// used.
static bool RemoveStaleSocket(const sockaddr_un& addr, std::string* error) {
  const char* path = addr.sun_path;
  struct stat st;
  if (lstat(path, &st) != 0) {
    if (errno == ENOENT) return true;
    *error = std::string("lstat(") + path + "): " + strerror(errno);
    return false;
  }
  if (!S_ISSOCK(st.st_mode)) {
    *error = std::string(path) + " exists and is not a socket";
    return false;
  }

  // A socket is stale if connecting to it is refused. Non-blocking, so that a
  // live server with a full backlog reports EAGAIN instead of blocking us.
  // A live zygote forks a child for the probe, which exits as soon as it
  // reads EOF instead of a request.
  const int probe =
      socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (probe < 0) {
    *error = std::string("socket(): ") + strerror(errno);
    return false;
  }
  int r;
  do {
    r = connect(probe, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
  } while (r != 0 && errno == EINTR);
  const int connect_errno = r == 0 ? 0 : errno;
  close(probe);
  if (connect_errno != ECONNREFUSED) {
    *error =
        connect_errno == 0 || connect_errno == EAGAIN
            ? std::string("another process is listening on ") + path
            : std::string("connect(") + path + "): " + strerror(connect_errno);
    return false;
  }
  // Something could replace the socket between lstat() and unlink(). That
  // needs write access to the directory, and in a sticky one such as /tmp it
  // needs to be the socket's owner, i.e. the user running this zygote.
  if (unlink(path) != 0 && errno != ENOENT) {
    *error = std::string("unlink(") + path + "): " + strerror(errno);
    return false;
  }
  return true;
}

static int ListenUnix(const std::string& path, std::string* error) {
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    *error = "socket path too long";
    return -1;
  }
  memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (!RemoveStaleSocket(addr, error)) return -1;
  // Non-blocking, so that the accept loop can drain the backlog.
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    *error = std::string("socket(): ") + strerror(errno);
    return -1;
  }
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

// Called in a program right after fork(). The program gets SIGHUP, as from a
// terminal hangup, once `parent`, the zygote or the relay that forked it,
// exits: nobody can report the program's exit to its client any more.
static void HangUpWhenParentExits(pid_t parent) {
  prctl(PR_SET_PDEATHSIG, SIGHUP);
  if (getppid() != parent) raise(SIGHUP);  // Already gone.
}

// Returns a pidfd for the forked child `pid`. If the kernel cannot provide one
// (out of file descriptors), kills and reaps the child and returns -1. Serve()
// checks that pidfd_open() is supported at all.
static int PidfdForChild(pid_t pid) {
  const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
  if (pidfd >= 0) return pidfd;
  kill(pid, SIGKILL);
  while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
  }
  return -1;
}

// Accept loop for a Unix domain socket. Returns only in a forked child, with
// the client's stdio installed on fds 0-2.
static Request ServeUnix(int listen_fd) {
  std::vector<Child> children;
  std::vector<pollfd> pollfds;
  uint64_t accept_after = 0;  // See kAcceptBackoffNs.
  for (;;) {
    const uint64_t now = uv_hrtime();
    const bool accepting = now >= accept_after;
    pollfds.clear();
    pollfds.push_back({accepting ? listen_fd : -1, POLLIN, 0});
    for (const Child& child : children) {
      pollfds.push_back({child.pidfd, POLLIN, 0});
      // Hangup only: the child reads its request from this socket, so the
      // zygote must not consume data from it.
      pollfds.push_back(
          {child.client_gone ? -1 : child.conn_fd, POLLRDHUP, 0});
    }
    if (poll(pollfds.data(),
             pollfds.size(),
             accepting ? -1 : MsUntil(accept_after, now)) < 0) {
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
      int conn;
      const AcceptResult accepted = AcceptConnection(listen_fd, 0, &conn);
      if (accepted == AcceptResult::kBackOff) {
        accept_after = uv_hrtime() + kAcceptBackoffNs;
      }
      if (accepted != AcceptResult::kAccepted) break;
      ucred cred{};
      socklen_t cred_len = sizeof(cred);
      if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0 ||
          cred.uid != geteuid()) {
        close(conn);
        continue;
      }

      const pid_t zygote = getpid();
      const pid_t pid = fork();
      if (pid < 0) {
        SendReply(conn, kReplyExit, W_EXITCODE(127, 0));
        close(conn);
        continue;
      }

      if (pid > 0) {
        const int pidfd = PidfdForChild(pid);
        if (pidfd < 0) {
          SendReply(conn, kReplyExit, W_EXITCODE(127, 0));
          close(conn);
          continue;
        }
        SendReply(conn, kReplyPid, pid);
        children.push_back({pid, conn, pidfd, false});
        continue;
      }

      // Child.
      HangUpWhenParentExits(zygote);
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
      return req;
    }
  }
}

#if NODE_ZYGOTE_HAVE_TLS

// Copies data between the connection and the program's stdio pipes, applies
// signal frames, and sends the program's wait status once it has exited.
static void PumpRelay(TlsConnection* conn,
                      pid_t child,
                      int pidfd,
                      int stdin_fd,
                      int stdout_fd,
                      int stderr_fd) {
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
  const auto on_frame = [&](uint32_t type, const char* data, uint32_t size) {
    if (type == kFrameStdin) {
      if (!stdin_end) to_stdin.append(data, size);
    } else if (type == kFrameStdinEnd) {
      stdin_end = true;
    } else if (type == kFrameSignal && size == sizeof(int32_t)) {
      const int32_t signo = ReadInt32Frame(data);
      if (signo > 0 && signo < NSIG && kill(-child, signo) != 0) {
        kill(child, signo);
      }
    }
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
    const bool want_read = !client_gone && to_stdin.size() < kMaxBuffered;
    const bool want_write = !client_gone && !to_client.empty();
    const int16_t conn_events = (want_read ? conn->read_events() : 0) |
                                (want_write ? conn->write_events() : 0);
    const bool buffered = want_read && conn->HasBufferedData();
    pollfd fds[] = {
        {conn_events != 0 ? conn->fd() : -1, conn_events, 0},
        {stdin_fd >= 0 && !to_stdin.empty() ? stdin_fd : -1, POLLOUT, 0},
        {stdout_fd >= 0 && room ? stdout_fd : -1, POLLIN, 0},
        {stderr_fd >= 0 && room ? stderr_fd : -1, POLLIN, 0},
        {pidfd, POLLIN, 0},
    };
    if (poll(fds, arraysize(fds), buffered ? 0 : -1) < 0) {
      CHECK_EQ(errno, EINTR);
      continue;
    }

    const bool conn_ready = buffered || fds[0].revents != 0;
    if (want_read && conn_ready) {
      while (!client_gone && to_stdin.size() < kMaxBuffered) {
        const ssize_t n = conn->Read(buffer.data(), buffer.size());
        if (n == TlsConnection::kWouldBlock) break;
        if (n == TlsConnection::kClosed) {
          hang_up();
          break;
        }
        from_client.append(buffer.data(), n);
        if (!ConsumeFrames(&from_client, on_frame)) hang_up();
      }
    }
    if (want_write && !client_gone && conn_ready &&
        !conn->WriteSome(&to_client)) {
      hang_up();
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
        TlsFlush(conn, &to_client, uv_hrtime() + 5000000000);
        conn->Shutdown();
      }
      return;
    }
  }
}

// Sends an exit frame with `status` and closes the connection. Best effort.
static void SendExitFrame(TlsConnection* conn, int status) {
  std::string reply;
  AppendInt32Frame(&reply, kFrameExit, status);
  TlsFlush(conn, &reply, uv_hrtime() + 1000000000);
  conn->Shutdown();
}

// Runs in a relay process forked for a TCP connection whose TLS handshake has
// completed. Reads the request, forks the program child with pipes on its fds
// 0-2, and copies data between the pipes and the connection until the program
// has exited. Returns only in the program child; the relay itself exits.
static Request RunRelay(int fd, SSL* ssl) {
  // OpenSSL writes to the socket with write(), not send(MSG_NOSIGNAL).
  // Node.js ignores SIGPIPE already, unless an embedder disabled that.
  const sighandler_t old_sigpipe = signal(SIGPIPE, SIG_IGN);
  TlsConnection conn(ssl, fd);
  Request req;
  if (!ReadRequest(&conn, uv_hrtime() + kRequestTimeoutNs, &req)) {
    SendExitFrame(&conn, W_EXITCODE(kInvalidRequestExitCode, 0));
    _exit(0);
  }
  const int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  int stdin_pipe[2];
  int stdout_pipe[2];
  int stderr_pipe[2];
  CHECK_EQ(pipe2(stdin_pipe, O_CLOEXEC), 0);
  CHECK_EQ(pipe2(stdout_pipe, O_CLOEXEC), 0);
  CHECK_EQ(pipe2(stderr_pipe, O_CLOEXEC), 0);

  const pid_t relay = getpid();
  const pid_t child = fork();
  if (child < 0) {
    SendExitFrame(&conn, W_EXITCODE(127, 0));
    _exit(0);
  }
  if (child == 0) {
    HangUpWhenParentExits(relay);
    close(fd);
    // The program has no use for the connection. The SSL does not own `fd`,
    // so freeing it sends nothing. This is hygiene, not isolation: the program
    // runs as the zygote's user, and freeing does not wipe the connection's
    // secrets (see ServeTcp()).
    SSL_free(ssl);
    signal(SIGPIPE, old_sigpipe);
    // The relay keeps fds 0-2 open, so the pipe fds are all > 2.
    CHECK_EQ(dup2(stdin_pipe[0], 0), 0);
    CHECK_EQ(dup2(stdout_pipe[1], 1), 1);
    CHECK_EQ(dup2(stderr_pipe[1], 2), 2);
    for (int pipe_fd : {stdin_pipe[0],
                        stdin_pipe[1],
                        stdout_pipe[0],
                        stdout_pipe[1],
                        stderr_pipe[0],
                        stderr_pipe[1]}) {
      close(pipe_fd);
    }
    return req;
  }
  close(stdin_pipe[0]);
  close(stdout_pipe[1]);
  close(stderr_pipe[1]);
  const int pidfd = PidfdForChild(child);
  if (pidfd < 0) {
    SendExitFrame(&conn, W_EXITCODE(127, 0));
    _exit(0);
  }
  PumpRelay(&conn, child, pidfd, stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);
  _exit(0);
}

// A TCP connection whose TLS handshake has not completed yet.
struct PendingConnection {
  int fd;
  uint64_t deadline;  // uv_hrtime()
  SSL* ssl;
  int16_t events;  // What the handshake waits for.
};

enum class HandshakeResult { kIncomplete, kAccepted, kRejected };

static HandshakeResult ContinueHandshake(PendingConnection* conn) {
  ERR_clear_error();
  const int r = SSL_do_handshake(conn->ssl);
  if (r == 1) {
    // The zygote has no certificate, so a handshake can only complete with
    // the PSK. Check anyway: the PSK is what authenticates the client.
    return SSL_session_reused(conn->ssl) == 1 ? HandshakeResult::kAccepted
                                              : HandshakeResult::kRejected;
  }
  switch (SSL_get_error(conn->ssl, r)) {
    case SSL_ERROR_WANT_READ:
      conn->events = POLLIN;
      return HandshakeResult::kIncomplete;
    case SSL_ERROR_WANT_WRITE:
      conn->events = POLLOUT;
      return HandshakeResult::kIncomplete;
    default:
      // Most likely a client with another token. There is nobody to tell.
      ERR_clear_error();
      return HandshakeResult::kRejected;
  }
}

// Accept loop for a TCP socket. A connection must complete the TLS handshake
// within kHandshakeTimeoutNs before the zygote forks a relay for it. Returns
// only in a program child, with the relay's pipes installed on fds 0-2.
static Request ServeTcp(int listen_fd, SSL_CTX* ctx) {
  // Oldest first.
  std::vector<PendingConnection> pending;
  std::vector<Relay> relays;
  std::vector<pollfd> pollfds;
  uint64_t accept_after = 0;  // See kAcceptBackoffNs.
  for (;;) {
    const uint64_t now = uv_hrtime();
    const bool accepting = now >= accept_after;
    int timeout_ms = accepting ? -1 : MsUntil(accept_after, now);
    pollfds.clear();
    pollfds.push_back({accepting ? listen_fd : -1, POLLIN, 0});
    for (const Relay& relay : relays) {
      pollfds.push_back({relay.pidfd, POLLIN, 0});
    }
    const size_t relay_count = relays.size();
    for (const PendingConnection& conn : pending) {
      pollfds.push_back({conn.fd, conn.events, 0});
      timeout_ms = EarlierTimeout(timeout_ms, MsUntil(conn.deadline, now));
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
      HandshakeResult result = HandshakeResult::kIncomplete;
      if (pollfds[1 + relay_count + i].revents != 0) {
        result = ContinueHandshake(&pending[i]);
      }
      if (result == HandshakeResult::kIncomplete &&
          after_poll >= pending[i].deadline) {
        result = HandshakeResult::kRejected;
      }
      if (result == HandshakeResult::kIncomplete) continue;
      const PendingConnection conn = pending[i];
      pending.erase(pending.begin() + i);
      if (result == HandshakeResult::kRejected) {
        SSL_free(conn.ssl);
        close(conn.fd);
        continue;
      }

      const pid_t pid = fork();
      if (pid == 0) {
        close(listen_fd);
        for (const PendingConnection& other : pending) {
          SSL_free(other.ssl);  // Sends nothing: the SSL does not own the fd.
          close(other.fd);
        }
        for (const Relay& relay : relays) close(relay.pidfd);
        // Only the zygote completes handshakes.
        ForgetTlsKey();
        return RunRelay(conn.fd, conn.ssl);
      }
      // The relay owns the connection now. The SSL does not own the fd, so
      // freeing it here sends nothing. OpenSSL does not wipe the connection's
      // secrets when it frees them, and has no API to do so: they stay in the
      // zygote's freed memory, which relays and programs forked later
      // inherit. The secrets are only good for this connection.
      SSL_free(conn.ssl);
      close(conn.fd);
      if (pid < 0) continue;
      const int pidfd = PidfdForChild(pid);
      if (pidfd < 0) continue;  // The client sees the connection close.
      relays.push_back({pid, pidfd});
    }

    if (!(pollfds[0].revents & POLLIN)) continue;
    for (;;) {
      int fd;
      const AcceptResult accepted =
          AcceptConnection(listen_fd, SOCK_NONBLOCK, &fd);
      if (accepted == AcceptResult::kBackOff) {
        accept_after = uv_hrtime() + kAcceptBackoffNs;
      }
      if (accepted != AcceptResult::kAccepted) break;
      if (pending.size() >= kMaxPendingHandshakes) {
        SSL_free(pending.front().ssl);
        close(pending.front().fd);
        pending.erase(pending.begin());
      }
      SSL* ssl = SSL_new(ctx);
      if (ssl == nullptr || SSL_set_fd(ssl, fd) != 1) {
        ERR_clear_error();
        SSL_free(ssl);
        close(fd);
        continue;
      }
      SSL_set_accept_state(ssl);
      // The client speaks first.
      pending.push_back({fd, uv_hrtime() + kHandshakeTimeoutNs, ssl, POLLIN});
    }
  }
}

#endif  // NODE_ZYGOTE_HAVE_TLS

// Runs the accept loop for a Unix domain socket path or a TCP `host:port`.
// Returns (in a forked child only) an array [pid, cwd, argv, env, mode]
// describing the program the child should become.
static void Serve(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  CHECK(env->is_main_thread());
  CHECK(env->owns_process_state());
  CHECK(args[0]->IsString());
  const std::string address = Utf8Value(isolate, args[0]).ToString();

  std::string host;
  std::string port;
  const bool tcp = ParseTcpAddress(address, &host, &port);
  // Read here rather than in JavaScript, so that no copy of the token is left
  // on the JavaScript heap, which every forked process inherits.
  std::string token;
  auto wipe_token =
      OnScopeLeave([&token]() { explicit_bzero(token.data(), token.size()); });
  if (tcp) token = TakeTokenFromEnvironment();
  if (tcp && !IsValidPort(port)) {
    return THROW_ERR_INVALID_STATE(env, "zygote: invalid port in %s", address);
  }
  if (tcp && (token.size() < kMinTokenSize || token.size() > kMaxTokenSize)) {
    return THROW_ERR_INVALID_STATE(
        env,
        "zygote: a TCP address requires NODE_ZYGOTE_TOKEN with 32 to 256 "
        "characters");
  }

  // The zygote tracks its children with pidfds.
  const int pidfd_probe =
      static_cast<int>(syscall(SYS_pidfd_open, getpid(), 0));
  if (pidfd_probe < 0) {
    return THROW_ERR_INVALID_STATE(
        env,
        "zygote: pidfd_open() is not available (Linux 5.3 or later is "
        "required): %s",
        strerror(errno));
  }
  close(pidfd_probe);

  if (env->event_loop()->active_reqs.count != 0) {
    return THROW_ERR_INVALID_STATE(
        env, "zygote: cannot fork while the event loop has active requests");
  }

#if NODE_ZYGOTE_HAVE_TLS
  SslCtxPointer tls_ctx;
  // Serve() only returns on errors and in program children; neither needs
  // the key.
  auto forget_key = OnScopeLeave([]() {
    ForgetTlsKey();
    ERR_clear_error();
  });
  if (tcp) {
    tls_ctx = NewTlsContext(true);
    const bool key_ok = tls_ctx && SetTlsKey(token);
    explicit_bzero(token.data(), token.size());
    if (!key_ok) {
      return THROW_ERR_INVALID_STATE(
          env, "zygote: cannot set up TLS: %s", TlsError());
    }
  }
#else
  if (tcp) {
    return THROW_ERR_INVALID_STATE(
        env,
        "zygote: a TCP address requires a build with OpenSSL (not BoringSSL)");
  }
#endif  // NODE_ZYGOTE_HAVE_TLS

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

  // A preload that listens for one of these signals installs libuv's handler,
  // which only wakes up the event loop. The zygote never runs its loop again,
  // so it would ignore the signal. Use the default actions while serving, and
  // give programs the preloads' handlers back. Ignored signals stay ignored
  // (as with nohup).
  constexpr int kStopSignals[] = {SIGHUP, SIGINT, SIGTERM};
  struct sigaction preload_actions[arraysize(kStopSignals)];
  for (size_t i = 0; i < arraysize(kStopSignals); i++) {
    CHECK_EQ(sigaction(kStopSignals[i], nullptr, &preload_actions[i]), 0);
    if (preload_actions[i].sa_handler == SIG_IGN) continue;
    struct sigaction default_action {};
    default_action.sa_handler = SIG_DFL;
    sigemptyset(&default_action.sa_mask);
    CHECK_EQ(sigaction(kStopSignals[i], &default_action, nullptr), 0);
  }

  // Only children that become programs get past this point.
#if NODE_ZYGOTE_HAVE_TLS
  Request req = tcp ? ServeTcp(listen_fd, tls_ctx.get()) : ServeUnix(listen_fd);
#else
  Request req = ServeUnix(listen_fd);
#endif  // NODE_ZYGOTE_HAVE_TLS

  for (size_t i = 0; i < arraysize(kStopSignals); i++) {
    CHECK_EQ(sigaction(kStopSignals[i], &preload_actions[i], nullptr), 0);
  }
  // process.uptime() counts from here.
  per_process::node_start_time = uv_hrtime();
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

static void SignalChild(pid_t pid, int signo) {
  // The child calls setsid() right after fork(); until it does, its process
  // group does not exist.
  if (kill(-pid, signo) != 0) kill(pid, signo);
}

static void ForwardSignalToChild(int signo) {
  const pid_t pid = client_child_pid;
  if (pid <= 0) {
    client_pending_signal = signo;
    return;
  }
  const int saved_errno = errno;
  SignalChild(pid, signo);
  errno = saved_errno;
}

// Job control. The child runs in a session of its own, and the kernel
// discards SIGTSTP sent to such an orphaned process group. So on SIGTSTP
// (Ctrl-Z) the client stops the child with SIGSTOP, stops itself as SIGTSTP
// would have, and continues the child once it is continued itself (`fg`,
// `bg`). If the client is in an orphaned process group as well, it does not
// stop, and the child continues right away.

// Stops this process as an unhandled SIGTSTP would, until SIGCONT.
// Async-signal-safe.
static void StopSelf() {
  struct sigaction default_action {};
  struct sigaction handler {};
  default_action.sa_handler = SIG_DFL;
  sigemptyset(&default_action.sa_mask);
  sigaction(SIGTSTP, &default_action, &handler);
  sigset_t tstp;
  sigset_t old_mask;
  sigemptyset(&tstp);
  sigaddset(&tstp, SIGTSTP);
  pthread_sigmask(SIG_UNBLOCK, &tstp, &old_mask);
  kill(getpid(), SIGTSTP);  // Returns once continued.
  pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
  sigaction(SIGTSTP, &handler, nullptr);
}

static void SuspendWithChild(int) {
  const int saved_errno = errno;
  const pid_t pid = client_child_pid;
  if (pid > 0) SignalChild(pid, SIGSTOP);
  StopSelf();
  if (pid > 0) SignalChild(pid, SIGCONT);
  errno = saved_errno;
}

#if NODE_ZYGOTE_HAVE_TLS
// TCP: signals are handed to the client's poll loop, which sends them as
// frames.
static int client_signal_pipe = -1;

static void WriteSignalToPipe(int signo) {
  const int saved_errno = errno;
  const unsigned char byte = static_cast<unsigned char>(signo);
  USE(write(client_signal_pipe, &byte, 1));
  errno = saved_errno;
}
#endif  // NODE_ZYGOTE_HAVE_TLS

static void InstallSignalHandlers(void (*handler)(int),
                                  void (*tstp_handler)(int)) {
  struct sigaction sa {};
  sa.sa_handler = handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  for (int signo : kForwardedSignals) {
    CHECK_EQ(sigaction(signo, &sa, nullptr), 0);
  }
  sa.sa_handler = tstp_handler;
  CHECK_EQ(sigaction(SIGTSTP, &sa, nullptr), 0);
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
  for (char** entry = ::environ; *entry != nullptr; entry++) {
    if (IsTokenEnvEntry(*entry)) continue;
    payload.append(*entry, strlen(*entry) + 1);
    envc++;
  }
  if (payload.size() > kMaxPayloadSize) {
    fprintf(stderr, "%s: --connect: request too large\n", self);
    return false;
  }

  const mode_t mask = umask(0);
  umask(mask);
  const RequestHeader header{htonl(kRequestMagic),
                             htonl(mode),
                             htonl(static_cast<uint32_t>(argv.size())),
                             htonl(envc),
                             htonl(static_cast<uint32_t>(mask)),
                             htonl(static_cast<uint32_t>(payload.size()))};
  message->assign(reinterpret_cast<const char*>(&header), sizeof(header));
  *message += payload;
  return true;
}

#if NODE_ZYGOTE_HAVE_TLS
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
#endif  // NODE_ZYGOTE_HAVE_TLS

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

  // The request hands over our environment and stdio, so make sure the server
  // runs as this user first. In a shared directory such as /tmp, another user
  // could have bound a socket at this path. The zygote checks the same thing
  // in the other direction.
  ucred cred{};
  socklen_t cred_len = sizeof(cred);
  if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0) {
    fprintf(stderr,
            "%s: cannot identify the server at %s: %s\n",
            self,
            socket_path.c_str(),
            strerror(errno));
    return kClientFailure;
  }
  if (cred.uid != geteuid()) {
    fprintf(stderr,
            "%s: refusing to use %s: it is served by uid %u, not uid %u\n",
            self,
            socket_path.c_str(),
            static_cast<unsigned>(cred.uid),
            static_cast<unsigned>(geteuid()));
    return kClientFailure;
  }

  std::string message;
  if (!BuildRequest(self, mode, request_argv, &message)) {
    return kClientFailure;
  }

  // From here on, signals are forwarded to the child, or recorded until its
  // pid is known.
  InstallSignalHandlers(ForwardSignalToChild, SuspendWithChild);

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
    reply.type = ntohl(reply.type);
    reply.value =
        static_cast<int32_t>(ntohl(static_cast<uint32_t>(reply.value)));
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
            "%s: --connect=%s requires NODE_ZYGOTE_TOKEN with 32 to 256 "
            "characters\n",
            self,
            address.c_str());
    return ExitCode::kInvalidCommandLineArgument;
  }
#if !NODE_ZYGOTE_HAVE_TLS
  fprintf(stderr,
          "%s: --connect=%s requires a build with OpenSSL (not BoringSSL)\n",
          self,
          address.c_str());
  return ExitCode::kInvalidCommandLineArgument;
#else
  // Node.js has not initialized OpenSSL yet, and the client does not need its
  // configuration file.
  if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1) {
    fprintf(stderr, "%s: cannot initialize OpenSSL\n", self);
    return kClientFailure;
  }
  // OpenSSL writes to the socket with write(), not send(MSG_NOSIGNAL).
  signal(SIGPIPE, SIG_IGN);

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
  SetNonBlocking(sock, true);

  SslCtxPointer ctx = NewTlsContext(false);
  std::string token_copy(token, token_size);
  const bool key_ok = ctx && SetTlsKey(token_copy);
  explicit_bzero(token_copy.data(), token_copy.size());
  SslPointer ssl(key_ok ? SSL_new(ctx.get()) : nullptr);
  if (!ssl || SSL_set_fd(ssl.get(), sock) != 1) {
    fprintf(stderr, "%s: cannot set up TLS: %s\n", self, TlsError().c_str());
    return kClientFailure;
  }
  SSL_set_connect_state(ssl.get());
  const uint64_t deadline = uv_hrtime() + kClientHandshakeTimeoutNs;
  for (;;) {
    ERR_clear_error();
    const int r = SSL_do_handshake(ssl.get());
    if (r == 1) break;
    const int err = SSL_get_error(ssl.get(), r);
    if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
        WaitFor(
            sock, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline)) {
      continue;
    }
    std::string reason;
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      reason = TlsError();
    } else if (uv_hrtime() >= deadline) {
      reason = "timed out";
    } else {
      reason = std::string("poll(): ") + strerror(errno);
    }
    fprintf(stderr,
            "%s: TLS handshake with %s failed (does NODE_ZYGOTE_TOKEN match "
            "the zygote's?): %s\n",
            self,
            address.c_str(),
            reason.c_str());
    return kClientFailure;
  }
  // NewTlsContext() leaves no way to complete a handshake without the PSK,
  // but make sure: only the PSK authenticates the zygote.
  if (SSL_session_reused(ssl.get()) != 1) {
    fprintf(stderr,
            "%s: %s did not authenticate with NODE_ZYGOTE_TOKEN\n",
            self,
            address.c_str());
    return kClientFailure;
  }
  ForgetTlsKey();
  TlsConnection conn(ssl.get(), sock);

  std::string to_server;
  if (!BuildRequest(self, mode, request_argv, &to_server)) {
    return kClientFailure;
  }

  int signal_pipe[2];
  CHECK_EQ(pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK), 0);
  client_signal_pipe = signal_pipe[1];
  InstallSignalHandlers(WriteSignalToPipe, WriteSignalToPipe);

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
  // Set on SIGTSTP once the SIGSTOP frame is queued: the client stops itself
  // once the frame has been sent (see SuspendWithChild()).
  bool suspend = false;
  const auto on_frame = [&](uint32_t type, const char* data, uint32_t size) {
    if (type == kFrameStdout) {
      if (stdout_open) stdout_open = WriteAll(1, data, size);
    } else if (type == kFrameStderr) {
      if (stderr_open) stderr_open = WriteAll(2, data, size);
    } else if (type == kFrameExit && size == sizeof(int32_t)) {
      exit_status = ReadInt32Frame(data);
    }
  };
  for (;;) {
    const bool want_write = !to_server.empty();
    const int16_t conn_events =
        conn.read_events() | (want_write ? conn.write_events() : 0);
    const bool buffered = conn.HasBufferedData();
    pollfd fds[] = {
        {sock, conn_events, 0},
        {stdin_open && to_server.size() < kMaxBuffered ? 0 : -1, POLLIN, 0},
        {signal_pipe[0], POLLIN, 0},
    };
    if (poll(fds, arraysize(fds), buffered ? 0 : -1) < 0) {
      if (errno == EINTR) continue;
      return lost_connection();
    }

    if (fds[2].revents & POLLIN) {
      unsigned char signals[64];
      const ssize_t n = read(signal_pipe[0], signals, sizeof(signals));
      for (ssize_t i = 0; i < n; i++) {
        if (signals[i] == SIGTSTP) {
          AppendInt32Frame(&to_server, kFrameSignal, SIGSTOP);
          suspend = true;
        } else {
          AppendInt32Frame(&to_server, kFrameSignal, signals[i]);
        }
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

    if (suspend && conn.WriteSome(&to_server) && to_server.empty()) {
      suspend = false;
      StopSelf();
      AppendInt32Frame(&to_server, kFrameSignal, SIGCONT);
      continue;
    }

    if (!buffered && fds[0].revents == 0) continue;
    if (!conn.WriteSome(&to_server)) return lost_connection();
    for (;;) {
      const ssize_t n = conn.Read(buffer.data(), buffer.size());
      if (n == TlsConnection::kWouldBlock) break;
      if (n == TlsConnection::kClosed) return lost_connection();
      from_server.append(buffer.data(), n);
      const bool ok = ConsumeFrames(&from_server, on_frame);
      if (exit_status.has_value()) {
        return ExitCodeFromWaitStatus(*exit_status);
      }
      if (!ok) return lost_connection();
    }
  }
#endif  // NODE_ZYGOTE_HAVE_TLS
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
