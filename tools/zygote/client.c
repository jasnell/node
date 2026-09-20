// Prototype client for `node --experimental-zygote=<socket>`.
//
//   cc -O2 -o out/zygote-client tools/zygote/client.c
//   out/zygote-client <socket> <script> [args...]
//
// Hands this process's stdio fds, cwd, umask, argv and environment to the
// zygote, forwards signals to the forked child's process group, and exits the
// way the child did.

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

#define REQUEST_MAGIC 0x4e5a5947u  // "NZYG"
#define EXIT_CLIENT_ERROR 125

struct request_header {
  uint32_t magic;
  uint32_t mode;  // 0: argv[0] is the main module
  uint32_t argc;
  uint32_t envc;
  uint32_t umask;
  uint32_t payload_size;
};

struct reply {
  uint32_t type;
  int32_t value;
};

static volatile sig_atomic_t child_pid;
static volatile sig_atomic_t pending_signal;

static void forward_signal(int sig) {
  const pid_t pid = child_pid;
  if (pid <= 0) {
    pending_signal = sig;
    return;
  }
  const int saved_errno = errno;
  // The child calls setsid() right after fork(); until it does, its process
  // group does not exist.
  if (kill(-pid, sig) != 0) kill(pid, sig);
  errno = saved_errno;
}

static int read_fully(int fd, void* buf, size_t len) {
  char* p = buf;
  while (len > 0) {
    const ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    p += n;
    len -= (size_t)n;
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <socket> <script> [args...]\n", argv[0]);
    return EXIT_CLIENT_ERROR;
  }

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  if (strlen(argv[1]) >= sizeof(addr.sun_path)) {
    fprintf(stderr, "zygote-client: socket path too long\n");
    return EXIT_CLIENT_ERROR;
  }
  strcpy(addr.sun_path, argv[1]);
  const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0 ||
      connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    fprintf(stderr, "zygote-client: cannot connect to %s: %s\n",
            argv[1], strerror(errno));
    return EXIT_CLIENT_ERROR;
  }

  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror("zygote-client: getcwd");
    return EXIT_CLIENT_ERROR;
  }

  size_t envc = 0;
  size_t payload_size = strlen(cwd) + 1;
  for (int i = 2; i < argc; i++) payload_size += strlen(argv[i]) + 1;
  for (char** e = environ; *e != NULL; e++, envc++) {
    payload_size += strlen(*e) + 1;
  }

  const mode_t mask = umask(0);
  umask(mask);

  const struct request_header header = {
      .magic = REQUEST_MAGIC,
      .mode = 0,
      .argc = (uint32_t)(argc - 2),
      .envc = (uint32_t)envc,
      .umask = (uint32_t)mask,
      .payload_size = (uint32_t)payload_size,
  };
  const size_t total = sizeof(header) + payload_size;
  char* message = malloc(total);
  if (message == NULL) return EXIT_CLIENT_ERROR;
  memcpy(message, &header, sizeof(header));
  char* p = message + sizeof(header);
  p = stpcpy(p, cwd) + 1;
  for (int i = 2; i < argc; i++) p = stpcpy(p, argv[i]) + 1;
  for (char** e = environ; *e != NULL; e++) p = stpcpy(p, *e) + 1;

  // The first chunk carries fds 0-2 as ancillary data.
  const int fds[3] = {0, 1, 2};
  char control[CMSG_SPACE(sizeof(fds))];
  memset(control, 0, sizeof(control));
  struct iovec iov = {.iov_base = message, .iov_len = total};
  struct msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
  memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

  for (size_t sent = 0; sent < total;) {
    const ssize_t n =
        sent == 0 ? sendmsg(sock, &msg, MSG_NOSIGNAL)
                  : send(sock, message + sent, total - sent, MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      perror("zygote-client: send");
      return EXIT_CLIENT_ERROR;
    }
    sent += (size_t)n;
  }
  free(message);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = forward_signal;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  const int forwarded[] = {
      SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH, SIGUSR1, SIGUSR2};
  for (size_t i = 0; i < sizeof(forwarded) / sizeof(forwarded[0]); i++) {
    sigaction(forwarded[i], &sa, NULL);
  }

  for (;;) {
    struct reply reply;
    if (read_fully(sock, &reply, sizeof(reply)) != 0) {
      fprintf(stderr, "zygote-client: lost connection to the zygote\n");
      return EXIT_CLIENT_ERROR;
    }
    if (reply.type == 'P') {
      child_pid = reply.value;
      if (pending_signal != 0) forward_signal(pending_signal);
    } else if (reply.type == 'X') {
      const int status = reply.value;
      if (WIFEXITED(status)) return WEXITSTATUS(status);
      if (WIFSIGNALED(status)) {
        // Die the same way, so that our parent sees the signal too.
        const int sig = WTERMSIG(status);
        signal(sig, SIG_DFL);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        raise(sig);
        return 128 + sig;
      }
      return EXIT_CLIENT_ERROR;
    }
  }
}
