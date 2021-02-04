#ifndef SRC_QUIC_STREAM_H_
#define SRC_QUIC_STREAM_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "quic/quic.h"
#include "quic/session.h"

#include <ngtcp2/ngtcp2.h>

namespace node {
namespace quic {

class Stream final : public AsyncWrap {
 public:
  enum class Direction {
    UNIDIRECTIONAL,
    BIDIRECTIONAL,
  };

  enum class Origin {
    SERVER,
    CLIENT,
  };

  enum class HeadersKind {
    INFO,
    INITIAL,
    TRAILING,
  };

  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static void Initialize(Environment* env);
  static BaseObjectPtr<Stream> Create(
      Environment* env,
      Session* session,
      stream_id id);

  Stream(
      Environment* env,
      v8::Local<v8::Object> object,
      Session* session,
      stream_id id);

  stream_id id() const { return id_; }

  Session* session() const { return session_.get(); }

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(Stream)
  SET_SELF_SIZE(Stream)

 private:

  BaseObjectPtr<Session> session_;
  stream_id id_;
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_STREAM_H_
