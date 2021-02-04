#ifndef SRC_QUIC_SESSION_H_
#define SRC_QUIC_SESSION_H_
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#ifndef OPENSSL_NO_QUIC

#include "async_wrap.h"
#include "base_object.h"
#include "env.h"
#include "quic.h"

#include <ngtcp2/ngtcp2.h>
#include <v8.h>

namespace node {
namespace quic {

class Session final : public AsyncWrap {
 public:
  static v8::Local<v8::FunctionTemplate> GetConstructorTemplate(
      Environment* env);
  static BaseObjectPtr<Session> Create(Environment* env);

 private:
  Session(Environment* env, v8::Local<v8::Object> object);
};

}  // namespace quic
}  // namespace node

#endif  // OPENSSL_NO_QUIC
#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_QUIC_SESSION_H_
