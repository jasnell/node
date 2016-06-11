
#include "node.h"
#include "node_buffer.h"
#include "nghttp2/nghttp2.h"

#include "async-wrap.h"
#include "async-wrap-inl.h"
#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8.h"

#include <vector>
#include <stdio.h>
#include <stdlib.h>

namespace node {

using v8::Array;
using v8::ArrayBuffer;
using v8::Boolean;
using v8::Context;
using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Name;
using v8::Integer;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::Value;
using v8::Uint8Array;

#define FN(name) static void name(const FunctionCallbackInfo<Value>& args)

#define PROP(name) static void name(Local<String> property,                   \
                                    const PropertyCallbackInfo<Value>& args)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                  \
  {                                                                           \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,  \
        NGHTTP2_NV_FLAG_NONE                                                  \
  }

#define MAKE_NV2(NAME, NAMELEN, VALUE, VALLEN)                                \
  {                                                                           \
    (uint8_t *) NAME, (uint8_t *)VALUE, NAMELEN, VALLEN, NGHTTP2_NV_FLAG_NONE \
  }

#define ERROR_STR(code)                                                       \
  OneByteString(env->isolate(), nghttp2_http2_strerror(code))

#define PROPERTY(target, isolate, name)                                       \
  target->Set(FIXED_ONE_BYTE_STRING(isolate, #name),                          \
         Integer::NewFromUnsigned(isolate, name));

#define THROW_AND_RETURN_UNLESS_BUFFER(env, obj)                              \
  do {                                                                        \
    if (!Buffer::HasInstance(obj))                                            \
      return env->ThrowTypeError("argument should be a Buffer");              \
  } while (0)

#define SPREAD_ARG(val, name)                                                 \
  CHECK((val)->IsUint8Array());                                               \
  Local<Uint8Array> name = (val).As<Uint8Array>();                            \
  ArrayBuffer::Contents name##_c = name->Buffer()->GetContents();             \
  const size_t name##_offset = name->ByteOffset();                            \
  const size_t name##_length = name->ByteLength();                            \
  char* const name##_data =                                                   \
      static_cast<char*>(name##_c.Data()) + name##_offset;                    \
  if (name##_length > 0)                                                      \
    CHECK_NE(name##_data, nullptr);

namespace http2 {

  enum http2_session_callbacks {
    kOnSend,
    kOnStreamClose,
    kOnBeginHeaders,
    kOnHeaders,
    kOnHeader,
    kOnData,
    kOnGoaway,
    kOnSettings,
    kOnRstStream,
    kOnPriority,
    kOnPing,
    kOnDataChunk,
    kOnFrameSend
  } http2_session_callbacks;
  
  enum http2_data_flags {
    kFlagEndStream,
    kFlagEndData,
    kFlagNoEndStream
  } http2_data_flags;

  enum http2_session_type {
    INVALID = -1,
    SERVER = 0,
    CLIENT = 1
  } http2_session_type;

  class Http2Session; // Forward Declaration
  class Http2Stream;  // Forward Declaration

  class Http2Header : BaseObject {
   public:
     FN(New);

     nghttp2_nv operator*() {
       return nv_;
     }
   private:
     friend class Http2Session;

     Http2Header(Environment* env,
                 v8::Local<v8::Object> wrap,
                 char* name, size_t nlen,
                 char* value, size_t vlen) :
                 BaseObject(env, wrap) {
        Wrap(object(), this);
        nv_.name = static_cast<uint8_t*>(malloc(nlen));
        nv_.value = static_cast<uint8_t*>(malloc(vlen));
        nv_.namelen = nlen;
        nv_.valuelen = vlen;
        nv_.flags = NGHTTP2_NV_FLAG_NONE;
        memcpy(nv_.name, name, nlen);
        memcpy(nv_.value, value, vlen);
     }

     ~Http2Header() {
       free(nv_.name);
       free(nv_.value);
     }

     nghttp2_nv nv_;
  };

  class Http2Stream : public AsyncWrap {
   public:

     PROP(GetID);

     size_t self_size() const override {
       return sizeof(*this);
     }

   private:
     friend class Http2Session;

     Http2Stream(Environment* env,
                 Local<Object> wrap,
                 Http2Session* session,
                 int32_t stream_id)
         : AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2SESSION),
           session_(session),
           stream_id_(stream_id) {
       Wrap(object(), this);
       prev_ = nullptr;
       next_ = nullptr;
     }

     ~Http2Stream() override {
       persistent().Reset();
     }

     static void RemoveStream(Http2Stream* stream);
     static void AddStream(Http2Stream* stream, Http2Session* session);

     Http2Session* session_;
     Http2Stream* prev_;
     Http2Stream* next_;
     int32_t stream_id_;
  };

  class Http2Session : public AsyncWrap {
   public:
     FN(New);
     FN(GetType);
     FN(Destroy);
     FN(Terminate);
     FN(ChangeStreamPriority);
     FN(Consume);
     FN(ConsumeSession);
     FN(ConsumeStream);
     FN(GetEffectiveLocalWindowSize);
     FN(GetEffectiveRecvDataLength);
     FN(GetLastProcStreamID);
     FN(GetNextStreamID);
     FN(GetOutboundQueueSize);
     FN(GetRemoteWindowSize);
     FN(SetLocalWindowSize);
     FN(SetNextStreamID);
     FN(GetRemoteSetting);
     FN(CreateIdleStream);
     FN(GetStreamLocalClose);
     FN(GetStreamRemoteClose);
     FN(GetStreamState);
     FN(GetStreamWeight);
     FN(SendServerConnectionHeader);
     FN(ReceiveData);
     FN(SendData);
     FN(RstStream);
     FN(Respond);
     FN(SendContinue);
     FN(ResumeData);
     FN(SendTrailers);

     size_t self_size() const override {
       return sizeof(*this);
     }

   private:
    friend class Http2Stream;
    friend class Http2Header;
    Http2Session(Environment* env,
                 Local<Object> wrap,
                 enum http2_session_type type)
        : AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2SESSION),
          type_(type) {
      Wrap(object(), this);
      Init(type);
      root_ = create_stream(env, this, 0);
    }

    ~Http2Session() override {
      persistent().Reset();
      nghttp2_session_del(session_);
    }

    // Called by nghttp2 with serialized data that needs to be passed to the
    // socket to be sent to the peer. This works by triggering a callback
    // event on the Http2Session object.
    static ssize_t on_send(nghttp2_session* session,
                           const uint8_t *data,
                           size_t length,
                           int flags,
                           void *user_data) {
      Http2Session* session_obj = (Http2Session *)user_data;
      Environment* env = session_obj->env();
      const char* ts_obj_data = reinterpret_cast<const char*>(data);
      
      Local<Object> buffer = Buffer::Copy(env->isolate(),
                                          ts_obj_data,
                                          length).ToLocalChecked();
      Local<Value> argv[1];
      Local<Object> obj = session_obj->object();
      Local<Value> cb = obj->Get(kOnSend);
      if (!cb->IsFunction())
        return 0;
      argv[0] = buffer;
      Environment::AsyncCallbackScope callback_scope(env);
      session_obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
      return length;
    }

    static int on_rst_stream_frame(Http2Session* session,
                                   Http2Stream* stream,
                                   const nghttp2_frame_hd hd,
                                   const nghttp2_rst_stream rst) {
      Local<Value> argv[2];
      Local<Object> obj = session->object();
      Local<Value> cb = obj->Get(kOnRstStream);
      Environment* env = session->env();
      if (!cb->IsFunction())
        return 0;
      argv[0] = stream->object();
      argv[1] = Integer::NewFromUnsigned(env->isolate(), rst.error_code);
      Environment::AsyncCallbackScope callback_scope(env);
      session->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
    }

    static int on_goaway_frame(Http2Session* session,
                               const nghttp2_frame_hd hd,
                               const nghttp2_goaway goaway) {
      Local<Value> argv[3];
      Local<Object> obj = session->object();
      Local<Value> cb = obj->Get(kOnGoaway);
      Environment* env = session->env();
      if (!cb->IsFunction())
        return 0;

      argv[0] = Integer::NewFromUnsigned(env->isolate(), goaway.error_code);
      argv[1] = Integer::New(env->isolate(), goaway.last_stream_id);

      if (goaway.opaque_data_len > 0) {
        const char* data = reinterpret_cast<const char*>(goaway.opaque_data);
        argv[2] = Buffer::Copy(env->isolate(),
                               data,
                               goaway.opaque_data_len).ToLocalChecked();
      } else {
        argv[2] = Undefined(env->isolate());
      }

      Environment::AsyncCallbackScope callback_scope(env);
      session->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
    }

    static int on_data_frame(Http2Session* session,
                             Http2Stream* stream,
                             const nghttp2_frame_hd hd,
                             const nghttp2_data data) {
      Local<Value> argv[4];
      Local<Object> obj = session->object();
      Local<Value> cb = obj->Get(kOnData);
      Environment* env = session->env();
      if (!cb->IsFunction())
        return 0;
      argv[0] = stream->object();
      argv[1] = Integer::NewFromUnsigned(env->isolate(), hd.flags);
      argv[2] = Integer::New(env->isolate(), hd.length);
      argv[3] = Integer::New(env->isolate(), data.padlen);

      Environment::AsyncCallbackScope callback_scope(env);
      session->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
    }

    // Called at the completion of a headers frame
    static int on_headers_frame(Http2Session* session,
                                Http2Stream* stream,
                                const nghttp2_frame_hd hd,
                                const nghttp2_headers headers) {
      Local<Object> obj = session->object();
      Local<Value> cb = obj->Get(kOnHeaders);
      Environment* env = session->env();
      if (!cb->IsFunction())
        return 0;
      Local<Value> argv[] {
        stream->object(),
        Integer::NewFromUnsigned(env->isolate(), hd.flags)
      };
      Environment::AsyncCallbackScope callback_scope(env);
      session->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
    }

    // Called by nghttp2 when a frame is received for processing.
    // the user_data void pointer is the Http2Session object.
    static int on_frame_recv(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             void *user_data) {
      Http2Session* session_obj = (Http2Session *)user_data;
      Http2Stream* stream_data;
      switch (frame->hd.type) {
      case NGHTTP2_RST_STREAM:
        stream_data =
            (Http2Stream*)nghttp2_session_get_stream_user_data(
                session, frame->hd.stream_id);
        return on_rst_stream_frame(session_obj,
                                   stream_data,
                                   frame->hd,
                                   frame->rst_stream);
      case NGHTTP2_GOAWAY:
        return on_goaway_frame(session_obj,
                               frame->hd,
                               frame->goaway);
      case NGHTTP2_DATA:
        stream_data =
            (Http2Stream*)nghttp2_session_get_stream_user_data(
                session, frame->hd.stream_id);
        return on_data_frame(session_obj,
                             stream_data,
                             frame->hd,
                             frame->data);
      case NGHTTP2_HEADERS:
        stream_data =
            (Http2Stream*)nghttp2_session_get_stream_user_data(
                session, frame->hd.stream_id);
        return on_headers_frame(session_obj,
                                stream_data,
                                frame->hd,
                                frame->headers);
      default:
        break;
      }
      return 0;
    }

    static int on_stream_close(nghttp2_session *session,
                               int32_t stream_id,
                               uint32_t error_code,
                               void *user_data) {
      Http2Session* session_obj = (Http2Session *)user_data;
      Environment* env = session_obj->env();
      Http2Stream* stream_data;

      stream_data = (Http2Stream*)nghttp2_session_get_stream_user_data(
          session, stream_id);
      if (!stream_data)
        return 0;

      Local<Value> argv[2];
      Local<Object> obj = session_obj->object();
      Local<Value> cb = obj->Get(kOnStreamClose);
      if (!cb->IsFunction())
        return 0;
      argv[0] = stream_data->object();
      argv[1] = Integer::NewFromUnsigned(env->isolate(), error_code);
      Environment::AsyncCallbackScope callback_scope(env);
      Local<Value> send_response =
          session_obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
      Http2Stream::RemoveStream(stream_data);
      free(stream_data);
      return 0;
    }

    static int on_header(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         const uint8_t *name,
                         size_t namelen,
                         const uint8_t *value,
                         size_t valuelen,
                         uint8_t flags,
                         void *user_data) {
      Http2Session* session_obj = (Http2Session*)user_data;
      Environment* env = session_obj->env();
      Http2Stream* stream_data;

      stream_data = (Http2Stream*)nghttp2_session_get_stream_user_data(
         session, frame->hd.stream_id);
      if (!stream_data)
        return 0;

      Local<Value> argv[3];
      Local<Object> obj = session_obj->object();
      Local<Value> cb = obj->Get(kOnHeader);
      if (!cb->IsFunction())
        return 0;

      argv[0] = stream_data->object();
      argv[1] = OneByteString(env->isolate(), name, namelen);
      argv[2] = OneByteString(env->isolate(), value, valuelen);

      Environment::AsyncCallbackScope callback_scope(env);
      session_obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);

      return 0;
    }

    static Http2Stream* create_stream(Environment* env,
                                       Http2Session* session,
                                       uint32_t stream_id) {
      Local<ObjectTemplate> stream_template =
        ObjectTemplate::New(env->isolate());
      stream_template->SetInternalFieldCount(1);
      stream_template->SetAccessor(FIXED_ONE_BYTE_STRING(env->isolate(), "id"),
                                   Http2Stream::GetID);
      Local<Object> obj =
          stream_template->NewInstance(env->context()).ToLocalChecked();
      Http2Stream* stream = new Http2Stream(env, obj, session, stream_id);
      if (stream_id > 0)
        Http2Stream::AddStream(stream, session);
      nghttp2_session_set_stream_user_data(session->session_,
                                           stream_id,
                                           stream);
      return stream;
    }

    static int on_begin_headers(nghttp2_session* session,
                                const nghttp2_frame* frame,
                                void* user_data) {
      Http2Session* session_obj = (Http2Session*)user_data;
      Environment* env = session_obj->env();

      if (frame->hd.type != NGHTTP2_HEADERS ||
          frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
      }
      Http2Stream* stream_data = create_stream(env,
                                               session_obj,
                                               frame->hd.stream_id);

      stream_data = (Http2Stream*)nghttp2_session_get_stream_user_data(
         session, frame->hd.stream_id);
      if (!stream_data)
       return 0;

      Local<Value> argv[] {
        stream_data->object(),
        Integer::NewFromUnsigned(env->isolate(), frame->headers.cat)
      };
      Local<Object> obj = session_obj->object();
      Local<Value> cb = obj->Get(kOnBeginHeaders);
      if (!cb->IsFunction())
       return 0;
      Environment::AsyncCallbackScope callback_scope(env);
      Local<Value> send_response =
         session_obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);

      return 0;
    }

    static int on_data_chunk_recv(nghttp2_session* session,
                                  uint8_t flags,
                                  int32_t stream_id,
                                  const uint8_t* data,
                                  size_t len,
                                  void* user_data) {
      Http2Session* session_obj = (Http2Session *)user_data;
      Environment* env = session_obj->env();
      Local<Object> obj = session_obj->object();
      Local<Value> cb = obj->Get(kOnDataChunk);
      if (!cb->IsFunction())
        return 0;
      const char* cdata = reinterpret_cast<const char*>(data);
      Local<Value> argv[] {
        Integer::New(env->isolate(), stream_id),
        Integer::NewFromUnsigned(env->isolate(), flags),
        Buffer::Copy(env->isolate(), cdata, len).ToLocalChecked()
      };
      session_obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
      return 0;
    }

    static int on_frame_send(nghttp2_session* session,
                             const nghttp2_frame* frame,
                             void* user_data) {
      Http2Session* session_obj = (Http2Session*)user_data;
      Environment* env = session_obj->env();
      Local<Object> obj = session_obj->object();
      Local<Value> cb = obj->Get(kOnFrameSend);
      if (!cb->IsFunction())
        return 0;
      Local<Value> argv[] {
        Integer::New(env->isolate(), frame->hd.stream_id),
        Integer::New(env->isolate(), frame->hd.type),
        Integer::New(env->isolate(), frame->hd.flags)
      };
      session_obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
      return 0;
    }

    void Init(enum http2_session_type type) {
      nghttp2_session_callbacks *callbacks;
      nghttp2_session_callbacks_new(&callbacks);
      nghttp2_session_callbacks_set_send_callback(
          callbacks, on_send);
      nghttp2_session_callbacks_set_on_frame_recv_callback(
          callbacks, on_frame_recv);
      nghttp2_session_callbacks_set_on_stream_close_callback(
          callbacks, on_stream_close);
      nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
      nghttp2_session_callbacks_set_on_begin_headers_callback(
          callbacks, on_begin_headers);
      nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
          callbacks, on_data_chunk_recv);
      nghttp2_session_callbacks_set_on_frame_send_callback(
          callbacks, on_frame_send);
      nghttp2_session_server_new(&session_, callbacks, this);
      nghttp2_session_callbacks_del(callbacks);
    }

    Http2Stream* root_;
    enum http2_session_type type_;
    nghttp2_session* session_;
  }; // class Http2Session

  class Http2DataProvider : BaseObject {
   public:
     FN(New);
   
     nghttp2_data_provider* operator*() {
       return &provider_;
     }
   
   private:

     static ssize_t on_read(nghttp2_session* session,
                            int32_t stream_id,
                            uint8_t* buf,
                            size_t length,
                            uint32_t* flags,
                            nghttp2_data_source* source,
                            void* user_data) {

       Http2Session* session_obj = (Http2Session*)user_data;
       Http2DataProvider* provider = (Http2DataProvider*)source->ptr;
       Http2Stream* stream = provider->stream_;
       Local<Object> provider_obj = provider->object();
       Local<Object> stream_obj = stream->object();
       Environment* env = stream->env();

       Local<Value> cb = provider_obj->Get(kOnData);
       if (!cb->IsFunction())
         return 0;

       // Create a new Buffer of size length, along with a flags object
       // Also pass a flags object.
       // Return value indicates what to do next
       Local<Object> retFlags =
           Object::New(env->isolate());
       Local<Object> buffer =
           Buffer::New(env->isolate(), length).ToLocalChecked();
       Local<Value> argv[] { buffer, retFlags};

       Environment::AsyncCallbackScope callback_scope(env);
       Local<Value> ret = cb.As<Function>()->Call(env->context(),
                                                  stream_obj,
                                                  arraysize(argv),
                                                  argv).ToLocalChecked();

       CHECK(!ret.IsEmpty());
       int32_t val = ret->Int32Value();

       Local<Value> fv;
       bool endStream = false;
       bool eofData = false;
       bool noEndStream = false;

       fv = retFlags->Get(kFlagEndStream);
       if (!fv.IsEmpty())
         endStream = fv->BooleanValue();

       fv = retFlags->Get(kFlagEndData);
       if (!fv.IsEmpty())
         endStream = fv->BooleanValue();

       fv = retFlags->Get(kFlagNoEndStream);
       if (!fv.IsEmpty())
         noEndStream = fv->BooleanValue();

       if (endStream)
         *flags |= NGHTTP2_FLAG_END_STREAM;
       if (eofData)
         *flags |= NGHTTP2_DATA_FLAG_EOF;
       if (noEndStream)
         *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;

       if (val > 0) {
         CHECK_LE(val, length);
         SPREAD_ARG(buffer, ts_obj);
         memcpy(buf, ts_obj_data, val);
         return val;
       } else if (val == 0) {
         return 0;
       } else {
         // TODO: perhaps something else would be better?
         return val;
       }

     }

     Http2DataProvider(Environment* env,
                       v8::Local<v8::Object> wrap,
                       Http2Stream* stream) :
                       BaseObject(env, wrap),
                       stream_(stream) {
        Wrap(object(), this);
        provider_.read_callback = on_read;
        provider_.source.ptr = this;
     }

     ~Http2DataProvider() {}

     Http2Stream* stream_;
     nghttp2_data_provider provider_;
  };

  // -----------------------------------------------------------------//

  void Http2DataProvider::New(const FunctionCallbackInfo<Value>& args) {
    CHECK(args.IsConstructCall());
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 1);
    Http2Stream* stream;
    ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());
    new Http2DataProvider(env, args.This(), stream);
  }

  void Http2Header::New(const FunctionCallbackInfo<Value>& args) {
    CHECK(args.IsConstructCall());
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 2);
    Utf8Value key(env->isolate(), args[0].As<String>());
    Utf8Value value(env->isolate(), args[1].As<String>());
    new Http2Header(env, args.This(),
                   *key, key.length(),
                   *value, value.length());
  }

  void Http2Stream::GetID(Local<String> property,
                          const PropertyCallbackInfo<Value>& args) {
    Http2Stream* stream;
    ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
    Environment* env = stream->env();
    args.GetReturnValue().Set(Integer::New(env->isolate(), stream->stream_id_));
  }

  void Http2Stream::RemoveStream(Http2Stream* stream) {
    // stream->prev_->next_ = stream->next_;
    // if (stream->next_)
    //   stream->next_->prev_ = stream->prev_;
  }

  void Http2Stream::AddStream(Http2Stream* stream, Http2Session* session) {
    // stream->next_ = session->root_->next_;
    // session->root_->next_ = stream;
    // stream->prev_ = session->root_;
    // if (stream->next_ != nullptr) {
    //   stream->next_->prev_ = stream;
    // }
  }

  /**
   * Creates a new instance of Http2Session. Must be called as a constructor
   * (e.g. new Http2Session([type = 0])).
   * Arguments:
   *   type {integer} 0 (SERVER), 1 (CLIENT)
   * Returns:
   *   
   * Aborts if any other value is given for type.
   **/
  void Http2Session::New(const FunctionCallbackInfo<Value>& args) {
    CHECK(args.IsConstructCall());
    Environment* env = Environment::GetCurrent(args);
    enum http2_session_type type =
        static_cast<enum http2_session_type>(args[0]->Int32Value());
    CHECK(type == SERVER || type == CLIENT);
    new Http2Session(env, args.This(), type);
  }

  /**
   * Get the Http2Session type.
   * Any passed arguments will be ignored.
   * Returns 0 (SERVER), 1 (CLIENT), or -1 (INVALID, after destroy())
   **/
  void Http2Session::GetType(const FunctionCallbackInfo<Value>& args) {
    Environment* env = Environment::GetCurrent(args);
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    if (session->session_ == nullptr)
      args.GetReturnValue().Set(Integer::New(env->isolate(), -1));
    else
      args.GetReturnValue().Set(Integer::New(env->isolate(), session->type_));
  }

  /**
   * Destroys the underlying nghttp2_session so that it can no longer
   * be used and all associated memory is freed. After calling this,
   * The Http2Session object will no longer be usable and calls to any
   * of the methods except GetType() will abort. GetType() will return -1
   * Any passed arguments will be ignored.
   * Returns undefined.
   * Has no effect if the session has already been destroyed.
   **/
  void Http2Session::Destroy(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    nghttp2_session_del(session->session_);
    session->session_ = nullptr;
  }

  /**
   * Causes the session to be terminated but not destroyed. Termination here
   * means sending the GOAWAY frame to the connected peer. This will not
   * interrupt existing streams, which will be allowed to complete, but will
   * half-close the connection so that any new frames/streams cannot be
   * created. Destroy() must be called to actually tear down the session and
   * free resources.
   * Arguments:
   *   code {Integer} The goaway code, if any 
   * Returns undefined if successfull, Error if not
   * Aborts if the session has been destroyed.
   **/
  void Http2Session::Terminate(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);

    uint32_t error_code = args[0]->Uint32Value();
    // TODO: last processed stream id?

    int rv = nghttp2_session_terminate_session(session->session_, error_code);
    if (rv != 0) {
      // TODO: Better error message
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
    // TODO: Do anything after this?
  }

  /**
   * Change the priority of the given stream
   * Arguments:
   *   stream {Integer} The Stream ID
   *   parent {Integer} The parent Stream ID
   *   weight {Integer} The weight
   *   exclusive {Boolean} true or false
   * Returns undefined if successful, Error if not
   * Aborts if the session has been destroyed or streamID is not given
   **/
  void Http2Session::ChangeStreamPriority(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);

    Environment* env = Environment::GetCurrent(args);
    int32_t stream = args[0]->Int32Value();
    int32_t parent = 0;      // Root Stream
    int32_t weight = 16;     // Default Weight
    bool exclusive = false;  // Non-Exclusive

    int argslen = args.Length();
    if (argslen > 1)
      parent = args[1]->Int32Value();
    if (argslen > 2)
      weight = args[2]->Int32Value();
    if (argslen > 3)
      exclusive = args[3]->BooleanValue();

    nghttp2_priority_spec pri_spec;
    nghttp2_priority_spec_init(&pri_spec, parent, weight, exclusive);
    int rv = nghttp2_session_change_stream_priority(session->session_,
                                                    stream,
                                                    &pri_spec);
    if (rv != 0) {
      // TODO: Better error message.
      // if rv == -501 == Invalid Arguments... what to do?
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  /**
   * Arguments
   *  stream {integer}
   *  size (integer)
   * Returns undefined if successful, Error if not
   * Aborts if session is null or not enough arguments are passed
   */
  void Http2Session::Consume(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 2);
    int32_t stream = args[0]->Int32Value();
    size_t size = args[1]->Uint32Value();

    int rv = nghttp2_session_consume(session->session_, stream, size);
    if (rv != 0) {
      // TODO: Better error message.
      // if rv == -501 == Invalid Arguments... what to do?
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  /**
   * Arguments
   *  size (integer)
   * Returns undefined if successful, Error if not
   * Aborts if session is null or not enough arguments are passed
   */
  void Http2Session::ConsumeSession(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 1);
    size_t size = args[0]->Uint32Value();

    int rv = nghttp2_session_consume_connection(session->session_, size);
    if (rv != 0) {
      // TODO: Better error message.
      // if rv == -501 == Invalid Arguments... what to do?
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  /**
   * Arguments
   *  stream {integer}
   *  size (integer)
   * Returns undefined if successful, Error if not
   * Aborts if session is null or not enough arguments are passed
   */
  void Http2Session::ConsumeStream(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 2);
    int32_t stream = args[0]->Int32Value();
    size_t size = args[1]->Uint32Value();

    int rv = nghttp2_session_consume_stream(session->session_, stream, size);
    if (rv != 0) {
      // TODO: Better error message.
      // if rv == -501 == Invalid Arguments... what to do?
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  /**
   * Arguments:
   *  stream {integer} optional
   * Aborts if session is null
   **/
  void Http2Session::GetEffectiveLocalWindowSize(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    int32_t stream = 0;
    if (args.Length() > 0)
      stream = args[0]->Int32Value();
    Environment* env = Environment::GetCurrent(args);
    int32_t size = stream > 0 ?
        nghttp2_session_get_stream_effective_local_window_size(
            session->session_, stream) :
        nghttp2_session_get_effective_local_window_size(session->session_);
    args.GetReturnValue().Set(Integer::New(env->isolate(), size));
  }

  /**
   * No arguments, Returns an integer
   * Aborts if session is null
   **/
  void Http2Session::GetEffectiveRecvDataLength(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    int32_t stream = 0;
    if (args.Length() > 0)
      stream = args[0]->Int32Value();
    Environment* env = Environment::GetCurrent(args);
    int32_t size = stream > 0 ?
        nghttp2_session_get_stream_effective_recv_data_length(session->session_,
                                                              stream) :
        nghttp2_session_get_effective_recv_data_length(session->session_);
    args.GetReturnValue().Set(Integer::New(env->isolate(), size));
  }

  /**
   * No arguments, Returns an integer
   * Aborts if session is null
   **/
  void Http2Session::GetLastProcStreamID(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    int32_t size =
        nghttp2_session_get_last_proc_stream_id(session->session_);
    args.GetReturnValue().Set(Integer::New(env->isolate(), size));
  }

  /**
   * No arguments, Returns an integer
   * Aborts if session is null
   **/
  void Http2Session::GetNextStreamID(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    int32_t size =
        nghttp2_session_get_next_stream_id(session->session_);
    args.GetReturnValue().Set(Integer::New(env->isolate(), size));
  }

  /**
   * No arguments, Returns an integer
   * Aborts if session is null
   **/
  void Http2Session::GetOutboundQueueSize(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    int32_t size =
        nghttp2_session_get_outbound_queue_size(session->session_);
    args.GetReturnValue().Set(Integer::New(env->isolate(), size));
  }

  /**
   * No arguments, Returns an integer
   * Aborts if session is null
   **/
  void Http2Session::GetRemoteWindowSize(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    int32_t stream = 0;
    if (args.Length() > 0)
      stream = args[0]->Int32Value();
    Environment* env = Environment::GetCurrent(args);
    int32_t size = stream > 0 ?
        nghttp2_session_get_stream_remote_window_size(session->session_,
                                                      stream) :
        nghttp2_session_get_remote_window_size(session->session_);
    args.GetReturnValue().Set(Integer::New(env->isolate(), size));
  }

  void Http2Session::GetStreamLocalClose(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    int32_t stream = 0;
    if (args.Length() > 0)
      stream = args[0]->Int32Value();
    Environment* env = Environment::GetCurrent(args);
    int ret = nghttp2_session_get_stream_local_close(session->session_,
                                                     stream);
    args.GetReturnValue().Set(Integer::New(env->isolate(), ret));
  }

  void Http2Session::GetStreamRemoteClose(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    int32_t stream = 0;
    if (args.Length() > 0)
      stream = args[0]->Int32Value();
    Environment* env = Environment::GetCurrent(args);
    int ret = nghttp2_session_get_stream_remote_close(session->session_,
                                                     stream);
    args.GetReturnValue().Set(Integer::New(env->isolate(), ret));
  }

  /**
   * Arguments:
   *  stream {integer}
   *  size {integer}
   *  Returns undefined if successful, Error if not
   * Aborts if session is null or not enough arguments are passed
   */
  void Http2Session::SetLocalWindowSize(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 2);
    int32_t stream = args[0]->Int32Value();
    int32_t size = args[1]->Int32Value();
    int rv = nghttp2_session_set_local_window_size(session->session_,
                                                   NGHTTP2_FLAG_NONE,
                                                   stream, size);
    if (rv != 0) {
     // TODO: Better error message.
     // if rv == -501 == Invalid Arguments... what to do?
     Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
     Local<Object> obj = e->ToObject(env->isolate());
     obj->Set(env->code_string(), ERROR_STR(rv));
     args.GetReturnValue().Set(e);
    }
  }

  /**
   * Manually sets the id for the next stream
   * Arguments:
   *  stream {integer}
   *  Returns undefined if successful, Error if not
   * Aborts if session is null or not enough arguments are passed
   */
  void Http2Session::SetNextStreamID(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    CHECK_GE(args.Length(), 1);
    int32_t stream = args[0]->Int32Value();
    int rv = nghttp2_session_set_next_stream_id(session->session_, stream);
    if (rv != 0) {
     // TODO: Better error message.
     // if rv == -501 == Invalid Arguments... what to do?
     Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
     Local<Object> obj = e->ToObject(env->isolate());
     obj->Set(env->code_string(), ERROR_STR(rv));
     args.GetReturnValue().Set(e);
    }
  }

  /**
   * Arguments:
   *  settings ID {integer}
   *  Returns undefined if successful, Error if not
   * Aborts if session is null or not enough arguments are passed
   */
  void Http2Session::GetRemoteSetting(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    CHECK_GE(args.Length(), 1);
    Environment* env = Environment::GetCurrent(args);
    nghttp2_settings_id id =
        static_cast<nghttp2_settings_id>(args[0]->Int32Value());
    uint32_t val = nghttp2_session_get_remote_settings(session->session_, id);
    args.GetReturnValue().Set(Integer::New(env->isolate(), val));
  }

  /**
   * Arguments
   *  stream {integer}
   *  parent (integer)
   *  weight {integer}
   *  exclusive {boolean}
   **/
  void Http2Session::CreateIdleStream(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    const int argslen = args.Length();
    CHECK_GE(argslen, 1);
    int32_t stream = args[0]->Int32Value();
    int32_t parent = -1;
    int32_t weight = 16;
    bool exclusive = false;

    if (argslen > 1)
      parent = args[1]->Int32Value();
    if (argslen > 2)
      weight = args[2]->Int32Value();
    if (argslen > 3)
      exclusive = args[3]->BooleanValue();

    if (parent == -1) parent = stream;

    nghttp2_priority_spec pri_spec;
    nghttp2_priority_spec_init(&pri_spec, parent, weight, exclusive);
    int rv;
    rv = nghttp2_session_create_idle_stream(session->session_,
                                            stream,
                                            &pri_spec);
    if (rv != 0) {
     // TODO: Better error message.
     // if rv == -501 == Invalid Arguments... what to do?
     Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
     Local<Object> obj = e->ToObject(env->isolate());
     obj->Set(env->code_string(), ERROR_STR(rv));
     args.GetReturnValue().Set(e);
    }
  }
  
  void Http2Session::GetStreamState(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    CHECK_GE(args.Length(), 1);
    Environment* env = Environment::GetCurrent(args);
    int32_t stream = args[0]->Int32Value();
    nghttp2_stream* stream_ = nghttp2_session_find_stream(session->session_,
                                                          stream);
    int state = -1;
    if (stream_ != nullptr) {
      state = static_cast<int>(nghttp2_stream_get_state(stream_));
    }
    args.GetReturnValue().Set(Integer::New(env->isolate(), state));
  }

  void Http2Session::GetStreamWeight(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    CHECK_GE(args.Length(), 1);
    Environment* env = Environment::GetCurrent(args);
    int32_t stream = args[0]->Int32Value();
    bool dependencies = false;
    if (args.Length() > 1)
      dependencies = args[1]->BooleanValue();
    int32_t weight = 0;
    nghttp2_stream* stream_ = nghttp2_session_find_stream(session->session_,
                                                          stream);
    if (stream_ != nullptr) {
      weight = dependencies ?
        nghttp2_stream_get_sum_dependency_weight(stream_) :
        nghttp2_stream_get_weight(stream_);
    }
    args.GetReturnValue().Set(Integer::New(env->isolate(), weight));
  }

  void Http2Session::SendServerConnectionHeader(
      const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);

    // TODO: Get the settings somehow
    nghttp2_settings_entry iv[1] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    int rv;

    rv = nghttp2_submit_settings(session->session_,
                                 NGHTTP2_FLAG_NONE,
                                 iv, ARRLEN(iv));
    if (rv != 0) {
      // TODO: Better error message.
      // if rv == -501 == Invalid Arguments... what to do?
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  void Http2Session::ReceiveData(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    CHECK_GE(args.Length(), 1);

    Environment* env = Environment::GetCurrent(args);
    THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
    SPREAD_ARG(args[0], ts_obj);

    uint8_t* data = reinterpret_cast<uint8_t*>(ts_obj_data);

    ssize_t readlen;

    readlen = nghttp2_session_mem_recv(session->session_,
                                       data,
                                       ts_obj_length);

    if (readlen < 0) {
      // what is a good error to return?
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(readlen));
      args.GetReturnValue().Set(e);
    }
  }

  void Http2Session::SendData(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    int rv = nghttp2_session_send(session->session_);
    if (rv != 0) {
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }
  
  void Http2Session::RstStream(const FunctionCallbackInfo<Value>& args) {
  }

  void Http2Session::Respond(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    Isolate* isolate = env->isolate();

    Http2Stream* stream;
    nghttp2_data_provider* provider;
    ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());
    std::vector<nghttp2_nv> headers;

    if (args.Length() > 1) {
      // args[1], if given, must be an array of Http2Header objects
      CHECK(args[1]->IsArray());
      Local<Array> headers_array = args[1].As<Array>();
      int length = headers_array->Length();
      for (int i = 0; i < length; i++) {
        Local<Value> val = headers_array->Get(i);
        CHECK(val->IsObject());
        Http2Header* header;
        ASSIGN_OR_RETURN_UNWRAP(&header, val.As<Object>());
        headers.push_back(**header);
      }
    }
    if (args.Length() > 2) {
      // args[2], if given, must be a Http2DataProvider object
      CHECK(args[2]->IsObject());
      Http2DataProvider* dataProvider;
      ASSIGN_OR_RETURN_UNWRAP(&dataProvider, args[2].As<Object>());
      provider = **dataProvider;
    }

    int rv = nghttp2_submit_response(session->session_,
                                     stream->stream_id_,
                                     &headers[0],
                                     headers.size(), 
                                     provider);
    
    if (rv != 0) {
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  void Http2Session::SendContinue(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    Isolate* isolate = env->isolate();

    Http2Stream* stream;
    ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());

    nghttp2_nv headers[] {
      MAKE_NV(":status", "100")
    };

    int rv = nghttp2_submit_headers(session->session_,
                                    NGHTTP2_FLAG_NONE,
                                    stream->stream_id_,
                                    nullptr,
                                    &headers[0], 1, nullptr);
    if (rv != 0) {
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  void Http2Session::ResumeData(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    Isolate* isolate = env->isolate();

    Http2Stream* stream;
    ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());

    nghttp2_nv headers[] {
      MAKE_NV(":status", "100")
    };

    int rv = nghttp2_session_resume_data(session->session_,
                                         stream->stream_id_);
    if (rv != 0) {
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }
  }

  void Http2Session::SendTrailers(const FunctionCallbackInfo<Value>& args) {
    Http2Session* session;
    ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
    CHECK_NE(session->session_, nullptr);
    Environment* env = Environment::GetCurrent(args);
    Isolate* isolate = env->isolate();

    Http2Stream* stream;
    ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());

    std::vector<nghttp2_nv> headers;

    if (args.Length() > 1) {
      // args[1], if given, must be an array of Http2Header objects
      CHECK(args[1]->IsArray());
      Local<Array> headers_array = args[1].As<Array>();
      int length = headers_array->Length();
      for (int i = 0; i < length; i++) {
        Local<Value> val = headers_array->Get(i);
        CHECK(val->IsObject());
        Http2Header* header;
        ASSIGN_OR_RETURN_UNWRAP(&header, val.As<Object>());
        headers.push_back(**header);
      }
    }

    int rv = nghttp2_submit_headers(session->session_,
                                    NGHTTP2_FLAG_END_STREAM,
                                    stream->stream_id_,
                                    nullptr,
                                    &headers[0], 1, nullptr);
    if (rv != 0) {
      Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
      Local<Object> obj = e->ToObject(env->isolate());
      obj->Set(env->code_string(), ERROR_STR(rv));
      args.GetReturnValue().Set(e);
    }

  }

  // ----------------------------------------------------------------------//

  void InitHttp2(Local<Object> target,
                  Local<Value> unused,
                  Local<Context> context,
                  void* priv) {
    Environment* env = Environment::GetCurrent(context);
    Isolate* isolate = env->isolate();

    Local<FunctionTemplate> provider =
        env->NewFunctionTemplate(Http2DataProvider::New);
    provider->InstanceTemplate()->SetInternalFieldCount(1);
    provider->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "Http2DataProvider"));
    target->Set(FIXED_ONE_BYTE_STRING(isolate, "Http2DataProvider"),
                provider->GetFunction());

    Local<FunctionTemplate> header =
        env->NewFunctionTemplate(Http2Header::New);
    header->InstanceTemplate()->SetInternalFieldCount(1);
    header->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "Http2Header"));
    target->Set(FIXED_ONE_BYTE_STRING(isolate, "Http2Header"),
                header->GetFunction());

    Local<FunctionTemplate> t =
        env->NewFunctionTemplate(Http2Session::New);
    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "Http2Session"));

    env->SetProtoMethod(t, "getType",
                        Http2Session::GetType);
    env->SetProtoMethod(t, "destroy",
                        Http2Session::Destroy);
    env->SetProtoMethod(t, "terminate",
                        Http2Session::Terminate);
    env->SetProtoMethod(t, "changeStreamPriority",
                        Http2Session::ChangeStreamPriority);
    env->SetProtoMethod(t, "consume",
                        Http2Session::Consume);
    env->SetProtoMethod(t, "consumeSession",
                        Http2Session::ConsumeSession);
    env->SetProtoMethod(t, "consumeStream",
                        Http2Session::ConsumeStream);
    env->SetProtoMethod(t, "getEffectiveLocalWindowSize",
                        Http2Session::GetEffectiveLocalWindowSize);
    env->SetProtoMethod(t, "getEffectiveRecvDataLength",
                        Http2Session::GetEffectiveRecvDataLength);
    env->SetProtoMethod(t, "getLastProcStreamID",
                        Http2Session::GetLastProcStreamID);
    env->SetProtoMethod(t, "getNextStreamID",
                        Http2Session::GetNextStreamID);
    env->SetProtoMethod(t, "getOutboundQueueSize",
                        Http2Session::GetOutboundQueueSize);
    env->SetProtoMethod(t, "getRemoteWindowSize",
                        Http2Session::GetRemoteWindowSize);
    env->SetProtoMethod(t, "setLocalWindowSize",
                        Http2Session::SetLocalWindowSize);
    env->SetProtoMethod(t, "setNextStreamID",
                        Http2Session::SetNextStreamID);
    env->SetProtoMethod(t, "getRemoteSetting",
                        Http2Session::GetRemoteSetting);
    env->SetProtoMethod(t, "createIdleStream",
                        Http2Session::CreateIdleStream);
    env->SetProtoMethod(t, "getStreamLocalClose",
                        Http2Session::GetStreamLocalClose);
    env->SetProtoMethod(t, "getStreamRemoteClose",
                        Http2Session::GetStreamRemoteClose);
    env->SetProtoMethod(t, "getStreamState",
                        Http2Session::GetStreamState);
    env->SetProtoMethod(t, "getStreamWeight",
                        Http2Session::GetStreamWeight);
    env->SetProtoMethod(t, "sendServerConnectionHeader",
                        Http2Session::SendServerConnectionHeader);
    env->SetProtoMethod(t, "receiveData",
                        Http2Session::ReceiveData);
    env->SetProtoMethod(t, "sendData",
                        Http2Session::SendData);
    env->SetProtoMethod(t, "rstStream",
                        Http2Session::RstStream);
    env->SetProtoMethod(t, "respond",
                        Http2Session::Respond);
    env->SetProtoMethod(t, "continue", Http2Session::SendContinue);
    env->SetProtoMethod(t, "resume", Http2Session::ResumeData);
    env->SetProtoMethod(t, "sendTrailers", Http2Session::SendTrailers);

    PROPERTY(t, isolate, INVALID);
    PROPERTY(t, isolate, SERVER);
    PROPERTY(t, isolate, CLIENT);
    PROPERTY(t, isolate, kOnSend);
    PROPERTY(t, isolate, kOnStreamClose);
    PROPERTY(t, isolate, kOnHeaders);
    PROPERTY(t, isolate, kOnData);
    PROPERTY(t, isolate, kOnGoaway);
    PROPERTY(t, isolate, kOnSettings);
    PROPERTY(t, isolate, kOnRstStream);
    PROPERTY(t, isolate, kOnPriority);
    PROPERTY(t, isolate, kOnPing);
    PROPERTY(t, isolate, kOnDataChunk);
    PROPERTY(t, isolate, kOnHeader);
    PROPERTY(t, isolate, kOnFrameSend);
    PROPERTY(t, isolate, kOnBeginHeaders);
    PROPERTY(t, isolate, kFlagEndStream);
    PROPERTY(t, isolate, kFlagEndData);
    PROPERTY(t, isolate, kFlagNoEndStream);

    target->Set(FIXED_ONE_BYTE_STRING(isolate, "Http2Session"),
                t->GetFunction());
  }

}  // namespace http2

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(http2, node::http2::InitHttp2)
