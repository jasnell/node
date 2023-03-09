#include "http3.h"
#include "bindingdata-inl.h"
#include "defs.h"
#include "session-inl.h"
#include "sessionticket.h"
#include "streams-inl.h"
#include "util-inl.h"
#include <async_wrap-inl.h>
#include <base_object-inl.h>
#include <debug_utils-inl.h>
#include <env-inl.h>
#include <memory_tracker-inl.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <node_http_common-inl.h>
#include <node_mem-inl.h>
#include <util.h>
#include <v8.h>

namespace node {

using v8::Just;
using v8::Local;
using v8::Maybe;

namespace quic {

// ======================================================================================
// Http3RcBufferPointerTraits

void Http3RcBufferPointerTraits::inc(rcbuf_t* buf) {
  nghttp3_rcbuf_incref(buf);
}

void Http3RcBufferPointerTraits::dec(rcbuf_t* buf) {
  nghttp3_rcbuf_decref(buf);
}

Http3RcBufferPointerTraits::vector_t Http3RcBufferPointerTraits::get_vec(
    const rcbuf_t* buf) {
  return nghttp3_rcbuf_get_buf(buf);
}

bool Http3RcBufferPointerTraits::is_static(const rcbuf_t* buf) {
  return nghttp3_rcbuf_is_static(buf);
}

// nghttp3 uses a numeric identifier for a large number of known HTTP header
// names. These allow us to use static strings for those rather than allocating
// new strings all of the time. The list of strings supported is included in
// node_http_common.h
#define V1(name, value)                                                        \
  case NGHTTP3_QPACK_TOKEN__##name:                                            \
    return value;
#define V2(name, value)                                                        \
  case NGHTTP3_QPACK_TOKEN_##name:                                             \
    return value;
const char* Http3HeaderTraits::ToHttpHeaderName(int32_t token) {
  switch (token) {
    default:
      // Fall through
    case -1:
      return nullptr;
      HTTP_SPECIAL_HEADERS(V1)
      HTTP_REGULAR_HEADERS(V2)
  }
}
#undef V1
#undef V2

// ======================================================================================
// Http3Application

Http3Application::Http3Application(Session* session, const Options& options)
    : Session::Application(session, options),
      alloc_info_(BindingData::Get(session->env())) {
  session->state_->priority_supported = 1;
}

void Http3Application::CreateConnection() {
  nghttp3_conn* conn;

  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.max_field_section_size = options().max_field_section_size;
  settings.qpack_blocked_streams = options().qpack_blocked_streams;
  settings.qpack_encoder_max_dtable_capacity =
      options().qpack_encoder_max_dtable_capacity;
  settings.qpack_max_dtable_capacity = options().qpack_max_dtable_capacity;

  switch (session().crypto_context().side()) {
    case CryptoContext::Side::CLIENT:
      CHECK_EQ(nghttp3_conn_client_new(
                   &conn, &callbacks_, &settings, &alloc_info_, this),
               0);
      break;
    case CryptoContext::Side::SERVER:
      CHECK_EQ(nghttp3_conn_server_new(
                   &conn, &callbacks_, &settings, &alloc_info_, this),
               0);
      break;
  }

  CHECK_NOT_NULL(conn);
  connection_.reset(conn);
}

bool Http3Application::is_control_stream(stream_id id) const {
  return id == control_stream_id_ ||
         id == qpack_dec_stream_id_ ||
         id == qpack_enc_stream_id_;
}

bool Http3Application::Start() {
  // The Session must allow for at least three local unidirectional streams.
  // This number is fixed by the http3 specification and represent the control
  // stream and two qpack management streams.
  if (session().max_local_streams_uni() < 3) return false;

  CreateConnection();

  if (session().is_server()) {
    nghttp3_conn_set_max_client_streams_bidi(
        connection_.get(), session().max_local_streams_bidi());
  }

  return CreateAndBindControlStream() && CreateAndBindQPackStreams();
}

bool Http3Application::ReceiveStreamData(Stream* stream,
                                         ReceiveStreamDataFlags flags,
                                         const uint8_t* data,
                                         size_t datalen,
                                         uint64_t offset) {
  ssize_t nread = nghttp3_conn_read_stream(
      connection_.get(), stream->id(), data, datalen, flags.fin ? 1 : 0);

  if (nread < 0) return false;

  session().ExtendStreamOffset(stream->id(), nread);
  session().ExtendOffset(nread);

  return true;
}

void Http3Application::AcknowledgeStreamData(Stream* stream,
                                             uint64_t offset,
                                             size_t datalen) {
  USE(nghttp3_conn_add_ack_offset(connection_.get(), stream->id(), datalen));
}

void Http3Application::SetStreamPriority(Stream* stream,
                                         StreamPriority priority,
                                         StreamPriorityFlags flags) {
  if (stream->direction() == Direction::BIDIRECTIONAL &&
      stream->origin() == CryptoContext::Side::CLIENT) {
    nghttp3_pri pri = {
        /* .urgency = */ static_cast<uint32_t>(priority),
        /* .inc = */ flags == StreamPriorityFlags::NON_INCREMENTAL ? 0 : 1,
    };
    CHECK_EQ(nghttp3_conn_set_stream_priority(*this, stream->id(), &pri),
             0);
  }
}

Session::Application::StreamPriority Http3Application::GetStreamPriority(
    Stream* stream) {
  // nghttp3 requires that the get_stream_priority function can only be called
  // by the server.
  if (!session().is_server()) return StreamPriority::DEFAULT;

  nghttp3_pri pri;
  CHECK_EQ(nghttp3_conn_get_stream_priority(*this, &pri, stream->id()),
           0);
  // We're only interested in the urgency field. The incremental flag is only
  // relevant when setting.
  return static_cast<StreamPriority>(pri.urgency);
}

bool Http3Application::CanAddHeader(size_t current_count,
                                    size_t current_headers_length,
                                    size_t this_header_length) {
  // We cannot add the header if we've either reached
  // * the max number of header pairs or
  // * the max number of header bytes
  return current_count < options().max_header_pairs &&
         current_headers_length + this_header_length <=
             options().max_header_length;
}

void Http3Application::BlockStream(stream_id id) {
  nghttp3_conn_block_stream(connection_.get(), id);
  Application::BlockStream(id);
}

void Http3Application::ExtendMaxStreams(EndpointLabel label,
                                        Direction direction,
                                        uint64_t max_streams) {
  switch (label) {
    case EndpointLabel::LOCAL: {
      return;
    }
    case EndpointLabel::REMOTE: {
      switch (direction) {
        case Direction::BIDIRECTIONAL:
          ngtcp2_conn_extend_max_streams_bidi(session(), max_streams);
          return;
        case Direction::UNIDIRECTIONAL:
          ngtcp2_conn_extend_max_streams_uni(session(), max_streams);
          return;
      }
      UNREACHABLE();
    }
  }
  UNREACHABLE();
}

void Http3Application::ExtendMaxStreamData(Stream* stream, uint64_t max_data) {
  nghttp3_conn_unblock_stream(connection_.get(), stream->id());
}

void Http3Application::ResumeStream(stream_id id) {
  nghttp3_conn_resume_stream(connection_.get(), id);
}

void Http3Application::CollectSessionTicketAppData(
    SessionTicket::AppData* app_data) const {
  // There's currently nothing to store but we might do so later.
}

SessionTicket::AppData::Status Http3Application::ExtractSessionTicketAppData(
    const SessionTicket::AppData& app_data,
    SessionTicket::AppData::Flag flag) {
  // There's currently nothing stored here but we might do so later.
  return flag == SessionTicket::AppData::Flag::STATUS_RENEW
             ? SessionTicket::AppData::Status::TICKET_USE_RENEW
             : SessionTicket::AppData::Status::TICKET_USE;
}

void Http3Application::StreamClose(Stream* stream, QuicError error) {
  error_code code = NGHTTP3_H3_NO_ERROR;
  if (error) {
    CHECK_EQ(error.type(), QuicError::Type::APPLICATION);
    code = error.code();
  }

  int rv = nghttp3_conn_close_stream(connection_.get(), stream->id(), code);
  // If the call is successful, Http3Application::OnStreamClose callback will
  // be invoked when the stream is ready to be closed. We'll handle destroying
  // the actual Stream object there.
  if (rv == 0) return;

  switch (rv) {
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
      ExtendMaxStreams(EndpointLabel::REMOTE, stream->direction(), 1);
      return;
  }

  session().SetLastError(
      QuicError::ForApplication(nghttp3_err_infer_quic_app_error_code(rv)));
  session().Close();
}

void Http3Application::StreamReset(Stream* stream,
                                   uint64_t final_size,
                                   QuicError error) {
  // We are shutting down the readable side of the local stream here.
  CHECK_EQ(nghttp3_conn_shutdown_stream_read(connection_.get(), stream->id()),
           0);
  stream->ReceiveResetStream(final_size, error);
}

void Http3Application::StreamStopSending(Stream* stream, QuicError error) {
  stream->ReceiveStopSending(error);
}

bool Http3Application::SendHeaders(stream_id id,
                                   HeadersKind kind,
                                   const v8::Local<v8::Array>& headers,
                                   HeadersFlags flags) {
  Session::SendPendingDataScope send_scope(&session());
  Http3Headers nva(env(), headers);

  switch (kind) {
    case HeadersKind::INFO: {
      return nghttp3_conn_submit_info(
                 connection_.get(), id, nva.data(), nva.length()) == 0;
      break;
    }
    case HeadersKind::INITIAL: {
      static constexpr nghttp3_data_reader reader = {
          Http3Application::on_read_data};
      const nghttp3_data_reader* reader_ptr = nullptr;

      // If the terminal flag is set, that means that we
      // know we're only sending headers and no body and
      // the stream should writable side should be closed
      // immediately because there is no nghttp3_data_reader
      // provided.
      if (flags != HeadersFlags::TERMINAL) reader_ptr = &reader;

      if (session().is_server()) {
        return nghttp3_conn_submit_response(
            connection_.get(), id, nva.data(), nva.length(), reader_ptr);
      } else {
        return nghttp3_conn_submit_request(connection_.get(),
                                           id,
                                           nva.data(),
                                           nva.length(),
                                           reader_ptr,
                                           nullptr) == 0;
      }
      break;
    }
    case HeadersKind::TRAILING: {
      return nghttp3_conn_submit_trailers(
                 connection_.get(), id, nva.data(), nva.length()) == 0;
      break;
    }
  }

  return false;
}

bool Http3Application::ShouldSetFin(const StreamData& stream_data) {
  return stream_data.id > -1 && !is_control_stream(stream_data.id) &&
         stream_data.fin == 1;
}

int Http3Application::GetStreamData(StreamData* stream_data) {
  ssize_t ret = 0;
  if (connection_ && session().max_data_left()) {
    ret = nghttp3_conn_writev_stream(
        connection_.get(),
        &stream_data->id,
        &stream_data->fin,
        reinterpret_cast<nghttp3_vec*>(stream_data->data),
        sizeof(stream_data->data));
    if (ret < 0) {
      return static_cast<int>(ret);
    } else {
      stream_data->remaining = stream_data->count = static_cast<size_t>(ret);
    }
  }
  return 0;
}

bool Http3Application::StreamCommit(StreamData* stream_data, size_t datalen) {
  int err = nghttp3_conn_add_write_offset(
      connection_.get(), stream_data->id, datalen);
  if (err != 0) {
    session().SetLastError(
        QuicError::ForApplication(nghttp3_err_infer_quic_app_error_code(err)));
    return false;
  }
  return true;
}

BaseObjectPtr<Stream> Http3Application::FindOrCreateStream(
    stream_id id, void* stream_user_data) {
  if (stream_user_data != nullptr) {
    return BaseObjectPtr<Stream>(static_cast<Stream*>(stream_user_data));
  }

  auto stream = session().FindStream(id);
  if (!stream) {
    if (!session().can_create_streams()) return BaseObjectPtr<Stream>();

    stream = session().CreateStream(id);
    if (LIKELY(stream))
      nghttp3_conn_set_stream_user_data(connection_.get(), id, stream.get());
  }

  CHECK(stream);
  return stream;
}

bool Http3Application::CreateAndBindControlStream() {
  auto stream = session().OpenStream(Direction::UNIDIRECTIONAL);
  if (!stream) return false;
  return nghttp3_conn_bind_control_stream(connection_.get(), stream->id()) == 0;
}

bool Http3Application::CreateAndBindQPackStreams() {
  auto enc_stream = session().OpenStream(Direction::UNIDIRECTIONAL);
  if (!enc_stream) return false;

  auto dec_stream = session().OpenStream(Direction::UNIDIRECTIONAL);
  if (!dec_stream) return false;

  return nghttp3_conn_bind_qpack_streams(connection_.get(),
                                         qpack_enc_stream_id_,
                                         qpack_dec_stream_id_) == 0;
}

ssize_t Http3Application::ReadData(stream_id id,
                                   nghttp3_vec* vec,
                                   size_t veccnt,
                                   uint32_t* pflags) {
  BaseObjectPtr<Stream> stream = session().FindStream(id);

  // This case really shouldn't happen but we're going to safely handle it
  // anyway just in case. We interpret the lack of a stream as a stream that has
  // been closed. The only way to get here would be if the stream was never
  // created or the stream was destroyed, in either case, there's no data.
  if (!stream) {
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }

  ssize_t ret = NGHTTP3_ERR_WOULDBLOCK;

  auto next =
      [&](int status, const ngtcp2_vec* data, size_t count, bob::Done done) {
        CHECK_LE(count, veccnt);

        switch (status) {
          case bob::Status::STATUS_BLOCK:
            // Fall through
          case bob::Status::STATUS_WAIT:
            return;
          case bob::Status::STATUS_EOS:
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            if (UNLIKELY(stream->might_send_trailers())) {
              *pflags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
              // We let the stream know that it can send trailers now. The
              // stream will not be ended until the trailers are sent.
              stream->ReadyForTrailers();
            }
            break;
        }

        ret = count;
        size_t numbytes =
            nghttp3_vec_len(reinterpret_cast<const nghttp3_vec*>(data), count);
        std::move(done)(numbytes);
      };

  CHECK_GE(
      stream->Pull(std::move(next),
                   // Set OPTIONS_END here because nghttp3 takes over
                   // responsibility for ensuring the data all gets written out.
                   bob::Options::OPTIONS_END | bob::Options::OPTIONS_SYNC,
                   reinterpret_cast<ngtcp2_vec*>(vec),
                   veccnt,
                   kMaxVectorCount),
      0);

  return ret;
}

// ======================================================================================
// nghttp3 callbacks
const nghttp3_callbacks Http3Application::callbacks_ = {on_acked_stream_data,
                                                        on_stream_close,
                                                        on_receive_data,
                                                        on_deferred_consume,
                                                        on_begin_headers,
                                                        on_receive_header,
                                                        on_end_headers,
                                                        on_begin_trailers,
                                                        on_receive_trailer,
                                                        on_end_trailers,
                                                        on_stop_sending,
                                                        on_end_stream,
                                                        on_reset_stream,
                                                        on_shutdown};

Http3Application& Http3Application::From(nghttp3_conn* conn, void* conn_user_data) {
  Http3Application* app = static_cast<Http3Application*>(conn_user_data);
  CHECK_EQ(app->connection_.get(), conn);
  return *app;
}

int Http3Application::on_acked_stream_data(nghttp3_conn* conn,
                                        stream_id id,
                                        uint64_t datalen,
                                        void* conn_user_data,
                                        void* stream_user_data) {
  if (stream_user_data == nullptr) return 0;
  auto& app = Http3Application::From(conn, conn_user_data);
  // If we don't find the stream, it either has never been created or was
  // destroyed. In either case, we just ignore the acknowledgement.
  auto stream = app.session().FindStream(id);
  if (stream) app.AcknowledgeStreamData(stream.get(), 0, datalen);
  return 0;
}

int Http3Application::on_stream_close(nghttp3_conn* conn,
                                    stream_id id,
                                    uint64_t app_error_code,
                                    void* conn_user_data,
                                    void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (stream) {
    auto stream = static_cast<Stream*>(stream_user_data);
    auto direction = stream->direction();
    stream->Destroy(QuicError::ForApplication(app_error_code));
    app.ExtendMaxStreams(EndpointLabel::REMOTE, direction, 1);
  }
  return 0;
}

int Http3Application::on_receive_data(nghttp3_conn* conn,
                                    stream_id id,
                                    const uint8_t* data,
                                    size_t datalen,
                                    void* conn_user_data,
                                    void* stream_user_data) {
  // At this point, the QUIC stack should have already created the Stream, so if
  // it's not found here, something has gone wrong (likely the stream was
  // destroyed). Let's not ignore the case and fail the callback if that
  // happens.
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream->ReceiveData(ReceiveStreamDataFlags{}, data, datalen, 0);
  return 0;
}

int Http3Application::on_deferred_consume(nghttp3_conn* conn,
                                        stream_id id,
                                        size_t consumed,
                                        void* conn_user_data,
                                        void* stream_user_data) {
  // This is a notification from nghttp3 to let ngtcp2 know that a certain
  // amount of data has been consumed. ngtcp2 uses this to update internal
  // accounting for flow control.
  auto& app = Http3Application::From(conn, conn_user_data);
  app.session().ExtendStreamOffset(id, consumed);
  app.session().ExtendOffset(consumed);
  return 0;
}

int Http3Application::on_begin_headers(nghttp3_conn* conn,
                                     stream_id id,
                                     void* conn_user_data,
                                     void* stream_user_data) {
  // The QUIC layer should have created the Stream already. If it doesn't exist
  // here, something has gone wrong.
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream->BeginHeaders(HeadersKind::INITIAL);
  return 0;
}

int Http3Application::on_end_headers(nghttp3_conn* conn,
                                   stream_id id,
                                   int fin,
                                   void* conn_user_data,
                                   void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream->EmitHeaders();
  if (fin != 0) {
    // The stream is done. There's no more data to receive!
    stream->ReceiveData(ReceiveStreamDataFlags{/* .fin = */ true,
                                               /* .early = */ false},
                        nullptr,
                        0,
                        0);
  }
  return 0;
}

int Http3Application::on_receive_header(nghttp3_conn* conn,
                                      stream_id id,
                                      int32_t token,
                                      nghttp3_rcbuf* name,
                                      nghttp3_rcbuf* value,
                                      uint8_t flags,
                                      void* conn_user_data,
                                      void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;

  // Protect against zero-length headers (zero-length if either the
  // name or value are zero-length). Such headers are simply ignored.
  if (!Http3Header::IsZeroLength(name, value)) {
    if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
      nghttp3_vec vec = nghttp3_rcbuf_get_buf(value);
      if (vec.base[0] == '1')
        stream->set_headers_kind(HeadersKind::INFO);
      else
        stream->set_headers_kind(HeadersKind::INITIAL);
    }
    stream->AddHeader(
        Http3Header(app.session().env(), token, name, value, flags));
  }
  return 0;
}

int Http3Application::on_begin_trailers(nghttp3_conn* conn,
                                      stream_id id,
                                      void* conn_user_data,
                                      void* stream_user_data) {
  // The QUIC layer should have created the Stream already. If it doesn't exist
  // here, something has gone wrong.
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream->BeginHeaders(HeadersKind::TRAILING);
  return 0;
}

int Http3Application::on_receive_trailer(nghttp3_conn* conn,
                                       stream_id id,
                                       int32_t token,
                                       nghttp3_rcbuf* name,
                                       nghttp3_rcbuf* value,
                                       uint8_t flags,
                                       void* conn_user_data,
                                       void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;

  // Protect against zero-length headers (zero-length if either the
  // name or value are zero-length). Such headers are simply ignored.
  if (!Http3Header::IsZeroLength(name, value))
    stream->AddHeader(
        Http3Header(app.session().env(), token, name, value, flags));
  return 0;
}

int Http3Application::on_end_trailers(nghttp3_conn* conn,
                                    stream_id id,
                                    int fin,
                                    void* conn_user_data,
                                    void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  stream->EmitHeaders();
  if (fin != 0) {
    // The stream is done. There's no more data to receive!
    stream->ReceiveData(ReceiveStreamDataFlags{/* .fin = */ true,
                                               /* .early = */ false},
                        nullptr,
                        0,
                        0);
  }
  return 0;
}

int Http3Application::on_stop_sending(nghttp3_conn* conn,
                                    stream_id id,
                                    error_code app_error_code,
                                    void* conn_user_data,
                                    void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  // This event can be a bit confusing. When this is triggered, we're being
  // asked to *send* a STOP_SENDING frame, not that we received one.
  stream->StopSending(QuicError::ForApplication(app_error_code));
  return 0;
}

int Http3Application::on_reset_stream(nghttp3_conn* conn,
                                    stream_id id,
                                    error_code app_error_code,
                                    void* conn_user_data,
                                    void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;
  // Similar to OnStopSending, this event is not that we *received* a
  // RESET_STREAM frame, we need to send one.
  stream->ResetStream(QuicError::ForApplication(app_error_code));
  return 0;
}

int Http3Application::on_end_stream(nghttp3_conn* conn,
                                  stream_id id,
                                  void* conn_user_data,
                                  void* stream_user_data) {
  auto& app = Http3Application::From(conn, conn_user_data);
  auto stream = app.session().FindStream(id);
  if (!stream) return NGHTTP3_ERR_CALLBACK_FAILURE;

  // This callback is invoked when the receiving side of a stream completes.
  // Specifically, for HTTP requests, this signals completion of the complete
  // HTTP request. For HTTP responses, this signals completion of the complete
  // HTTP response.

  stream->ReceiveData(ReceiveStreamDataFlags{/* .fin = */ true,
                                             /* .early = */ false},
                      nullptr,
                      0,
                      0);

  return 0;
}

int Http3Application::on_shutdown(nghttp3_conn* conn,
                                 stream_id id,
                                 void* conn_user_data) {
  // This callback is invoked when we receive a request to gracefully shutdown
  // the http3 connection. For client, the id is the stream id of a client
  // initiated stream. For server, the id is the stream id of a server initiated
  // stream. Once received, the other side is guaranteed not to process any more
  // data.

  // On the client side, if id is equal to NGHTTP3_SHUTDOWN_NOTICE_STREAM_ID,
  // or on the server if the id is equal to NGHTTP3_SHUSTDOWN_NOTICE_PUSH_ID,
  // then this is a request to begin a graceful shutdown.

  // This can be called multiple times but the id can only stay the same or
  // *decrease*.

  // Need to determine exactly how to handle.

  return 0;
}

ssize_t Http3Application::on_read_data(nghttp3_conn* conn,
                                     stream_id id,
                                     nghttp3_vec* vec,
                                     size_t veccnt,
                                     uint32_t* pflags,
                                     void* conn_user_data,
                                     void* stream_user_data) {
  return Http3Application::From(conn, conn_user_data)
      .ReadData(id, vec, veccnt, pflags);
}

}  // namespace quic
}  // namespace node
