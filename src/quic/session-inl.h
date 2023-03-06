#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "session.h"
#include "cryptocontext-inl.h"

namespace node {
namespace quic {

CryptoContext& Session::crypto_context() { return crypto_context_; }

Session::Application& Session::application() { return *application_; }

const Endpoint& Session::endpoint() const {
  return *endpoint_.get();
}

const SocketAddress& Session::remote_address() const {
  return remote_address_;
}

const SocketAddress& Session::local_address() const {
  return local_address_;
}

bool Session::is_destroyed() const { return state_->destroyed; }

bool Session::is_server() const {
  return crypto_context_.side() == CryptoContext::Side::SERVER;
}

bool Session::is_closing() const {
  return state_->closing;
}

bool Session::is_graceful_closing() const {
  return state_->graceful_closing;
}

BaseObjectPtr<Session::LogStream>& Session::qlogstream() {
  return qlogstream_;
}

BaseObjectPtr<Session::LogStream>& Session::keylogstream() {
  return keylogstream_;
}

void Session::SendPendingData() {
  if (!is_unable_to_send_packets()) application_->SendPendingData();
}

bool Session::can_create_streams() const {
  return !state_->destroyed && !state_->graceful_closing && !state_->closing &&
         !is_in_closing_period() && !is_in_draining_period();
}

bool Session::is_in_closing_period() const {
  return ngtcp2_conn_is_in_closing_period(*this);
}

bool Session::is_in_draining_period() const {
  return ngtcp2_conn_is_in_draining_period(*this);
}

uint64_t Session::max_data_left() const {
  return ngtcp2_conn_get_max_data_left(*this);
}

uint64_t Session::max_local_streams_uni() const {
  return ngtcp2_conn_get_max_local_streams_uni(*this);
}

uint64_t Session::max_local_streams_bidi() const {
  return ngtcp2_conn_get_local_transport_params(*this)
      ->initial_max_streams_bidi;
}

void Session::ExtendOffset(size_t amount) {
  ngtcp2_conn_extend_max_offset(*this, amount);
}

void Session::ExtendStreamOffset(stream_id id, size_t amount) {
  ngtcp2_conn_extend_max_stream_offset(*this, id, amount);
}

quic_version Session::version() const {
  return ngtcp2_conn_get_negotiated_version(*this);
}

void Session::set_wrapped() { state_->wrapped = true; }

const Session::Options& Session::options() const { return options_; }

inline Session::operator ngtcp2_conn*() const {
  CHECK(!is_destroyed());
  return connection_.get();
}

void Session::SetLastError(QuicError&& error) {
  last_error_ = std::move(error);
}

Session::TransportParams::TransportParams(
    Type type,
    const ngtcp2_transport_params* ptr)
    : type_(type), ptr_(ptr) {}

Session::TransportParams::TransportParams(Type type)
    : type_(type), ptr_(&params_) {}

Session::TransportParams::Type Session::TransportParams::type() const {
  return type_;
}

Session::TransportParams::operator const ngtcp2_transport_params& () const {
  CHECK_NOT_NULL(ptr_);
  return *ptr_;
}

Session::TransportParams::operator const ngtcp2_transport_params*() const {
  CHECK_NOT_NULL(ptr_);
  return ptr_;
}

Session::TransportParams::operator bool() const { return ptr_ != nullptr; }

const QuicError& Session::TransportParams::error() const { return error_; }

Session::Application::Application(Session* session, const Options& options)
    : session_(session), options_(options) {}

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
