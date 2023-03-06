#pragma once

#include "streams.h"

namespace node {
namespace quic {

stream_id Stream::id() const { return state_->id; }

Direction Stream::direction() const {
  return id() & 0b10 ? Direction::UNIDIRECTIONAL : Direction::BIDIRECTIONAL;
}

CryptoContext::Side Stream::origin() const {
  return id() & 0b01 ? CryptoContext::Side::SERVER : CryptoContext::Side::CLIENT;
}

Session* Stream::session() const { return session_.get(); }

bool Stream::is_destroyed() const {
  return state_->destroyed;
}

bool Stream::might_send_trailers() const {
  return state_->trailers;
}

uint64_t Stream::final_size() const {
  return stats_.Get<&Stream::Stats::final_size>();
}

void Stream::set_headers_kind(Session::Application::HeadersKind headers_kind) {
  headers_kind_ = headers_kind;
}

}  // namespace quic
}  // namespace node
