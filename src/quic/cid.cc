#include "cid-inl.h"
#include "bindingdata-inl.h"
#include "quic/defs.h"
#include "util.h"
#include <env-inl.h>
#include <node_realm-inl.h>
#include <base_object-inl.h>
#include <string_bytes.h>
#include <crypto/crypto_util.h>
#include <node_mutex.h>

namespace node {

using v8::FunctionTemplate;
using v8::Local;
using v8::Object;

namespace quic {

// ============================================================================
// CID

CID& CID::operator=(const CID& other) {
  if (this == &other) return *this;
  ptr_ = &cid_;
  CHECK_NOT_NULL(other.ptr_);
  ngtcp2_cid_init(&cid_, other.ptr_->data, other.ptr_->datalen);
  return *this;
}

std::string CID::ToString() const {
  char dest[QUIC_MAX_CIDLEN * 2];
  size_t written =
      StringBytes::hex_encode(reinterpret_cast<const char*>(ptr_->data),
                              ptr_->datalen,
                              dest,
                              arraysize(dest));
  return std::string(dest, written);
}

size_t CID::Hash::operator()(const CID& cid) const {
  size_t hash = 0;
  for (size_t n = 0; n < cid.length(); n++) {
    hash ^= std::hash<uint8_t>{}(cid.ptr_->data[n]) + 0x9e3779b9 + (hash << 6) +
            (hash >> 2);
  }
  return hash;
}

bool CID::operator==(const CID& other) const noexcept {
  if (this == &other || (length() == 0 && other.length() == 0)) return true;
  if (length() != other.length()) return false;
  return memcmp(ptr_->data, other.ptr_->data, ptr_->datalen) == 0;
}

// ============================================================================
// CIDFactory

namespace {
// The default random CIDFactory implementation.
class RandomCIDFactory : public CIDFactory {
 public:
  RandomCIDFactory() = default;
  QUIC_NO_COPY_OR_MOVE(RandomCIDFactory)
  CID Generate(size_t length_hint) const override {
    CHECK_GE(length_hint, QUIC_MIN_CIDLEN);
    CHECK_LE(length_hint, QUIC_MAX_CIDLEN);
    Mutex::ScopedLock lock(mutex_);
    ngtcp2_cid cid;
    CHECK(crypto::CSPRNG(&cid.data, length_hint).is_ok());
    cid.datalen = length_hint;
    return CID(cid);
  }
 private:
  Mutex mutex_;
};
}  // namespace

const CIDFactory& CIDFactory::random() {
  static RandomCIDFactory instance;
  return instance;
}

CIDFactory::operator BaseObjectPtr<BaseObject>() const { return {}; }

Local<FunctionTemplate>
CIDFactory::Base::GetConstructorTemplate(Environment* env) {
  auto& state = BindingData::Get(env);
  Local<FunctionTemplate> tmpl = state.cidfactorybase_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = FunctionTemplate::New(env->isolate());
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(Base::kInternalFieldCount);
    tmpl->SetClassName(state.cidfactorybase_string());
    state.set_cidfactorybase_constructor_template(tmpl);
  }
  return tmpl;
}

CIDFactory::Base::Base(Realm* realm, Local<Object> object)
    : BaseObject(realm, object) {
  MakeWeak();
}

CIDFactory::Base::operator BaseObjectPtr<BaseObject>() const {
  return BaseObjectPtr<BaseObject>(const_cast<CIDFactory::Base*>(this));
}

}  // namespace quic
}  // namespace node
