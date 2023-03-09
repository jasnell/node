#pragma once

#include "ngtcp2/ngtcp2.h"
#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "defs.h"
#include <base_object.h>
#include <memory_tracker.h>
#include <node.h>

namespace node {
namespace quic {

// CIDs are used to identify endpoints participating in a QUIC session.
// Once created, CID instances are immutable.
//
// CIDs contain between 1 to 20 bytes. Most typically they are selected
// randomly but there is a spec for creating "routable" CIDs that encode
// a specific structure. However, that structure is only meaningful to
// the side that creates the CID. Generally they should be treated as
// opaque tokens.
//
// Each peer in a QUIC session generates one or more CIDs that the *other*
// peer will use to identify the session. So, for instance, when a QUIC
// client initiates a brand new session, it will initially generate a CID
// of its own (it's "source CID") and a random placeholder CID for the
// server (the initial "destination CID"). When the server receives the
// initial packet, it will generate its own source CID, and will use the
// client's source CID as it's destination CID.
//
//      Client              Server
// --------------------------------------
//    Source CID   <===> Destination CID
// Destination CID <===>   Source CID
//
// While the connection is being established, it is possible for either
// peer to generate additional CIDs that are also associated with the
// connection.
//
// Once a CID is generated, it is immutable.
class CID final : public MemoryRetainer {
 public:
  // The default constructor creates an empty, zero-length CID.
  // Zero-length CIDs are not usable at all, we use them as a
  // placeholder for a missing or empty CID value.
  inline CID();

  // Copies the given ngtcp2_cid.
  explicit inline CID(const ngtcp2_cid& cid);

  // Copies the given buffer as a cid. len must
  // be within QUIC_MIN_CIDLEN and QUIC_MAX_CIDLEN
  explicit inline CID(const uint8_t* data, size_t len);

  // Wraps the given ngtcp2_cid. The CID does not take ownership
  // of the underlying ngtcp2_cid.
  explicit inline CID(const ngtcp2_cid* cid);

  inline CID(const CID& other);
  CID& operator=(const CID& other);

  struct Hash final {
    size_t operator()(const CID& cid) const;
  };

  bool operator==(const CID& other) const noexcept;
  inline bool operator!=(const CID& other) const noexcept;

  inline operator const uint8_t*() const;
  inline operator const ngtcp2_cid&() const;
  inline operator const ngtcp2_cid*() const;
  inline size_t length() const;
  inline operator bool() const;

  std::string ToString() const;

  SET_NO_MEMORY_INFO()
  SET_MEMORY_INFO_NAME(CID)
  SET_SELF_SIZE(CID)

  template <typename T>
  using Map = std::unordered_map<CID, T, CID::Hash>;

 private:
  ngtcp2_cid cid_;
  const ngtcp2_cid* ptr_;

  friend struct Hash;
};

// A CIDFactory, as the name suggests, is used to create new CIDs.
// Per https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/, QUIC
// implementations may use the Connection IDs associated with a QUIC session as
// a routing mechanism, with each CID instance securely encoding the routing
// information. By default, our implementation creates CIDs randomly but allows
// user code to provide their own CIDFactory implementation.
class CIDFactory {
 public:
  virtual ~CIDFactory() = default;

  // Generate a new CID. The length_hint must be greater than or
  // equal QUIC_MIN_CIDLEN and less than or equal QUIC_MAX_CIDLEN.
  // The CIDFactory implementation can choose to ignore the length
  // hint and could even choose to return a zero-length (unusable)
  // CID.
  virtual CID Generate(size_t length_hint = QUIC_MAX_CIDLEN) const = 0;

  // If the CIDFactory instance is a BaseObject, StrongRef() will
  // return a strong BaseObjectPtr reference that may be used to
  // keep the instance alive.
  virtual operator BaseObjectPtr<BaseObject>() const;

  // A virtual base class for CIDFactory implementations as BaseObjects.
  class Base;

  // The default random CID generator instance.
  static const CIDFactory& random();
};

class CIDFactory::Base : public BaseObject, public CIDFactory {
 public:
  HAS_INSTANCE()
  GET_CONSTRUCTOR_TEMPLATE()

  Base(Realm* env, v8::Local<v8::Object> object);
  operator BaseObjectPtr<BaseObject>() const override;
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
