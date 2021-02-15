#include "node_sockaddr-inl.h"  // NOLINT(build/include)
#include "env-inl.h"
#include "base64-inl.h"
#include "base_object-inl.h"
#include "memory_tracker-inl.h"
#include "node_errors.h"
#include "uv.h"

#include <memory>
#include <string>
#include <vector>

namespace node {

using v8::Array;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Int32;
using v8::Integer;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::Uint32;
using v8::Value;

namespace {
template <typename T, typename F>
SocketAddress FromUVHandle(F fn, const T& handle) {
  SocketAddress addr;
  int len = sizeof(sockaddr_storage);
  if (fn(&handle, addr.storage(), &len) == 0)
    CHECK_EQ(static_cast<size_t>(len), addr.length());
  else
    addr.storage()->sa_family = 0;
  return addr;
}
}  // namespace

bool SocketAddress::ToSockAddr(
    int32_t family,
    const char* host,
    uint32_t port,
    sockaddr_storage* addr) {
  switch (family) {
    case AF_INET:
      return uv_ip4_addr(
          host,
          port,
          reinterpret_cast<sockaddr_in*>(addr)) == 0;
    case AF_INET6:
      return uv_ip6_addr(
          host,
          port,
          reinterpret_cast<sockaddr_in6*>(addr)) == 0;
    default:
      UNREACHABLE();
  }
}

bool SocketAddress::New(
    const char* host,
    uint32_t port,
    SocketAddress* addr) {
  return New(AF_INET, host, port, addr) || New(AF_INET6, host, port, addr);
}

bool SocketAddress::New(
    int32_t family,
    const char* host,
    uint32_t port,
    SocketAddress* addr) {
  return ToSockAddr(family, host, port,
                    reinterpret_cast<sockaddr_storage*>(addr->storage()));
}

size_t SocketAddress::Hash::operator()(const SocketAddress& addr) const {
  size_t hash = 0;
  switch (addr.family()) {
    case AF_INET: {
      const sockaddr_in* ipv4 =
          reinterpret_cast<const sockaddr_in*>(addr.raw());
      hash_combine(&hash, ipv4->sin_port, ipv4->sin_addr.s_addr);
      break;
    }
    case AF_INET6: {
      const sockaddr_in6* ipv6 =
          reinterpret_cast<const sockaddr_in6*>(addr.raw());
      const uint64_t* a =
          reinterpret_cast<const uint64_t*>(&ipv6->sin6_addr);
      hash_combine(&hash, ipv6->sin6_port, a[0], a[1]);
      break;
    }
    default:
      UNREACHABLE();
  }
  return hash;
}

SocketAddress SocketAddress::FromSockName(const uv_tcp_t& handle) {
  return FromUVHandle(uv_tcp_getsockname, handle);
}

SocketAddress SocketAddress::FromSockName(const uv_udp_t& handle) {
  return FromUVHandle(uv_udp_getsockname, handle);
}

SocketAddress SocketAddress::FromPeerName(const uv_tcp_t& handle) {
  return FromUVHandle(uv_tcp_getpeername, handle);
}

SocketAddress SocketAddress::FromPeerName(const uv_udp_t& handle) {
  return FromUVHandle(uv_udp_getpeername, handle);
}

namespace {
constexpr uint8_t mask[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

bool is_match_ipv4(
    const SocketAddress& one,
    const SocketAddress& two) {
  const sockaddr_in* one_in =
      reinterpret_cast<const sockaddr_in*>(one.data());
  const sockaddr_in* two_in =
      reinterpret_cast<const sockaddr_in*>(two.data());
  return memcmp(&one_in->sin_addr, &two_in->sin_addr, sizeof(uint32_t)) == 0;
}

bool is_match_ipv6(
    const SocketAddress& one,
    const SocketAddress& two) {
  const sockaddr_in6* one_in =
      reinterpret_cast<const sockaddr_in6*>(one.data());
  const sockaddr_in6* two_in =
      reinterpret_cast<const sockaddr_in6*>(two.data());
  return memcmp(&one_in->sin6_addr, &two_in->sin6_addr, 16) == 0;
}

bool is_match_ipv4_ipv6(
    const SocketAddress& ipv4,
    const SocketAddress& ipv6) {
  const sockaddr_in* check_ipv4 =
      reinterpret_cast<const sockaddr_in*>(ipv4.data());
  const sockaddr_in6* check_ipv6 =
      reinterpret_cast<const sockaddr_in6*>(ipv6.data());

  const uint8_t* ptr =
      reinterpret_cast<const uint8_t*>(&check_ipv6->sin6_addr);

  return memcmp(ptr, mask, sizeof(mask)) == 0 &&
         memcmp(ptr + sizeof(mask),
                &check_ipv4->sin_addr,
                sizeof(uint32_t)) == 0;
}

SocketAddress::CompareResult compare_ipv4(
    const SocketAddress& one,
    const SocketAddress& two) {
  const sockaddr_in* one_in =
      reinterpret_cast<const sockaddr_in*>(one.data());
  const sockaddr_in* two_in =
      reinterpret_cast<const sockaddr_in*>(two.data());

  if (one_in->sin_addr.s_addr < two_in->sin_addr.s_addr)
    return SocketAddress::CompareResult::LESS_THAN;
  else if (one_in->sin_addr.s_addr == two_in->sin_addr.s_addr)
    return SocketAddress::CompareResult::SAME;
  else
    return SocketAddress::CompareResult::GREATER_THAN;
}

SocketAddress::CompareResult compare_ipv6(
    const SocketAddress& one,
    const SocketAddress& two) {
  const sockaddr_in6* one_in =
      reinterpret_cast<const sockaddr_in6*>(one.data());
  const sockaddr_in6* two_in =
      reinterpret_cast<const sockaddr_in6*>(two.data());
  int ret = memcmp(&one_in->sin6_addr, &two_in->sin6_addr, 16);
  if (ret < 0)
    return SocketAddress::CompareResult::LESS_THAN;
  else if (ret > 0)
    return SocketAddress::CompareResult::GREATER_THAN;
  return SocketAddress::CompareResult::SAME;
}

SocketAddress::CompareResult compare_ipv4_ipv6(
    const SocketAddress& ipv4,
    const SocketAddress& ipv6) {
  const sockaddr_in* ipv4_in =
      reinterpret_cast<const sockaddr_in*>(ipv4.data());
  const sockaddr_in6 * ipv6_in =
      reinterpret_cast<const sockaddr_in6*>(ipv6.data());

  const uint8_t* ptr =
      reinterpret_cast<const uint8_t*>(&ipv6_in->sin6_addr);

  if (memcmp(ptr, mask, sizeof(mask)) != 0)
    return SocketAddress::CompareResult::NOT_COMPARABLE;

  int ret = memcmp(
      &ipv4_in->sin_addr,
      ptr + sizeof(mask),
      sizeof(uint32_t));

  if (ret < 0)
    return SocketAddress::CompareResult::LESS_THAN;
  else if (ret > 0)
    return SocketAddress::CompareResult::GREATER_THAN;
  return SocketAddress::CompareResult::SAME;
}

bool in_network_ipv4(
    const SocketAddress& ip,
    const SocketAddress& net,
    int prefix) {
  uint32_t mask = ((1 << prefix) - 1) << (32 - prefix);

  const sockaddr_in* ip_in =
      reinterpret_cast<const sockaddr_in*>(ip.data());
  const sockaddr_in* net_in =
      reinterpret_cast<const sockaddr_in*>(net.data());

  return (htonl(ip_in->sin_addr.s_addr) & mask) ==
         (htonl(net_in->sin_addr.s_addr) & mask);
}

bool in_network_ipv6(
    const SocketAddress& ip,
    const SocketAddress& net,
    int prefix) {
  // Special case, if prefix == 128, then just do a
  // straight comparison.
  if (prefix == 128)
    return compare_ipv6(ip, net) == SocketAddress::CompareResult::SAME;

  uint8_t r = prefix % 8;
  int len = (prefix - r) / 8;
  uint8_t mask = ((1 << r) - 1) << (8 - r);

  const sockaddr_in6* ip_in =
      reinterpret_cast<const sockaddr_in6*>(ip.data());
  const sockaddr_in6* net_in =
      reinterpret_cast<const sockaddr_in6*>(net.data());

  if (memcmp(&ip_in->sin6_addr, &net_in->sin6_addr, len) != 0)
    return false;

  const uint8_t* p1 = reinterpret_cast<const uint8_t*>(
      ip_in->sin6_addr.s6_addr);
  const uint8_t* p2 = reinterpret_cast<const uint8_t*>(
      net_in->sin6_addr.s6_addr);

  return (p1[len] & mask) == (p2[len] & mask);
}

bool in_network_ipv4_ipv6(
    const SocketAddress& ip,
    const SocketAddress& net,
    int prefix) {

  if (prefix == 128)
    return compare_ipv4_ipv6(ip, net) == SocketAddress::CompareResult::SAME;

  uint8_t r = prefix % 8;
  int len = (prefix - r) / 8;
  uint8_t mask = ((1 << r) - 1) << (8 - r);

  const sockaddr_in* ip_in =
      reinterpret_cast<const sockaddr_in*>(ip.data());
  const sockaddr_in6* net_in =
      reinterpret_cast<const sockaddr_in6*>(net.data());

  uint8_t ip_mask[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0};
  uint8_t* ptr = ip_mask;
  memcpy(ptr + 12, &ip_in->sin_addr, 4);

  if (memcmp(ptr, &net_in->sin6_addr, len) != 0)
    return false;

  ptr += len;
  const uint8_t* p2 = reinterpret_cast<const uint8_t*>(
      net_in->sin6_addr.s6_addr);

  return (ptr[0] & mask) == (p2[len] & mask);
}

bool in_network_ipv6_ipv4(
    const SocketAddress& ip,
    const SocketAddress& net,
    int prefix) {
  if (prefix == 32)
    return compare_ipv4_ipv6(net, ip) == SocketAddress::CompareResult::SAME;

  uint32_t m = ((1 << prefix) - 1) << (32 - prefix);

  const sockaddr_in6* ip_in =
      reinterpret_cast<const sockaddr_in6*>(ip.data());
  const sockaddr_in* net_in =
      reinterpret_cast<const sockaddr_in*>(net.data());

  const uint8_t* ptr =
      reinterpret_cast<const uint8_t*>(&ip_in->sin6_addr);

  if (memcmp(ptr, mask, sizeof(mask)) != 0)
    return false;

  ptr += sizeof(mask);
  uint32_t check = ReadUint32BE(ptr);

  return (check & m) == (htonl(net_in->sin_addr.s_addr) & m);
}
}  // namespace

// TODO(@jasnell): The implementations of is_match, compare, and
// is_in_network have not been performance optimized and could
// likely benefit from work on more performant approaches.

bool SocketAddress::is_match(const SocketAddress& other) const {
  switch (family()) {
    case AF_INET:
      switch (other.family()) {
        case AF_INET: return is_match_ipv4(*this, other);
        case AF_INET6: return is_match_ipv4_ipv6(*this, other);
      }
      break;
    case AF_INET6:
      switch (other.family()) {
        case AF_INET: return is_match_ipv4_ipv6(other, *this);
        case AF_INET6: return is_match_ipv6(*this, other);
      }
      break;
  }
  return false;
}

SocketAddress::CompareResult SocketAddress::compare(
    const SocketAddress& other) const {
  switch (family()) {
    case AF_INET:
      switch (other.family()) {
        case AF_INET: return compare_ipv4(*this, other);
        case AF_INET6: return compare_ipv4_ipv6(*this, other);
      }
      break;
    case AF_INET6:
      switch (other.family()) {
        case AF_INET: {
          CompareResult c = compare_ipv4_ipv6(other, *this);
          switch (c) {
            case SocketAddress::CompareResult::NOT_COMPARABLE:
              // Fall through
            case SocketAddress::CompareResult::SAME:
              return c;
            case SocketAddress::CompareResult::GREATER_THAN:
              return SocketAddress::CompareResult::LESS_THAN;
            case SocketAddress::CompareResult::LESS_THAN:
              return SocketAddress::CompareResult::GREATER_THAN;
          }
          break;
        }
        case AF_INET6: return compare_ipv6(*this, other);
      }
      break;
  }
  return SocketAddress::CompareResult::NOT_COMPARABLE;
}

bool SocketAddress::is_in_network(
    const SocketAddress& other,
    int prefix) const {

  switch (family()) {
    case AF_INET:
      switch (other.family()) {
        case AF_INET: return in_network_ipv4(*this, other, prefix);
        case AF_INET6: return in_network_ipv4_ipv6(*this, other, prefix);
      }
      break;
    case AF_INET6:
      switch (other.family()) {
        case AF_INET: return in_network_ipv6_ipv4(*this, other, prefix);
        case AF_INET6: return in_network_ipv6(*this, other, prefix);
      }
      break;
  }

  return false;
}

SocketAddressBlockList::SocketAddressBlockList(
    std::shared_ptr<SocketAddressBlockList> parent)
    : parent_(parent) {}

void SocketAddressBlockList::AddSocketAddress(
    std::shared_ptr<SocketAddress> address) {
  SocketAddress addr = *address.get();
  std::unique_ptr<Rule> rule =
      std::make_unique<SocketAddressRule>(std::move(address));
  Mutex::ScopedLock lock(mutex_);
  rules_.emplace_front(std::move(rule));
  address_rules_[addr] = rules_.begin();
}

void SocketAddressBlockList::RemoveSocketAddress(
    std::shared_ptr<SocketAddress> address) {
  Mutex::ScopedLock lock(mutex_);
  auto it = address_rules_.find(*address.get());
  if (it != std::end(address_rules_)) {
    rules_.erase(it->second);
    address_rules_.erase(it);
  }
}

void SocketAddressBlockList::AddSocketAddressRange(
    std::shared_ptr<SocketAddress> start,
    std::shared_ptr<SocketAddress> end) {
  std::unique_ptr<Rule> rule =
      std::make_unique<SocketAddressRangeRule>(
          std::move(start),
          std::move(end));
  Mutex::ScopedLock lock(mutex_);
  rules_.emplace_front(std::move(rule));
}

void SocketAddressBlockList::AddSocketAddressMask(
    std::shared_ptr<SocketAddress> network,
    int prefix) {
  std::unique_ptr<Rule> rule =
      std::make_unique<SocketAddressMaskRule>(std::move(network), prefix);
  Mutex::ScopedLock lock(mutex_);
  rules_.emplace_front(std::move(rule));
}

bool SocketAddressBlockList::Apply(const SocketAddress& address) {
  Mutex::ScopedLock lock(mutex_);
  for (const auto& rule : rules_) {
    if (rule->Apply(address))
      return true;
  }
  return parent_ ? parent_->Apply(address) : false;
}

SocketAddressBlockList::SocketAddressRule::SocketAddressRule(
    std::shared_ptr<SocketAddress> address_)
    : address(std::move(address_)) {}

SocketAddressBlockList::SocketAddressRangeRule::SocketAddressRangeRule(
    std::shared_ptr<SocketAddress> start_,
    std::shared_ptr<SocketAddress> end_)
    : start(std::move(start_)),
      end(std::move(end_)) {}

SocketAddressBlockList::SocketAddressMaskRule::SocketAddressMaskRule(
    std::shared_ptr<SocketAddress> network_,
    int prefix_)
    : network(std::move(network_)),
      prefix(prefix_) {}

bool SocketAddressBlockList::SocketAddressRule::Apply(
    const SocketAddress& address) {
  return this->address->is_match(address);
}

std::string SocketAddressBlockList::SocketAddressRule::ToString() {
  std::string ret = "Address: ";
  ret += address->family() == AF_INET ? "IPv4" : "IPv6";
  ret += " ";
  ret += address->address();
  return ret;
}

bool SocketAddressBlockList::SocketAddressRangeRule::Apply(
    const SocketAddress& address) {
  return address >= *start.get() && address <= *end.get();
}

std::string SocketAddressBlockList::SocketAddressRangeRule::ToString() {
  std::string ret = "Range: ";
  ret += start->family() == AF_INET ? "IPv4" : "IPv6";
  ret += " ";
  ret += start->address();
  ret += "-";
  ret += end->address();
  return ret;
}

bool SocketAddressBlockList::SocketAddressMaskRule::Apply(
    const SocketAddress& address) {
  return address.is_in_network(*network.get(), prefix);
}

std::string SocketAddressBlockList::SocketAddressMaskRule::ToString() {
  std::string ret = "Subnet: ";
  ret += network->family() == AF_INET ? "IPv4" : "IPv6";
  ret += " ";
  ret += network->address();
  ret += "/" + std::to_string(prefix);
  return ret;
}

MaybeLocal<Array> SocketAddressBlockList::ListRules(Environment* env) {
  Mutex::ScopedLock lock(mutex_);
  std::vector<Local<Value>> rules;

  if (parent_) {
    for (const auto& rule : parent_->rules_) {
      Local<Value> str;
      if (!rule->ToV8String(env).ToLocal(&str))
        return MaybeLocal<Array>();
      rules.push_back(str);
    }
  }

  for (const auto& rule : rules_) {
    Local<Value> str;
    if (!rule->ToV8String(env).ToLocal(&str))
      return MaybeLocal<Array>();
    rules.push_back(str);
  }
  return Array::New(env->isolate(), rules.data(), rules.size());
}

void SocketAddressBlockList::MemoryInfo(node::MemoryTracker* tracker) const {
  Mutex::ScopedLock lock(mutex_);
  tracker->TrackField("rules", rules_);
}

void SocketAddressBlockList::SocketAddressRule::MemoryInfo(
    node::MemoryTracker* tracker) const {
  tracker->TrackField("address", address);
}

void SocketAddressBlockList::SocketAddressRangeRule::MemoryInfo(
    node::MemoryTracker* tracker) const {
  tracker->TrackField("start", start);
  tracker->TrackField("end", end);
}

void SocketAddressBlockList::SocketAddressMaskRule::MemoryInfo(
    node::MemoryTracker* tracker) const {
  tracker->TrackField("network", network);
}

SocketAddressBlockListWrap::SocketAddressBlockListWrap(
    Environment* env,
    Local<Object> wrap,
    std::shared_ptr<SocketAddressBlockList> blocklist)
    : BaseObject(env, wrap),
      blocklist_(std::move(blocklist)) {
  MakeWeak();
}

bool SocketAddressBlockListWrap::HasInstance(
    Environment* env,
    Local<Value> value) {
  return GetConstructorTemplate(env)->HasInstance(value);
}

BaseObjectPtr<SocketAddressBlockListWrap> SocketAddressBlockListWrap::New(
    Environment* env) {
  Local<Object> obj;
  if (!env->blocklist_ctor_template()
          ->InstanceTemplate()
          ->NewInstance(env->context()).ToLocal(&obj)) {
    return BaseObjectPtr<SocketAddressBlockListWrap>();
  }
  BaseObjectPtr<SocketAddressBlockListWrap> wrap =
      MakeDetachedBaseObject<SocketAddressBlockListWrap>(env, obj);
  CHECK(wrap);
  return wrap;
}

void SocketAddressBlockListWrap::New(
    const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);

  CHECK_IMPLIES(
      !args[0]->IsUndefined(),
      SocketAddressBlockListWrap::HasInstance(env, args[0]));
  if (!args[0]->IsUndefined()) {
    SocketAddressBlockListWrap* parent;
    ASSIGN_OR_RETURN_UNWRAP(&parent, args[0]);
    std::shared_ptr<SocketAddressBlockList> list =
        std::make_shared<SocketAddressBlockList>(parent->blocklist_);
    new SocketAddressBlockListWrap(env, args.This(), std::move(list));
    return;
  }

  new SocketAddressBlockListWrap(env, args.This());
}

void SocketAddressBlockListWrap::AddAddress(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  SocketAddressBlockListWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  CHECK(SocketAddressWrap::HasInstance(env, args[0]));
  SocketAddressWrap* addr;
  ASSIGN_OR_RETURN_UNWRAP(&addr, args[0]);
  wrap->blocklist_->AddSocketAddress(addr->address());
  args.GetReturnValue().Set(true);
}

void SocketAddressBlockListWrap::AddRange(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  SocketAddressBlockListWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK(SocketAddressWrap::HasInstance(env, args[0]));
  CHECK(SocketAddressWrap::HasInstance(env, args[1]));

  SocketAddressWrap* start;
  SocketAddressWrap* end;

  ASSIGN_OR_RETURN_UNWRAP(&start, args[0]);
  ASSIGN_OR_RETURN_UNWRAP(&end, args[1]);

  // Starting address must come before the end address
  if (*start->address().get() > *end->address().get())
    return args.GetReturnValue().Set(false);

  wrap->blocklist_->AddSocketAddressRange(start->address(), end->address());

  args.GetReturnValue().Set(true);
}

void SocketAddressBlockListWrap::AddSubnet(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  SocketAddressBlockListWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK(SocketAddressWrap::HasInstance(env, args[0]));
  CHECK(args[1]->IsInt32());  // Prefix

  int32_t prefix;
  if (!args[1]->Int32Value(env->context()).To(&prefix))
    return;

  SocketAddressWrap* addr;
  ASSIGN_OR_RETURN_UNWRAP(&addr, args[0]);

  CHECK_IMPLIES(addr->address()->family() == AF_INET, prefix <= 32);
  CHECK_IMPLIES(addr->address()->family() == AF_INET6, prefix <= 128);
  CHECK_GE(prefix, 0);

  wrap->blocklist_->AddSocketAddressMask(addr->address(), prefix);

  args.GetReturnValue().Set(true);
}

void SocketAddressBlockListWrap::Check(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  SocketAddressBlockListWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  CHECK(SocketAddressWrap::HasInstance(env, args[0]));
  SocketAddressWrap* addr;
  ASSIGN_OR_RETURN_UNWRAP(&addr, args[0]);

  args.GetReturnValue().Set(wrap->blocklist_->Apply(addr->address()));
}

void SocketAddressBlockListWrap::GetRules(
    const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  SocketAddressBlockListWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  Local<Array> rules;
  if (wrap->blocklist_->ListRules(env).ToLocal(&rules))
    args.GetReturnValue().Set(rules);
}

Local<FunctionTemplate> SocketAddressBlockListWrap::GetConstructorTemplate(
    Environment* env) {
  Local<FunctionTemplate> tmpl = env->blocklist_ctor_template();
  if (tmpl.IsEmpty()) {
    tmpl = env->NewFunctionTemplate(SocketAddressBlockListWrap::New);
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        BaseObject::kInternalFieldCount);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "BlockList"));
    env->SetProtoMethod(tmpl, "addAddress", AddAddress);
    env->SetProtoMethod(tmpl, "addRange", AddRange);
    env->SetProtoMethod(tmpl, "addSubnet", AddSubnet);
    env->SetProtoMethod(tmpl, "check", Check);
    env->SetProtoMethod(tmpl, "getRules", GetRules);
    env->set_blocklist_ctor_template(tmpl);
  }
  return tmpl;
}

void SocketAddressBlockListWrap::Initialize(
    Local<Object> target,
    Local<Value> unused,
    Local<Context> context,
    void* priv) {
  Environment* env = Environment::GetCurrent(context);
  env->SetConstructorFunction(target, "BlockList", GetConstructorTemplate(env));
  SocketAddressWrap::Initialize(env, target);
  NODE_DEFINE_CONSTANT(target, AF_INET);
  NODE_DEFINE_CONSTANT(target, AF_INET6);
}

std::unique_ptr<worker::TransferData>
SocketAddressBlockListWrap::CloneForMessaging() const {
  return std::make_unique<TransferData>(blocklist_);
}

BaseObjectPtr<BaseObject> SocketAddressBlockListWrap::TransferData::Deserialize(
    Environment* env,
    Local<Context> context,
    std::unique_ptr<worker::TransferData> self) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(context).ToLocal(&obj)) {
    return BaseObjectPtr<BaseObject>();
  }

  return MakeBaseObject<SocketAddressBlockListWrap>(
      env,
      obj,
      std::move(blocklist_));
}

bool SocketAddressWrap::HasInstance(Environment* env, Local<Value> value) {
  return GetConstructorTemplate(env)->HasInstance(value);
}

Local<FunctionTemplate> SocketAddressWrap::GetConstructorTemplate(
    Environment* env) {
  Local<FunctionTemplate> tmpl = env->socketaddress_constructor_template();
  if (tmpl.IsEmpty()) {
    tmpl = env->NewFunctionTemplate(New);
    tmpl->Inherit(BaseObject::GetConstructorTemplate(env));
    tmpl->InstanceTemplate()->SetInternalFieldCount(
        SocketAddressWrap::kInternalFieldCount);
    tmpl->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "SocketAddress"));
    env->SetProtoMethodNoSideEffect(tmpl, "detail", Detail);
    env->set_socketaddress_constructor_template(tmpl);
  }
  return tmpl;
}

void SocketAddressWrap::Initialize(Environment* env, Local<Object> target) {
  env->SetConstructorFunction(
      target,
      "SocketAddress",
      GetConstructorTemplate(env));
  NODE_DEFINE_CONSTANT(target, kLabelMask);
}

void SocketAddressWrap::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsInt32());  // Family
  CHECK(args[1]->IsString());  // Address
  CHECK(args[2]->IsInt32());  // Port
  CHECK_IMPLIES(!args[3]->IsUndefined(), args[3]->IsUint32());

  uint32_t family = args[0].As<Int32>()->Value();
  uint32_t port = args[2].As<Int32>()->Value();
  Utf8Value address(env->isolate(), args[1]);

  std::shared_ptr<SocketAddress> addr =
      std::make_shared<SocketAddress>();
  CHECK(addr);
  if (!SocketAddress::New(family, *address, port, addr.get()))
    return THROW_ERR_INVALID_ADDRESS(env);

  SocketAddressWrap* wrap =
      new SocketAddressWrap(env, args.This(), std::move(addr));

  if (!args[3]->IsUndefined() && family == AF_INET6) {
    uint32_t flow_label = args[3].As<Uint32>()->Value();
    wrap->address_->set_flow_label(flow_label);
  }
}

SocketAddressWrap::SocketAddressWrap(
    Environment* env,
    Local<Object> object,
    std::shared_ptr<SocketAddress> addr)
    : BaseObject(env, object),
      address_(std::move(addr)) {
  MakeWeak();
}

void SocketAddressWrap::Detail(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  SocketAddressWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();

  Local<Value> address;
  if (!ToV8Value(env->context(), wrap->address_->address()).ToLocal(&address))
    return;

  if (wrap->address_->family() == AF_INET6 &&
      !obj->Set(
          env->context(),
          env->flowlabel_string(),
          Integer::NewFromUnsigned(
              env->isolate(),
              wrap->address_->flow_label())).FromJust()) {
    return;
  }

  if (!obj->Set(
          env->context(),
          env->family_string(),
          FIXED_ONE_BYTE_STRING(
              env->isolate(),
              wrap->address_->family() == AF_INET ? "ipv4" : "ipv6"))
                  .FromJust() ||
      !obj->Set(env->context(), env->host_string(), address).FromJust() ||
      !obj->Set(
          env->context(),
          env->port_string(),
          Integer::NewFromUnsigned(
              env->isolate(),
              wrap->address_->port())).FromJust()) {
    // Intentionally empty block. The If statements are structured to
    // short circuit if any of the statements return false.
  }

  args.GetReturnValue().Set(obj);
}

void SocketAddressWrap::MemoryInfo(
    node::MemoryTracker* tracker) const {
  if (address_)
    tracker->TrackField("address", address_);
}

void SocketAddressWrap::TransferData::MemoryInfo(
    node::MemoryTracker* tracker) const {
  if (address_)
    tracker->TrackField("address", address_);
}

BaseObjectPtr<BaseObject> SocketAddressWrap::TransferData::Deserialize(
    Environment* env,
    v8::Local<v8::Context> context,
    std::unique_ptr<worker::TransferData> self) {
  Local<Object> obj;
  if (!GetConstructorTemplate(env)
          ->InstanceTemplate()
          ->NewInstance(context).ToLocal(&obj)) {
    return BaseObjectPtr<BaseObject>();
  }
  return MakeBaseObject<SocketAddressWrap>(env, obj, std::move(address_));
}

}  // namespace node

NODE_MODULE_CONTEXT_AWARE_INTERNAL(
    block_list,
    node::SocketAddressBlockListWrap::Initialize)
