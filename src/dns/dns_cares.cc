#include "dns/dns_cares.h"
#include "base64-inl.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "node_errors.h"
#include "node.h"
#include "util-inl.h"
#include "memory_tracker-inl.h"

#include <algorithm>
#include <unordered_map>

namespace node {

using v8::Array;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Int32;
using v8::Integer;
using v8::Local;
using v8::MaybeLocal;
using v8::Null;
using v8::Object;
using v8::String;
using v8::Value;

namespace per_process {
struct dns::DNSService dns_service_;
};

namespace dns {

namespace {

typedef int (*ParseFn)(
    const unsigned char*,
    int,
    struct hostent**,
    struct ares_addrttl*,
    int*);

// using ParseAFN = int ares_parse_a_reply(const unsigned char *abuf, int alen,
//                        struct hostent **host,
//                        struct ares_addrttl *addrttls, int *naddrttls)

const int kOptmask =
    ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_SOCK_STATE_CB;
const int kMaxTimeout = 1000;
const char EMSG_ESETSRVPENDING[] = "There are pending queries.";

inline uint16_t cares_get_16bit(const unsigned char* p) {
  return static_cast<uint32_t>(p[0] << 8U) | (static_cast<uint32_t>(p[1]));
}

int ParseCname(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  hostent* host;

  int status = ares_parse_a_reply(
    response_data.buf.data,
    response_data.buf.size,
    &host,
    nullptr,
    nullptr);

  if (status != ARES_SUCCESS)
    return status;

  HostEntPointer ptr(host);
  if (host->h_name && host->h_aliases[0]) {
    Local<Object> obj = Object::New(env->isolate());
    if (!obj->Set(
            env->context(),
            env->value_string(),
            OneByteString(env->isolate(), host->h_name)).FromJust() ||
        !obj->Set(
            env->context(),
            env->type_string(),
            env->dns_cname_string()).FromJust()) {
      return ARES_EBADRESP;
    }
    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseA(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  hostent* host;

  ares_addrttl addrttls[256];
  int naddrttls = arraysize(addrttls);

  int status = ares_parse_a_reply(
    response_data.buf.data,
    response_data.buf.size,
    &host,
    addrttls,
    &naddrttls);

  naddrttls = std::min(naddrttls, static_cast<int>(arraysize(addrttls)));

  if (status != ARES_SUCCESS)
    return status;

  HostEntPointer ptr(host);

  // If host->h_name and host->h_aliases[0] are both
  // set, it's a CNAME
  if (host->h_name && host->h_aliases[0])
    return ARES_SUCCESS;

  char ip[INET6_ADDRSTRLEN];
  for (uint32_t i = 0; host->h_addr_list[i] != nullptr; ++i) {
    uv_inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
    Local<Object> obj = Object::New(env->isolate());
    if (!obj->Set(env->context(),
            env->address_string(),
            OneByteString(env->isolate(), ip)).FromJust() ||
        !obj->Set(env->context(),
            env->type_string(),
            env->dns_a_string()).FromJust()) {
      return ARES_EBADRESP;
    }
    if (naddrttls > 0 &&
        i < static_cast<uint32_t>(naddrttls) &&
        !obj->Set(
             env->context(),
             env->ttl_string(),
             Integer::NewFromUnsigned(
                 env->isolate(),
                 addrttls[i].ttl)).FromJust()) {
      return ARES_EBADRESP;
    }
    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseAAAA(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  hostent* host;

  ares_addr6ttl addrttls[256];
  int naddrttls = arraysize(addrttls);

  int status = ares_parse_aaaa_reply(
    response_data.buf.data,
    response_data.buf.size,
    &host,
    addrttls,
    &naddrttls);

  naddrttls = std::min(naddrttls, static_cast<int>(arraysize(addrttls)));

  if (status != ARES_SUCCESS)
    return status;

  HostEntPointer ptr(host);

  // If host->h_name and host->h_aliases[0] are both
  // set, it's a CNAME
  if (host->h_name && host->h_aliases[0])
    return ARES_SUCCESS;

  char ip[INET6_ADDRSTRLEN];
  for (uint32_t i = 0; host->h_addr_list[i] != nullptr; ++i) {
    uv_inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
    Local<Object> obj = Object::New(env->isolate());
    if (!obj->Set(env->context(),
            env->address_string(),
            OneByteString(env->isolate(), ip)).FromJust() ||
        !obj->Set(env->context(),
            env->type_string(),
            env->dns_aaaa_string()).FromJust()) {
      return ARES_EBADRESP;
    }
    if (naddrttls > 0 &&
        i < static_cast<uint32_t>(naddrttls) &&
        !obj->Set(
             env->context(),
             env->ttl_string(),
             Integer::NewFromUnsigned(
                 env->isolate(),
                 addrttls[i].ttl)).FromJust()) {
      return ARES_EBADRESP;
    }
    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseMx(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  struct ares_mx_reply* mx_start;
  int status = ares_parse_mx_reply(
      response_data.buf.data,
      response_data.buf.size,
      &mx_start);
  if (status != ARES_SUCCESS)
    return status;

  DataPointer delete_me(mx_start);

  ares_mx_reply* current = mx_start;
  for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
    Local<Object> mx_record = Object::New(env->isolate());
    if (!mx_record->Set(
            env->context(),
            env->exchange_string(),
            OneByteString(env->isolate(), current->host)).FromJust() ||
        !mx_record->Set(
            env->context(),
            env->priority_string(),
            Integer::New(env->isolate(), current->priority)).FromJust() ||
        !mx_record->Set(
            env->context(),
            env->type_string(),
            env->dns_mx_string()).FromJust()) {
      return ARES_EBADRESP;
    }
    vec->push_back(mx_record);
  }
  return ARES_SUCCESS;
}

int ParseNs(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  hostent* host;
  int status = ares_parse_ns_reply(
      response_data.buf.data,
      response_data.buf.size,
      &host);

  if (status != ARES_SUCCESS)
    return status;

  HostEntPointer delete_me(host);

  for (uint32_t i = 0; host->h_aliases[i] != nullptr; ++i) {
    Local<Object> obj = Object::New(env->isolate());

    if (!obj->Set(
            env->context(),
            env->value_string(),
            OneByteString(env->isolate(), host->h_aliases[i])).FromJust() ||
        !obj->Set(
            env->context(),
            env->type_string(),
            env->dns_ns_string()).FromJust()) {
      return ARES_EBADRESP;
    }

    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseTxt(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  struct ares_txt_ext* txt_out;
  int status = ares_parse_txt_reply_ext(
      response_data.buf.data,
      response_data.buf.size,
      &txt_out);
  if (status != ARES_SUCCESS)
    return status;

  DataPointer delete_me(txt_out);

  std::vector<Local<Value>> chunks;
  struct ares_txt_ext* current = txt_out;
  for (; current != nullptr; current = current->next) {
    Local<String> txt =
        OneByteString(env->isolate(), current->txt, current->length);

    if (current->record_start) {
      if (!chunks.empty()) {
        Local<Object> obj = Object::New(env->isolate());
        if (!obj->Set(
                env->context(),
                env->entries_string(),
                Array::New(env->isolate(), chunks.data(), chunks.size()))
                   .FromJust() ||
            !obj->Set(
                env->context(),
                env->type_string(),
                env->dns_txt_string()).FromJust()) {
          return ARES_EBADRESP;
        }
        vec->push_back(obj);
      }

      chunks.clear();
    }

    chunks.push_back(txt);
  }
  return ARES_SUCCESS;
}

int ParsePtr(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  hostent* host;
  int status = ares_parse_ptr_reply(
      response_data.buf.data,
      response_data.buf.size,
      nullptr, 0, AF_INET, &host);
  if (status != ARES_SUCCESS)
    return status;

  HostEntPointer delete_me(host);

  for (uint32_t i = 0; host->h_aliases[i] != nullptr; i++) {
    Local<Object> obj = Object::New(env->isolate());

    if (!obj->Set(
            env->context(),
            env->value_string(),
            OneByteString(env->isolate(), host->h_aliases[i])).FromJust() ||
        !obj->Set(
            env->context(),
            env->type_string(),
            env->dns_ptr_string()).FromJust()) {
      return ARES_EBADRESP;
    }

    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseNaptr(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  ares_naptr_reply* naptr_start;
  int status = ares_parse_naptr_reply(
      response_data.buf.data,
      response_data.buf.size,
      &naptr_start);

  if (status != ARES_SUCCESS)
    return status;

  DataPointer delete_me(naptr_start);

  ares_naptr_reply* current = naptr_start;
  for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
    Local<Object> obj = Object::New(env->isolate());
    if (!obj->Set(
            env->context(),
            env->flags_string(),
            OneByteString(env->isolate(), current->flags)).FromJust() ||
        !obj->Set(
            env->context(),
            env->service_string(),
            OneByteString(env->isolate(), current->service)).FromJust() ||
        !obj->Set(
            env->context(),
            env->regexp_string(),
            OneByteString(env->isolate(), current->regexp)).FromJust() ||
        !obj->Set(
            env->context(),
            env->replacement_string(),
            OneByteString(env->isolate(), current->replacement)).FromJust() ||
        !obj->Set(
            env->context(),
            env->order_string(),
            Integer::New(env->isolate(), current->order)).FromJust() ||
        !obj->Set(
            env->context(),
            env->preference_string(),
            Integer::New(env->isolate(), current->preference)).FromJust() ||
        !obj->Set(
            env->context(),
            env->type_string(),
            env->dns_naptr_string()).FromJust()) {
      return ARES_EBADRESP;
    }

    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseSoa(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {

  // Can't use ares_parse_soa_reply() here which can only parse single record
  const unsigned int ancount =
      cares_get_16bit(response_data.buf.data + 6);
  unsigned char* ptr = response_data.buf.data + NS_HFIXEDSZ;
  char* name_temp = nullptr;
  long temp_len;  // NOLINT(runtime/int)
  int status = ares_expand_name(
      ptr,
      response_data.buf.data,
      response_data.buf.size,
      &name_temp,
      &temp_len);
  if (status != ARES_SUCCESS) {
    // returns EBADRESP in case of invalid input
    return status == ARES_EBADNAME ? ARES_EBADRESP : status;
  }

  AresStringPointer name(name_temp);

  if (ptr + temp_len + NS_QFIXEDSZ >
          response_data.buf.data + response_data.buf.size) {
    return ARES_EBADRESP;
  }
  ptr += temp_len + NS_QFIXEDSZ;

  for (unsigned int i = 0; i < ancount; i++) {
    char* rr_name_temp = nullptr;
    long rr_temp_len;  // NOLINT(runtime/int)
    int status2 = ares_expand_name(
        ptr,
        response_data.buf.data,
        response_data.buf.size,
        &rr_name_temp,
        &rr_temp_len);

    if (status2 != ARES_SUCCESS)
      return status2 == ARES_EBADNAME ? ARES_EBADRESP : status2;

    AresStringPointer rr_name(rr_name_temp);

    ptr += rr_temp_len;
    if (ptr + NS_RRFIXEDSZ > response_data.buf.data + response_data.buf.size)
      return ARES_EBADRESP;

    const int rr_type = cares_get_16bit(ptr);
    const int rr_len = cares_get_16bit(ptr + 8);
    ptr += NS_RRFIXEDSZ;

    // only need SOA
    if (rr_type == ns_t_soa) {
      char* nsname_temp = nullptr;
      long nsname_temp_len;  // NOLINT(runtime/int)

      int status3 = ares_expand_name(
          ptr,
          response_data.buf.data,
          response_data.buf.size,
          &nsname_temp,
          &nsname_temp_len);
      if (status3 != ARES_SUCCESS)
        return status3 == ARES_EBADNAME ? ARES_EBADRESP : status3;

      AresStringPointer nsname(nsname_temp);
      ptr += nsname_temp_len;

      char* hostmaster_temp = nullptr;
      long hostmaster_temp_len;  // NOLINT(runtime/int)
      int status4 = ares_expand_name(
          ptr,
          response_data.buf.data,
          response_data.buf.size,
          &hostmaster_temp,
          &hostmaster_temp_len);
      if (status4 != ARES_SUCCESS)
        return status4 == ARES_EBADNAME ? ARES_EBADRESP : status4;
      AresStringPointer hostmaster(hostmaster_temp);
      ptr += hostmaster_temp_len;

      if (ptr + 5 * 4 > response_data.buf.data + response_data.buf.size)
        return ARES_EBADRESP;

      const unsigned int serial = ReadUint32BE(ptr + 0 * 4);
      const unsigned int refresh = ReadUint32BE(ptr + 1 * 4);
      const unsigned int retry = ReadUint32BE(ptr + 2 * 4);
      const unsigned int expire = ReadUint32BE(ptr + 3 * 4);
      const unsigned int minttl = ReadUint32BE(ptr + 4 * 4);

      Local<Object> obj = Object::New(env->isolate());
      if (!obj->Set(
              env->context(),
              env->nsname_string(),
              OneByteString(env->isolate(), nsname.get())).FromJust() ||
          !obj->Set(
              env->context(),
              env->hostmaster_string(),
              OneByteString(env->isolate(), hostmaster.get())).FromJust() ||
          !obj->Set(
              env->context(),
              env->serial_string(),
              Integer::NewFromUnsigned(env->isolate(), serial)).FromJust() ||
          !obj->Set(
              env->context(),
              env->refresh_string(),
              Integer::New(env->isolate(), refresh)).FromJust() ||
          !obj->Set(
              env->context(),
              env->retry_string(),
              Integer::New(env->isolate(), retry)).FromJust() ||
          !obj->Set(
              env->context(),
              env->expire_string(),
              Integer::New(env->isolate(), expire)).FromJust() ||
          !obj->Set(
              env->context(),
              env->minttl_string(),
              Integer::NewFromUnsigned(env->isolate(), minttl)).FromJust() ||
          !obj->Set(
              env->context(),
              env->type_string(),
              env->dns_soa_string()).FromJust()) {
        return ARES_EBADRESP;
      }

      vec->push_back(obj);
      break;
    }

    ptr += rr_len;
  }

  return ARES_SUCCESS;
}

int ParseCaa(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {
  struct ares_caa_reply* caa_start;
  int status = ares_parse_caa_reply(
      response_data.buf.data,
      response_data.buf.size,
      &caa_start);
  if (status != ARES_SUCCESS)
    return status;

  DataPointer delete_me(caa_start);

  ares_caa_reply* current = caa_start;
  for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
    Local<Object> obj = Object::New(env->isolate());

    if (!obj->Set(
            env->context(),
            env->dns_critical_string(),
            Integer::New(env->isolate(), current->critical)).FromJust() ||
        !obj->Set(
           env->context(),
           OneByteString(env->isolate(), current->property),
           OneByteString(env->isolate(), current->value)).FromJust() ||
        !obj->Set(
           env->context(),
           env->type_string(),
           env->dns_caa_string()).FromJust()) {
      return ARES_EBADRESP;
    }

    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

int ParseSrv(
    Environment* env,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    DNSParseFlag flag) {

  struct ares_srv_reply* srv_start;
  int status = ares_parse_srv_reply(
      response_data.buf.data,
      response_data.buf.size,
      &srv_start);
  if (status != ARES_SUCCESS)
    return status;

  DataPointer delete_me(srv_start);

  ares_srv_reply* current = srv_start;
  for (uint32_t i = 0; current != nullptr; ++i, current = current->next) {
    Local<Object> obj = Object::New(env->isolate());
    if (!obj->Set(
            env->context(),
            env->name_string(),
            OneByteString(env->isolate(), current->host)).FromJust() ||
        !obj->Set(
            env->context(),
            env->port_string(),
            Integer::New(env->isolate(), current->port)).FromJust() ||
        !obj->Set(
            env->context(),
            env->priority_string(),
            Integer::New(env->isolate(), current->priority)).FromJust() ||
        !obj->Set(
            env->context(),
            env->weight_string(),
            Integer::New(env->isolate(), current->weight)).FromJust() ||
        !obj->Set(
            env->context(),
            env->type_string(),
            env->dns_srv_string()).FromJust()) {
      return ARES_EBADRESP;
    }

    vec->push_back(obj);
  }

  return ARES_SUCCESS;
}

void AresSockStateCallback(
    void* data,
    ares_socket_t sock,
    int read,
    int write) {
  DNSContext* context = static_cast<DNSContext*>(data);
  context->OnSockState(sock, read, write);
}

void AresTimeout(uv_timer_t* handle) {
  DNSContext* context = static_cast<DNSContext*>(handle->data);
  context->OnTimeout();
}

void AresPollCallback(uv_poll_t* watcher, int status, int events) {
  NodeAresTask* task = NodeAresTask::FromPollWatcher(watcher);
  task->context()->OnPoll(task, status, events);
}

void StrError(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  int code = args[0]->Int32Value(env->context()).FromJust();
  const char* errmsg = (code == DNS_ESETSRVPENDING) ?
    EMSG_ESETSRVPENDING :
    ares_strerror(code);
  args.GetReturnValue().Set(OneByteString(env->isolate(), errmsg));
}

void CaresWrapHostentCopy(
    struct hostent* dest,
    const struct hostent* src) {
  dest->h_addr_list = nullptr;
  dest->h_addrtype = 0;
  dest->h_aliases = nullptr;
  dest->h_length = 0;
  dest->h_name = nullptr;

  /* copy `h_name` */
  size_t name_size = strlen(src->h_name) + 1;
  dest->h_name = node::Malloc<char>(name_size);
  memcpy(dest->h_name, src->h_name, name_size);

  /* copy `h_aliases` */
  size_t alias_count;
  for (alias_count = 0;
      src->h_aliases[alias_count] != nullptr;
      alias_count++) {
  }

  dest->h_aliases = node::Malloc<char*>(alias_count + 1);
  for (size_t i = 0; i < alias_count; i++) {
    const size_t cur_alias_size = strlen(src->h_aliases[i]) + 1;
    dest->h_aliases[i] = node::Malloc(cur_alias_size);
    memcpy(dest->h_aliases[i], src->h_aliases[i], cur_alias_size);
  }
  dest->h_aliases[alias_count] = nullptr;

  /* copy `h_addr_list` */
  size_t list_count;
  for (list_count = 0;
      src->h_addr_list[list_count] != nullptr;
      list_count++) {
  }

  dest->h_addr_list = node::Malloc<char*>(list_count + 1);
  for (size_t i = 0; i < list_count; i++) {
    dest->h_addr_list[i] = node::Malloc(src->h_length);
    memcpy(dest->h_addr_list[i], src->h_addr_list[i], src->h_length);
  }
  dest->h_addr_list[list_count] = nullptr;

  /* work after work */
  dest->h_length = src->h_length;
  dest->h_addrtype = src->h_addrtype;
}

template <class Wrap>
static void Query(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DNSContext* context;
  ASSIGN_OR_RETURN_UNWRAP(&context, args.Holder());

  CHECK_EQ(false, args.IsConstructCall());
  CHECK(args[0]->IsObject());  // Req Wrap Object
  CHECK(args[1]->IsString());  // Name

  Local<Object> req_wrap_obj = args[0].As<Object>();
  Utf8Value name(env->isolate(), args[1]);

  auto wrap = std::make_unique<Wrap>(context, req_wrap_obj, *name);

  int err = wrap->Send();
  if (err == 0)
    USE(wrap.release());

  args.GetReturnValue().Set(err);
}

void GetServersList(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DNSContext* context;
  ASSIGN_OR_RETURN_UNWRAP(&context, args.Holder());
  auto servers = context->GetServers(env);
  args.GetReturnValue().Set(
      Array::New(env->isolate(), servers.data(), servers.size()));
}

void SetServersList(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DNSContext* context;
  ASSIGN_OR_RETURN_UNWRAP(&context, args.Holder());
  CHECK(args[0]->IsArray());
  args.GetReturnValue().Set(context->SetServers(env, args[0].As<Array>()));
}

void SetLocalAddressAPI(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  DNSContext* context;
  ASSIGN_OR_RETURN_UNWRAP(&context, args.Holder());

  CHECK(args[0]->IsString());
  CHECK_IMPLIES(!args[1]->IsUndefined(), args[1]->IsString());

  Utf8Value ip(env->isolate(), args[0]);

  if (args.Length() == 1) {
    context->SetLocalAddress(env, *ip);
  } else {
    Utf8Value other(env->isolate(), args[1]);
    context->SetLocalAddress(env, *ip, *other);
  }
}

void CancelAPI(const FunctionCallbackInfo<Value>& args) {
  DNSContext* context;
  ASSIGN_OR_RETURN_UNWRAP(&context, args.Holder());
  context->Cancel();
}
}  // namespace

DNSService::DNSService() {
  status = ares_library_init(ARES_LIB_INIT_ALL);
}

DNSService::~DNSService() {
  if (status == ARES_SUCCESS)
    ares_library_cleanup();
}

DNSChannel::DNSChannel(const DNSChannel::Options& options) {
  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  opts.flags = ARES_FLAG_NOCHECKRESP;
  opts.sock_state_cb = AresSockStateCallback;
  opts.sock_state_cb_data = this;
  opts.timeout = options.timeout;
  last_status_ = ares_init_options(&channel_, &opts, kOptmask);
}

DNSChannel::~DNSChannel() {
  if (last_status_ == ARES_SUCCESS && channel_ != nullptr)
    ares_destroy(channel_);
}

std::vector<Local<Value>> DNSContext::GetServers(Environment* env) {
  std::vector<Local<Value>> ret;
  ares_addr_port_node* servers;
  int r = ares_get_servers_ports(channel_->channel(), &servers);
  if (r != ARES_SUCCESS)
    return ret;

  DataPointer delete_me(servers);
  ares_addr_port_node* current = servers;
  for (;current != nullptr; current = current->next) {
    char ip[INET6_ADDRSTRLEN];
    const void* caddr = static_cast<const void*>(&current->addr);
    r = uv_inet_ntop(current->family, caddr, ip, sizeof(ip));
    CHECK_EQ(r, 0);
    Local<Value> entry[] = {
      OneByteString(env->isolate(), ip),
      Integer::New(env->isolate(), current->udp_port)
    };
    ret.push_back(Array::New(env->isolate(), entry, arraysize(entry)));
  }

  return ret;
}

int DNSContext::SetServers(Environment* env, v8::Local<v8::Array> list) {
  if (queries_count_ > 0)
    return DNS_ESETSRVPENDING;

  uint32_t len = list->Length();

  if (len == 0)
    return ares_set_servers(channel_->channel(), nullptr);

  std::vector<ares_addr_port_node> servers(len);
  ares_addr_port_node* last = nullptr;

  int err;

  for (uint32_t i = 0; i < len; i++) {
    Local<Value> elm;
    Local<Value> family;
    Local<Value> ip_str;
    Local<Value> port;

    CHECK(list->Get(env->context(), i).ToLocal(&elm));
    CHECK(elm->IsArray());

    CHECK(elm.As<Array>()->Get(env->context(), 0).ToLocal(&family));
    CHECK(elm.As<Array>()->Get(env->context(), 1).ToLocal(&ip_str));
    CHECK(elm.As<Array>()->Get(env->context(), 2).ToLocal(&port));
    CHECK(family->IsInt32());
    CHECK(ip_str->IsString());
    CHECK(port->IsInt32());

    Utf8Value ip(env->isolate(), ip_str);

    ares_addr_port_node* cur = &servers[i];

    cur->tcp_port = cur->udp_port = port.As<Int32>()->Value();
    switch (family.As<Int32>()->Value()) {
      case 4:
        cur->family = AF_INET;
        err = uv_inet_pton(AF_INET, *ip, &cur->addr);
        break;
      case 6:
        cur->family = AF_INET6;
        err = uv_inet_pton(AF_INET6, *ip, &cur->addr);
        break;
      default:
        UNREACHABLE();
    }

    if (err)
      break;

    cur->next = nullptr;

    if (last != nullptr)
      last->next = cur;

    last = cur;
  }

  if (err == 0)
    err = ares_set_servers_ports(channel_->channel(), &servers[0]);
  else
    err = ARES_EBADSTR;

  if (err == ARES_SUCCESS)
    set_default_servers(false);

  return err;
}

void DNSContext::Cancel() {
  // TODO(@jasnell): Re-enable trace events
  // TRACE_EVENT_INSTANT0(TRACING_CATEGORY_NODE2(dns, native),
  //     "cancel", TRACE_EVENT_SCOPE_THREAD);

  ares_cancel(channel_->channel());
}

void DNSContext::SetLocalAddress(
    Environment* env,
    const char* ip,
    const char* other) {

  unsigned char addr0[sizeof(struct in6_addr)];
  unsigned char addr1[sizeof(struct in6_addr)];
  int type0 = 0;

  if (uv_inet_pton(AF_INET, ip, &addr0) == 0) {
    ares_set_local_ip4(channel_->channel(), ReadUint32BE(addr0));
    type0 = 4;
  } else if (uv_inet_pton(AF_INET6, ip, &addr0) == 0) {
    ares_set_local_ip6(channel_->channel(), addr0);
    type0 = 6;
  } else {
    return THROW_ERR_INVALID_ARG_VALUE(env, "Invalid IP address.");
  }

  if (other != nullptr) {
    if (uv_inet_pton(AF_INET, other, &addr1) == 0) {
      if (type0 == 4) {
        return THROW_ERR_INVALID_ARG_VALUE(
            env, "Cannot specify two IPv4 addresses.");
      } else {
        ares_set_local_ip4(channel_->channel(), ReadUint32BE(addr1));
      }
    } else if (uv_inet_pton(AF_INET6, other, &addr1) == 0) {
      if (type0 == 6) {
        return THROW_ERR_INVALID_ARG_VALUE(
            env, "Cannot specify two IPv6 addresses.");
      } else {
        ares_set_local_ip6(channel_->channel(), addr1);
      }
    } else {
      return THROW_ERR_INVALID_ARG_VALUE(env, "Invalid IP address.");
    }
  } else {
    // No second arg specifed
    if (type0 == 4) {
      memset(&addr1, 0, sizeof(addr1));
      ares_set_local_ip6(channel_->channel(), addr1);
    } else {
      ares_set_local_ip4(channel_->channel(), 0);
    }
  }
}

void DNSContext::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  CHECK(args[0]->IsInt32());  // timeout
  Environment* env = Environment::GetCurrent(args);
  DNSContext::Options options;
  options.channel_options.timeout = args[0].As<Int32>()->Value();
  new DNSContext(env, args.This(), options);
}

void DNSContext::Initialize(Environment* env, Local<Object> target) {
  Local<FunctionTemplate> ctx = env->NewFunctionTemplate(DNSContext::New);
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "DNSContext");
  ctx->SetClassName(class_name);
  ctx->Inherit(AsyncWrap::GetConstructorTemplate(env));
  ctx->InstanceTemplate()->SetInternalFieldCount(
      DNSContext::kInternalFieldCount);

  env->SetProtoMethod(ctx, "queryAny", Query<QueryAnyWrap>);
  env->SetProtoMethod(ctx, "queryA", Query<QueryAWrap>);
  env->SetProtoMethod(ctx, "queryAaaa", Query<QueryAAAAWrap>);
  env->SetProtoMethod(ctx, "queryCaa", Query<QueryCaaWrap>);
  env->SetProtoMethod(ctx, "queryCname", Query<QueryCnameWrap>);
  env->SetProtoMethod(ctx, "queryMx", Query<QueryMxWrap>);
  env->SetProtoMethod(ctx, "queryNs", Query<QueryNsWrap>);
  env->SetProtoMethod(ctx, "queryTxt", Query<QueryTxtWrap>);
  env->SetProtoMethod(ctx, "querySrv", Query<QuerySrvWrap>);
  env->SetProtoMethod(ctx, "queryPtr", Query<QueryPtrWrap>);
  env->SetProtoMethod(ctx, "queryNaptr", Query<QueryNaptrWrap>);
  env->SetProtoMethod(ctx, "querySoa", Query<QuerySoaWrap>);
  env->SetProtoMethod(ctx, "getHostByAddr", Query<GetHostByAddrWrap>);

  env->SetProtoMethodNoSideEffect(ctx, "getServers", GetServersList);
  env->SetProtoMethod(ctx, "setServers", SetServersList);
  env->SetProtoMethod(ctx, "setLocalAddress", SetLocalAddressAPI);
  env->SetProtoMethod(ctx, "cancel", CancelAPI);

  target->Set(
      env->context(),
      class_name,
      ctx->GetFunction(env->context()).ToLocalChecked()).Check();
}

DNSContext::DNSContext(
    Environment* env,
    Local<Object> object,
    const Options& options)
    : AsyncWrap(env, object, AsyncWrap::PROVIDER_DNSCONTEXT),
      options_(options) {
  MakeWeak();
  Setup();
  set_default_servers();
  set_last_query_ok();
}

DNSContext::~DNSContext() {
  for (auto iter = tasks_.begin(); iter != tasks_.end(); ++iter)
    RemoveTask(iter->first);
}

void DNSContext::Setup() {
  channel_ = std::make_unique<DNSChannel>(options_.channel_options);
  last_status_ = channel_->last_status();
}

void DNSContext::EnsureServers() {
  // If the last query is OK or servers are set by the user, do not check.
  if (CheckFlag(Flags::LAST_QUERY_OK) ||
      !CheckFlag(Flags::DEFAULT_SERVERS) ||
      last_status_ != ARES_SUCCESS) {
    return;
  }

  ares_addr_port_node* servers = nullptr;
  ares_get_servers_ports(channel_->channel(), &servers);
  if (servers == nullptr)
    return;

  DeleteFnPtr<void, ares_free_data> delete_me(servers);

  // If no server or multiple servers, ignore.
  // If the only server is not 127.0.0.1, ignore.
  if (servers->next != nullptr ||
      servers[0].family != AF_INET ||
      servers[0].addr.addr4.s_addr != htonl(INADDR_LOOPBACK) ||
      servers[0].tcp_port != 0 ||
      servers[0].udp_port != 0) {
    set_default_servers(false);
    return;
  }

  // Reset the timer and channel
  CloseTimer();
  Setup();
}

void DNSContext::OnTimeout() {
  ares_process_fd(channel_->channel(), ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

void DNSContext::StartTimer() {
  if (timer_ == nullptr) {
    timer_ = new uv_timer_t();
    timer_->data = static_cast<void*>(this);
    uv_timer_init(env()->event_loop(), timer_);
  } else if (uv_is_active(reinterpret_cast<uv_handle_t*>(timer_))) {
    return;
  }

  int timeout = options_.channel_options.timeout;
  if (timeout == 0)
    timeout = 1;
  if (timeout < 0 || timeout > kMaxTimeout)
    timeout = kMaxTimeout;
  uv_timer_start(timer_, AresTimeout, timeout, timeout);
}

void DNSContext::CloseTimer() {
  if (timer_ == nullptr)
    return;

  env()->CloseHandle(timer_, [](uv_timer_t* handle) {
    std::unique_ptr<uv_timer_t> delete_me(handle);
  });
  timer_ = nullptr;
}

NodeAresTask* DNSContext::FindOrCreateTask(ares_socket_t sock) {
  NodeAresTask* task;
  auto it = tasks_.find(sock);
  if (it != tasks_.end()) {
     task = it->second.get();
  } else {
    task = (tasks_[sock] = NodeAresTask::Create(this, sock)).get();
  }
  StartTimer();
  return task;
}

void DNSContext::RemoveTask(ares_socket_t sock) {
  auto it = tasks_.find(sock);
  if (it != tasks_.end()) {
    NodeAresTask::Close(env(), it->second.release());
    tasks_.erase(it);
  }

  if (tasks_.empty())
    CloseTimer();
}

void DNSContext::OnSockState(ares_socket_t sock, int read, int write) {
  if (read || write) {
    NodeAresTask* task = FindOrCreateTask(sock);
    if (task != nullptr)
      task->PollStart(env(), read, write);
  } else {
    RemoveTask(sock);
  }
}

void DNSContext::OnPoll(NodeAresTask* task, int status, int events) {
  uv_timer_again(timer_);
  ares_process_fd(
      channel_->channel(),
      status < 0 || events & UV_READABLE ? task->sock() : ARES_SOCKET_BAD,
      status < 0 || events & UV_WRITABLE ? task->sock() : ARES_SOCKET_BAD);
}

std::unique_ptr<NodeAresTask> NodeAresTask::Create(
    DNSContext* context,
    ares_socket_t sock) {
  std::unique_ptr<NodeAresTask> task =
      std::make_unique<NodeAresTask>(context, sock);

  if (uv_poll_init_socket(
          context->env()->event_loop(),
          &task->poll_watcher_,
          sock) < 0) {
    return std::unique_ptr<NodeAresTask>();
  }

  return task;
}

void NodeAresTask::Close(Environment* env, NodeAresTask* task) {
  env->CloseHandle(&task->poll_watcher_, [](uv_poll_t* watcher) {
    std::unique_ptr<NodeAresTask> delete_me(
        ContainerOf(&NodeAresTask::poll_watcher_, watcher));
  });
}

NodeAresTask* NodeAresTask::FromPollWatcher(uv_poll_t* handle) {
  return ContainerOf(&NodeAresTask::poll_watcher_, handle);
}

void NodeAresTask::PollStart(Environment* env, bool read, bool write) {
  uv_poll_start(
      &poll_watcher_,
      (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0),
      AresPollCallback);
}

ResponseData::ResponseData(
    int status_,
    unsigned char* answer_buf,
    int answer_len)
    : status(status_),
      is_host(false) {
  unsigned char* buf_copy = nullptr;
  if (status == ARES_SUCCESS) {
    buf_copy = node::Malloc<unsigned char>(answer_len);
    memcpy(buf_copy, answer_buf, answer_len);
  }
  this->buf = MallocedBuffer<unsigned char>(buf_copy, answer_len);
}

ResponseData::ResponseData(int status_, HostEntPointer host_)
    : status(status_),
      is_host(true),
      host(std::move(host_)) {}

void SafeFreeHostent(struct hostent* host) {
  int idx;

  if (host->h_addr_list != nullptr) {
    idx = 0;
    while (host->h_addr_list[idx]) {
      free(host->h_addr_list[idx++]);
    }
    free(host->h_addr_list);
    host->h_addr_list = nullptr;
  }

  if (host->h_aliases != nullptr) {
    idx = 0;
    while (host->h_aliases[idx]) {
      free(host->h_aliases[idx++]);
    }
    free(host->h_aliases);
    host->h_aliases = nullptr;
  }

  free(host->h_name);
  free(host);
}

int QueryAnyTraits::Parse(
    QueryAnyWrap* wrap,
    const ResponseData& response_data,
    std::vector<Local<Value>>* vec,
    Local<Value>* extra) {
#define V(key, _, __)                                                         \
  do {                                                                        \
    int err = Parse##key(wrap->env(), response_data, vec, DNSParseFlag::ANY); \
    if (err != ARES_SUCCESS)                                                  \
      return err;                                                             \
  } while(0);
  DNS_RECORD_TYPES(V)
#undef V
  return ARES_SUCCESS;
}

#define V(key, _, __)                                                         \
  int Query##key##Traits::Parse(                                              \
      Query##key##Wrap* wrap,                                                 \
      const ResponseData& response_data,                                      \
      std::vector<Local<Value>>* vec,                                         \
      Local<Value>* extra) {                                                  \
    return Parse##key(wrap->env(), response_data, vec, DNSParseFlag::ONLY);   \
  }
  DNS_RECORD_TYPES(V)
#undef V

int GetHostByAddrTraits::Send(GetHostByAddrWrap* wrap) {
  int length;
  int family;
  char address_buffer[sizeof(struct in6_addr)];
  const char* name = wrap->name().c_str();
  if (uv_inet_pton(AF_INET, name, &address_buffer) == 0) {
    length = sizeof(struct in_addr);
    family = AF_INET;
  } else if (uv_inet_pton(AF_INET6, name, &address_buffer) == 0) {
    length = sizeof(struct in6_addr);
    family = AF_INET6;
  } else {
    return UV_EINVAL;  // So errnoException() reports a proper error.
  }

  // TODO(@jasnell): Re-enable trace events
  // TRACE_EVENT_NESTABLE_ASYNC_BEGIN2(
  //     TRACING_CATEGORY_NODE2(dns, native), "reverse", this,
  //     "name", TRACE_STR_COPY(name),
  //     "family", family == AF_INET ? "ipv4" : "ipv6");

  ares_gethostbyaddr(wrap->channel(),
                      address_buffer,
                      length,
                      family,
                      Callback,
                      wrap);
  return ARES_SUCCESS;
}

void GetHostByAddrTraits::Callback(
    void* arg,
    int status,
    int timeouts,
    struct hostent* host) {
  GetHostByAddrWrap* wrap = static_cast<GetHostByAddrWrap*>(arg);
  if (wrap == nullptr) return;

  HostEntPointer host_copy;
  if (status == ARES_SUCCESS) {
    host_copy.reset(node::Malloc<hostent>(1));
    CaresWrapHostentCopy(host_copy.get(), host);
  }

  wrap->HandleResponse(ResponseData(status, std::move(host_copy)));
}

int GetHostByAddrTraits::Parse(
    GetHostByAddrWrap* wrap,
    const ResponseData& response_data,
    std::vector<v8::Local<v8::Value>>* vec,
    v8::Local<v8::Value>* extra) {
  if (!response_data.is_host)
    return ARES_EBADRESP;
  for (uint32_t i = 0; response_data.host->h_aliases[i] != nullptr; ++i) {
    vec->push_back(
        OneByteString(
            wrap->env()->isolate(),
            response_data.host->h_aliases[i]));
  }
  return ARES_SUCCESS;
}

void cares::Initialize(Environment* env, v8::Local<v8::Object> target) {
  env->SetMethodNoSideEffect(target, "strerror", StrError);

  DNSContext::Initialize(env, target);

  Local<FunctionTemplate> qrw =
      BaseObject::MakeLazilyInitializedJSTemplate(env);
  qrw->Inherit(AsyncWrap::GetConstructorTemplate(env));
  Local<String> class_name =
      FIXED_ONE_BYTE_STRING(env->isolate(), "QueryWrap");
  qrw->SetClassName(class_name);
  target->Set(env->context(),
              class_name,
              qrw->GetFunction(env->context()).ToLocalChecked()).Check();
}

}  // namespace dns
}  // namespace node
