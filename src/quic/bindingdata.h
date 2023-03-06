#pragma once

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "defs.h"
#include <base_object.h>
#include <env.h>
#include <memory_tracker.h>
#include <node.h>
#include <node_mem.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <v8.h>

namespace node {
namespace quic {

class BindingData;
class Endpoint;

// =============================================================================
// The BindingState object holds state for the internalBinding('quic') binding
// instance. It is mostly used to hold the persistent constructors, strings, and
// callback references used for the rest of the implementation.
//
// TODO(@jasnell): Make this snapshotable?
class BindingData final : public BaseObject,
                          public mem::NgLibMemoryManager<BindingData, ngtcp2_mem> {
 public:
  SET_BINDING_ID(quic_binding_data)
  BASEOBJECT_INIT()

  static inline BindingData& Get(Environment* env);

  BindingData(Realm* realm, v8::Local<v8::Object> object);
  QUIC_NO_COPY_OR_MOVE(BindingData)

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(BindingData);
  SET_SELF_SIZE(BindingData);

  // NgLibMemoryManager
  inline operator ngtcp2_mem() const;
  inline operator nghttp3_mem() const;
  inline void CheckAllocatedSize(size_t previous_size) const;
  inline void IncreaseAllocatedSize(size_t size);
  inline void DecreaseAllocatedSize(size_t size);

  // Installs the set of JavaScript callback functions that are used to
  // bridge out to the JS API.
  static void SetCallbacks(const v8::FunctionCallbackInfo<v8::Value>& args);

  // A set of listening Endpoints. We maintain this to ensure that the Endpoint
  // cannot be gc'd while it is still listening and there are active
  // connections.
  std::unordered_map<Endpoint*, BaseObjectPtr<Endpoint>> listening_endpoints;

  // The following set up various storage and accessors for common strings,
  // construction templates, and callbacks stored on the BindingData. These
  // are all defined in defs.h

#define V(name)                                                                \
  void set_##name##_constructor_template(                                      \
      v8::Local<v8::FunctionTemplate> tmpl);                                   \
  v8::Local<v8::FunctionTemplate> name##_constructor_template() const;
  QUIC_CONSTRUCTORS(V)
#undef V

#define V(name, _)                                                             \
  void set_##name##_callback(v8::Local<v8::Function> fn);                      \
  v8::Local<v8::Function> name##_callback() const;
  QUIC_JS_CALLBACKS(V)
#undef V

#define V(name, _) v8::Local<v8::String> name##_string() const;
  QUIC_STRINGS(V)
#undef V

#define V(name, _) v8::Local<v8::String> on_##name##_string() const;
  QUIC_JS_CALLBACKS(V)
#undef V

  size_t current_ngtcp2_memory_ = 0;

#define V(name) v8::Global<v8::FunctionTemplate> name##_constructor_template_;
  QUIC_CONSTRUCTORS(V)
#undef V

#define V(name, _) v8::Global<v8::Function> name##_callback_;
  QUIC_JS_CALLBACKS(V)
#undef V

#define V(name, _) mutable v8::Eternal<v8::String> name##_string_;
  QUIC_STRINGS(V)
#undef V

#define V(name, _) mutable v8::Eternal<v8::String> on_##name##_string_;
  QUIC_JS_CALLBACKS(V)
#undef V
};

}  // namespace quic
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
