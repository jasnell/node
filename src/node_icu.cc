#if defined(NODE_HAVE_I18N_SUPPORT)

#include "node.h"
#include "node_buffer.h"
#include "node_icu.h"

#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "string_bytes.h"
#include "v8.h"

#include <unicode/utypes.h>
#include <unicode/ucsdet.h>
#include <unicode/ustring.h>
#include <unicode/ucnv.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>

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

#define GET_DATA(isolate, val, name, buf)                                     \
  CHECK((val)->IsString());                                                   \
  Local<String> name = (val).As<String>();                                    \
  char* name##_data = buf;                                                    \
  const size_t name##_length = StringBytes::Size(isolate, name, BINARY);      \
  size_t name##_actual = 0;                                                   \
  if (name##_length > 0) {                                                    \
    if (name##_length >= sizeof(buf))                                         \
      name##_data = static_cast<char*>(malloc(name##_length));                \
    if (name##_data != nullptr) {                                             \
      name##_actual = StringBytes::Write(isolate,                             \
                                         name##_data,                         \
                                         name##_length,                       \
                                         name,                                \
                                         BINARY);                             \
      CHECK_LE(name##_actual, name##_length);                                 \
      if (name##_actual < name##_length && name##_data != buf) {              \
        name##_data = static_cast<char*>(realloc(name##_data, name##_actual));\
        CHECK_NE(name##_data, nullptr);                                       \
      }                                                                       \
    }                                                                         \
  }

#define OPEN_CONVERTER(conv, name, status)                                    \
  conv = ucnv_open(name, &status);                                            \
  if (U_FAILURE(status))                                                      \
    goto error;                                                               \
  status = U_ZERO_ERROR;

#define BOOLEAN_OPTION(env, options, name)                                    \
  options->Get(env->context(), FIXED_ONE_BYTE_STRING(                         \
      env->isolate(), name)).ToLocalChecked()->BooleanValue();

namespace node {

namespace ICU {

using v8::ArrayBuffer;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Isolate;
using v8::HandleScope;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;
using v8::Uint8Array;
using v8::Uint32;
using v8::Maybe;
using v8::EscapableHandleScope;

// Charset Detection

const char* DetectCharset(const char* data, size_t len) {
  const char* ret = nullptr;
  UErrorCode status = U_ZERO_ERROR;
  UCharsetDetector* detector = ucsdet_open(&status);
  ucsdet_setText(detector, data, len, &status);
  const UCharsetMatch* match = ucsdet_detect(detector, &status);
  if (match == nullptr)
    goto done;  // No match!
  ret = ucsdet_getName(match, &status);

 done:
  ucsdet_close(detector);
  return ret;
}

void DetectCharsets(Isolate* isolate,
                            Local<Object> results,
                            const char* data,
                            size_t len) {
  UErrorCode status = U_ZERO_ERROR;
  UCharsetDetector* detector = ucsdet_open(&status);
  ucsdet_setText(detector, data, len, &status);
  int32_t matches;
  int32_t n = 0;
  const UCharsetMatch** match = ucsdet_detectAll(detector, &matches, &status);

  for (; n < matches; n++, match++) {
    const UCharsetMatch* m = *match;
    const char* name = ucsdet_getName(m, &status);
    int32_t confidence = ucsdet_getConfidence(m, &status);
    results->Set(OneByteString(isolate, name),
                 Integer::New(isolate, confidence));
  }
  ucsdet_close(detector);
}

void DetectEncodings(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  CHECK(args[1]->IsObject());

  DetectCharsets(env->isolate(),
                 args[1].As<Object>(),
                 ts_obj_data,
                 ts_obj_length);
}

void DetectEncoding(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  const char* name = DetectCharset(ts_obj_data, ts_obj_length);
  if (name != nullptr)
    args.GetReturnValue().Set(OneByteString(env->isolate(), name));
}

void DetectEncodingsString(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  CHECK(args[1]->IsObject());

  char buf[1024];

  GET_DATA(env->isolate(), args[0], string, buf);
  if (string_data == nullptr)
    return;

  DetectCharsets(env->isolate(),
                 args[1].As<Object>(),
                 string_data,
                 string_actual);

  if (string_data != buf)
    free(string_data);
}

void DetectEncodingString(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());

  char buf[1024];
  const char * name;

  GET_DATA(env->isolate(), args[0], string, buf);
  if (string_data == nullptr)
    return;

  name = DetectCharset(string_data, string_actual);
  if (name != nullptr)
    args.GetReturnValue().Set(OneByteString(env->isolate(), name));

  if (string_data != buf)
    free(string_data);
}

// One-Shot Converters

// Converts the Buffer from one named encoding to another.
// args[0] is a string identifying the encoding we're converting to.
// args[1] is a string identifying the encoding we're converting from.
// args[2] must be a buffer instance
// args[3] is the options object (currently unused);
void Convert(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  CHECK(args[1]->IsString());
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[2]);

  Utf8Value to_name(env->isolate(), args[0]);
  Utf8Value from_name(env->isolate(), args[1]);

  SPREAD_ARG(args[2], ts_obj);

  UConverter* to_conv = nullptr;
  UConverter* from_conv = nullptr;
  UErrorCode status = U_ZERO_ERROR;

  const char* data = ts_obj_data;
  char* buf;
  char* target;
  uint32_t len, limit;

  OPEN_CONVERTER(to_conv, *to_name, status);
  OPEN_CONVERTER(from_conv, *from_name, status);

  ucnv_setSubstChars(to_conv, "?", 1, &status);
  status = U_ZERO_ERROR;

  limit = ts_obj_length * ucnv_getMaxCharSize(to_conv);
  buf = static_cast<char*>(malloc(limit));
  target = buf;

  ucnv_convertEx(to_conv, from_conv,
                 &target, target + limit,
                 &data, data + ts_obj_length,
                 NULL, NULL, NULL, NULL,
                 true, true,
                 &status);

  if (U_SUCCESS(status)) {
    len = target - buf;
    if (len < limit)
      buf = static_cast<char*>(realloc(buf, len));
    args.GetReturnValue().Set(
      Buffer::New(env->isolate(), buf, len).ToLocalChecked());
    goto cleanup;
  }

 error:
  env->ThrowError(u_errorName(status));

 cleanup:
  if (to_conv != nullptr)
    ucnv_close(to_conv);
  if (from_conv != nullptr)
    ucnv_close(from_conv);
}

// Converts to UCS2 from ISO-8859-1 and US-ASCII
// args[0] is the encoding to convert from
// args[1] must be a buffer instance
// args[2] is the options object (currently unused)
void ConvertToUcs2(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[1]);

  Utf8Value name(env->isolate(), args[0]);

  SPREAD_ARG(args[1], ts_obj);

  UConverter* to_conv = nullptr;
  UErrorCode status = U_ZERO_ERROR;
  size_t len;

  UChar* target = reinterpret_cast<UChar*>(malloc(ts_obj_length));

  OPEN_CONVERTER(to_conv, *name, status);

  len = ucnv_toUChars(to_conv,
                      target, ts_obj_length << 1,
                      ts_obj_data, ts_obj_length,
                      &status);

  if (U_SUCCESS(status)) {
    if (len < ts_obj_length)
      target = static_cast<UChar*>(realloc(target, len));
    if (IsBigEndian()) {
      uint16_t* dst = reinterpret_cast<uint16_t*>(target);
      SwapBytes(dst, dst, len);
    }
    args.GetReturnValue().Set(
      Buffer::New(env->isolate(),
                  reinterpret_cast<char*>(target),
                  ts_obj_length << 1).ToLocalChecked());
    goto cleanup;
  }

 error:
  env->ThrowError(u_errorName(status));

 cleanup:
  if (to_conv != nullptr)
    ucnv_close(to_conv);
}

// Convert to a named encoding from UCS2
// args[0] is the name of the encoding being converted to
// args[1] must be a buffer instance
// args[2] is the options object (current unused)
void ConvertFromUcs2(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[1]);

  Utf8Value name(env->isolate(), args[0]);
  SPREAD_ARG(args[1], ts_obj);

  UConverter* to_conv = nullptr;
  UErrorCode status = U_ZERO_ERROR;

  UChar* source = nullptr;
  bool release = false;

  if (IsLittleEndian()) {
    source = reinterpret_cast<UChar*>(ts_obj_data);
  } else {
    source = static_cast<UChar*>(malloc(ts_obj_length >> 1));
    for (size_t n = 0, i = 0; i < ts_obj_length; n += 2, i += 1) {
      const uint8_t hi = static_cast<uint8_t>(ts_obj_data[n + 0]);
      const uint8_t lo = static_cast<uint8_t>(ts_obj_data[n + 1]);
      source[i] = (hi << 8) | lo;
    }
    release = true;
  }

  // Because this is used only for conversion into
  // single byte encoding, we don't have to preflight.
  uint32_t len;
  uint32_t length = ts_obj_length >> 1;
  char* target = static_cast<char*>(malloc(length));

  OPEN_CONVERTER(to_conv, *name, status);

  ucnv_setSubstChars(to_conv, "?", 1, &status);
  status = U_ZERO_ERROR;

  len = ucnv_fromUChars(to_conv,
                        target, length,
                        source, length,
                        &status);

  if (U_SUCCESS(status)) {
    if (len < length)
      target = static_cast<char*>(realloc(target, len));
    args.GetReturnValue().Set(
      Buffer::New(env->isolate(), target, len).ToLocalChecked());
    goto cleanup;
  }

 error:
  env->ThrowError(u_errorName(status));

 cleanup:
  if (release)
    free(source);
  if (to_conv != nullptr)
    ucnv_close(to_conv);
}

// Converts from UTF-8 to UCS2
// args[0] must be a buffer instance
// args[1] is the options object
//   options.lenient = true | false
void Ucs2FromUtf8(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  Local<Object> options = args[2].As<Object>();
  const bool lenient = BOOLEAN_OPTION(env, options, "lenient")

  UErrorCode status = U_ZERO_ERROR;

  UChar buf[2048];
  UChar* target = buf;
  int32_t len;

  if (lenient) {
    u_strFromUTF8Lenient(target, 2048, &len,
                         ts_obj_data, ts_obj_length,
                         &status);
  } else {
    u_strFromUTF8(target, 2048, &len,
                  ts_obj_data, ts_obj_length,
                  &status);
  }

  if (U_SUCCESS(status)) {
    // Used the static buf, just copy it into the new Buffer instance.
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(),
                   reinterpret_cast<char*>(target),
                   len * sizeof(UChar)).ToLocalChecked());
    return;
  } else if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    // The static buf was not large enough, try again with an allocated buf
    target = static_cast<UChar*>(malloc(len));
    if (lenient) {
      u_strFromUTF8Lenient(target, len, &len,
                           ts_obj_data, ts_obj_length,
                           &status);
    } else {
      u_strFromUTF8(target, len, &len,
                    ts_obj_data, ts_obj_length,
                    &status);
    }
    if (U_FAILURE(status))
      goto error;
    // The Buffer takes ownership of the allocated memory. No need to free.
    if (IsBigEndian()) {
      uint16_t* dst = reinterpret_cast<uint16_t*>(target);
      SwapBytes(dst, dst, len);
    }
    args.GetReturnValue().Set(
      Buffer::New(env->isolate(),
                  reinterpret_cast<char*>(target),
                  len << 1).ToLocalChecked());
    return;
  }

 error:
  env->ThrowError(u_errorName(status));
}

// Converts UCS2 into UTF-8
// args[0] must be a buffer instance
// args[1] is the options object (currently unused)
void Utf8FromUcs2(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  UChar* source = nullptr;
  bool release = false;

  if (IsLittleEndian()) {
    source = reinterpret_cast<UChar*>(ts_obj_data);
  } else {
    source = static_cast<UChar*>(malloc(ts_obj_length >> 1));
    for (size_t n = 0, i = 0; i < ts_obj_length; n += 2, i += 1) {
      const uint8_t hi = static_cast<uint8_t>(ts_obj_data[n + 0]);
      const uint8_t lo = static_cast<uint8_t>(ts_obj_data[n + 1]);
      source[i] = (hi << 8) | lo;
    }
    release = true;
  }

  UErrorCode status = U_ZERO_ERROR;

  char buf[2048];
  char* target = buf;
  int32_t len;

  u_strToUTF8(target, 2048, &len, source, ts_obj_length >> 1, &status);
  if (U_SUCCESS(status)) {
    // Used the static buf, just copy it into the new Buffer instance.
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(), buf, len).ToLocalChecked());
    goto cleanup;
  } else if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    // The static buf was not large enough, try again with an allocated buf
    target = static_cast<char*>(malloc(len));
    u_strToUTF8(target, len, &len, source, ts_obj_length >> 1, &status);
    if (U_FAILURE(status))
      goto error;
    // The Buffer takes ownership of the allocated memory. No need to free.
    args.GetReturnValue().Set(
      Buffer::New(env->isolate(), target, len).ToLocalChecked());
    goto cleanup;
  }

 error:
  env->ThrowError(u_errorName(status));

 cleanup:
  if (release)
    free(source);
}

/**
 * Get's the codepoint at a given offset for UTF-8 or UCS2
 * args[0] must be a buffer instance
 * args[1] must be a boolean, true == utf8, false = ucs2
 * args[2] must be the integer offset within the buffer to check
 **/
void GetCodePointAt(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  CHECK(args[1]->IsBoolean());
  CHECK(args[2]->IsUint32());

  bool utf8 = args[1]->BooleanValue();
  uint32_t pos = args[2]->Uint32Value();
  UChar32 codepoint = 0;

  if (utf8) {
    U8_GET_UNSAFE(ts_obj_data, pos, codepoint);
  } else {
    if (IsBigEndian()) {
      const uint32_t len = ts_obj_length >> 1;
      UChar* copy = static_cast<UChar*>(malloc(len));
      for (uint32_t n = 0, i = 0; n < len; n += 1, i += 2) {
        uint8_t hi = ts_obj_data[i + 0];
        uint8_t lo = ts_obj_data[i + 1];
        copy[n] = (hi << 8) | lo;
      }
      U16_GET_UNSAFE(copy, pos >> 1, codepoint);
      free(copy);
    } else {
      UChar* source = reinterpret_cast<UChar*>(ts_obj_data);
      U16_GET_UNSAFE(source, pos >> 1, codepoint);
    }
  }
  args.GetReturnValue().Set(Uint32::NewFromUnsigned(env->isolate(),
                                                    codepoint));
}

void GetCharAt(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  CHECK(args[1]->IsBoolean());
  CHECK(args[2]->IsUint32());

  bool utf8 = args[1]->BooleanValue();
  uint32_t pos = args[2]->Uint32Value();
  UChar32 codepoint = 0;

  if (utf8) {
    U8_GET_UNSAFE(ts_obj_data, pos, codepoint);
  } else {
    if (IsBigEndian()) {
      const uint32_t len = ts_obj_length >> 1;
      UChar* copy = static_cast<UChar*>(malloc(len));
      for (uint32_t n = 0, i = 0; n < len; n += 1, i += 2) {
        uint8_t hi = ts_obj_data[i + 0];
        uint8_t lo = ts_obj_data[i + 1];
        copy[n] = (hi << 8) | lo;
      }
      U16_GET_UNSAFE(copy, pos >> 1, codepoint);
      free(copy);
    } else {
      UChar* source = reinterpret_cast<UChar*>(ts_obj_data);
      U16_GET_UNSAFE(source, pos >> 1, codepoint);
    }
  }

  UChar* c = static_cast<UChar*>(malloc(U16_LENGTH(codepoint)));
  int i = 0;
  U16_APPEND_UNSAFE(c, i, codepoint);
  args.GetReturnValue().Set(
    String::NewFromTwoByte(env->isolate(), c,
                           String::kNormalString,
                           U16_LENGTH(codepoint)));
  free(c);
}

// Initialization

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context) {
  Environment* env = Environment::GetCurrent(context);

  // Encoding Detection
  env->SetMethod(target, "detectEncoding", DetectEncoding);
  env->SetMethod(target, "detectEncodings", DetectEncodings);
  env->SetMethod(target, "detectEncodingString", DetectEncodingString);
  env->SetMethod(target, "detectEncodingsString", DetectEncodingsString);

  // One-Shot Converters.
  env->SetMethod(target, "convert", Convert);
  env->SetMethod(target, "convertFromUcs2", ConvertFromUcs2);
  env->SetMethod(target, "convertToUcs2", ConvertToUcs2);
  env->SetMethod(target, "convertToUcs2FromUtf8", Ucs2FromUtf8);
  env->SetMethod(target, "convertToUtf8FromUcs2", Utf8FromUcs2);

  // Utilities
  env->SetMethod(target, "getCodePointAt", GetCodePointAt);
  env->SetMethod(target, "getCharAt", GetCharAt);
}

}  // namespace ICU
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(icu, node::ICU::Initialize)

#endif  // NODE_HAVE_I18N_SUPPORT
