/*
 * notes: by srl295
 *  - When in NODE_HAVE_SMALL_ICU mode, ICU is linked against "stub" (null) data
 *     ( stubdata/libicudata.a ) containing nothing, no data, and it's also
 *    linked against a "small" data file which the SMALL_ICUDATA_ENTRY_POINT
 *    macro names. That's the "english+root" data.
 *
 *    If icu_data_path is non-null, the user has provided a path and we assume
 *    it goes somewhere useful. We set that path in ICU, and exit.
 *    If icu_data_path is null, they haven't set a path and we want the
 *    "english+root" data.  We call
 *       udata_setCommonData(SMALL_ICUDATA_ENTRY_POINT,...)
 *    to load up the english+root data.
 *
 *  - when NOT in NODE_HAVE_SMALL_ICU mode, ICU is linked directly with its full
 *    data. All of the variables and command line options for changing data at
 *    runtime are disabled, as they wouldn't fully override the internal data.
 *    See:  http://bugs.icu-project.org/trac/ticket/10924
 */


#include "node_i18n.h"

#if defined(NODE_HAVE_I18N_SUPPORT)

#include "node.h"
#include "node_buffer.h"
#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8.h"

#include <unicode/putil.h>
#include <unicode/udata.h>
#include <unicode/uidna.h>
#include <unicode/utypes.h>
#include <unicode/ustring.h>
#include <unicode/ucnv.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>

#include <stdio.h>

#ifdef NODE_HAVE_SMALL_ICU
/* if this is defined, we have a 'secondary' entry point.
   compare following to utypes.h defs for U_ICUDATA_ENTRY_POINT */
#define SMALL_ICUDATA_ENTRY_POINT \
  SMALL_DEF2(U_ICU_VERSION_MAJOR_NUM, U_LIB_SUFFIX_C_NAME)
#define SMALL_DEF2(major, suff) SMALL_DEF(major, suff)
#ifndef U_LIB_SUFFIX_C_NAME
#define SMALL_DEF(major, suff) icusmdt##major##_dat
#else
#define SMALL_DEF(major, suff) icusmdt##suff##major##_dat
#endif

extern "C" const char U_DATA_API SMALL_ICUDATA_ENTRY_POINT[];
#endif

namespace node {

using v8::ArrayBuffer;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Uint32;
using v8::Uint8Array;
using v8::Value;

bool flag_icu_data_dir = false;

namespace i18n {

#define THROW_AND_RETURN_UNLESS_BUFFER(env, obj)                              \
  do {                                                                        \
    if (!Buffer::HasInstance(obj))                                            \
      return env->ThrowTypeError("argument must be a Buffer");                \
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

#define OPEN_CONVERTER(conv, name, status)                                    \
  conv = ucnv_open(name, &status);                                            \
  if (U_FAILURE(status))                                                      \
    goto error;                                                               \
  status = U_ZERO_ERROR;

bool InitializeICUDirectory(const char* icu_data_path) {
  if (icu_data_path != nullptr) {
    flag_icu_data_dir = true;
    u_setDataDirectory(icu_data_path);
    return true;  // no error
  } else {
    UErrorCode status = U_ZERO_ERROR;
#ifdef NODE_HAVE_SMALL_ICU
    // install the 'small' data.
    udata_setCommonData(&SMALL_ICUDATA_ENTRY_POINT, &status);
#else  // !NODE_HAVE_SMALL_ICU
    // no small data, so nothing to do.
#endif  // !NODE_HAVE_SMALL_ICU
    return (status == U_ZERO_ERROR);
  }
}

static int32_t ToUnicode(MaybeStackBuffer<char>* buf,
                         const char* input,
                         size_t length) {
  UErrorCode status = U_ZERO_ERROR;
  uint32_t options = UIDNA_DEFAULT;
  options |= UIDNA_NONTRANSITIONAL_TO_UNICODE;
  UIDNA* uidna = uidna_openUTS46(options, &status);
  if (U_FAILURE(status))
    return -1;
  UIDNAInfo info = UIDNA_INFO_INITIALIZER;

  int32_t len = uidna_nameToUnicodeUTF8(uidna,
                                        input, length,
                                        **buf, buf->length(),
                                        &info,
                                        &status);

  if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    buf->AllocateSufficientStorage(len);
    len = uidna_nameToUnicodeUTF8(uidna,
                                  input, length,
                                  **buf, buf->length(),
                                  &info,
                                  &status);
  }

  if (U_FAILURE(status))
    len = -1;

  uidna_close(uidna);
  return len;
}

static int32_t ToASCII(MaybeStackBuffer<char>* buf,
                       const char* input,
                       size_t length) {
  UErrorCode status = U_ZERO_ERROR;
  uint32_t options = UIDNA_DEFAULT;
  options |= UIDNA_NONTRANSITIONAL_TO_ASCII;
  UIDNA* uidna = uidna_openUTS46(options, &status);
  if (U_FAILURE(status))
    return -1;
  UIDNAInfo info = UIDNA_INFO_INITIALIZER;

  int32_t len = uidna_nameToASCII_UTF8(uidna,
                                       input, length,
                                       **buf, buf->length(),
                                       &info,
                                       &status);

  if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    buf->AllocateSufficientStorage(len);
    len = uidna_nameToASCII_UTF8(uidna,
                                 input, length,
                                 **buf, buf->length(),
                                 &info,
                                 &status);
  }

  if (U_FAILURE(status))
    len = -1;

  uidna_close(uidna);
  return len;
}

static void ToUnicode(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK_GE(args.Length(), 1);
  CHECK(args[0]->IsString());
  Utf8Value val(env->isolate(), args[0]);
  MaybeStackBuffer<char> buf;
  int32_t len = ToUnicode(&buf, *val, val.length());

  if (len < 0) {
    return env->ThrowError("Cannot convert name to Unicode");
  }

  args.GetReturnValue().Set(
      String::NewFromUtf8(env->isolate(),
                          *buf,
                          v8::NewStringType::kNormal,
                          len).ToLocalChecked());
}

static void ToASCII(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK_GE(args.Length(), 1);
  CHECK(args[0]->IsString());
  Utf8Value val(env->isolate(), args[0]);
  MaybeStackBuffer<char> buf;
  int32_t len = ToASCII(&buf, *val, val.length());

  if (len < 0) {
    return env->ThrowError("Cannot convert name to ASCII");
  }

  args.GetReturnValue().Set(
      String::NewFromUtf8(env->isolate(),
                          *buf,
                          v8::NewStringType::kNormal,
                          len).ToLocalChecked());
}

// Get's the codepoint at a given offset for UTF-8 or UCS2
// args[0] must be a buffer instance
// args[1] must be a boolean, true = utf8, false = ucs2
// args[2] must be the integer offset within the buffer to check
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
  args.GetReturnValue().Set(codepoint);
}

// Get's the char at a given offset for UTF-8 or UCS2
// args[0] must be a buffer instance
// args[1] must be a boolean, true = utf8, false = ucs2
// args[2] must be the integer offset within the buffer to check
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
                           v8::NewStringType::kNormal,
                           U16_LENGTH(codepoint)).ToLocalChecked());
  free(c);
}

// One-Shot Converters

// Converts the Buffer from one named encoding to another.
// args[0] is a string identifying the encoding we're converting to.
// args[1] is a string identifying the encoding we're converting from.
// args[2] must be a buffer instance
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

  MaybeStackBuffer<char> buf;
  uint32_t len, limit;
  char* target;
  const char* data = ts_obj_data;

  OPEN_CONVERTER(to_conv, *to_name, status);
  OPEN_CONVERTER(from_conv, *from_name, status);

  ucnv_setSubstChars(to_conv, "?", 1, &status);
  status = U_ZERO_ERROR;

  limit = ts_obj_length * ucnv_getMaxCharSize(to_conv);
  buf.AllocateSufficientStorage(ts_obj_length * ucnv_getMaxCharSize(to_conv));
  target = *buf;

  ucnv_convertEx(to_conv, from_conv,
                 &target, target + limit,
                 &data, ts_obj_data + ts_obj_length,
                 NULL, NULL, NULL, NULL,
                 true, true,
                 &status);

  if (U_SUCCESS(status)) {
    len = target - *buf;
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(), *buf, len).ToLocalChecked());
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
void ConvertToUcs2(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[1]);

  Utf8Value name(env->isolate(), args[0]);

  SPREAD_ARG(args[1], ts_obj);

  UConverter* to_conv = nullptr;
  UErrorCode status = U_ZERO_ERROR;
  size_t len;

  MaybeStackBuffer<UChar> buf;
  buf.AllocateSufficientStorage(ts_obj_length);

  OPEN_CONVERTER(to_conv, *name, status);

  len = ucnv_toUChars(to_conv,
                      *buf, ts_obj_length << 1,
                      ts_obj_data, ts_obj_length,
                      &status);

  if (U_SUCCESS(status)) {
    if (IsBigEndian()) {
      uint16_t* dst = reinterpret_cast<uint16_t*>(*buf);
      SwapBytes(dst, dst, len);
    }
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(),
                  reinterpret_cast<char*>(*buf),
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
void ConvertFromUcs2(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[0]->IsString());
  THROW_AND_RETURN_UNLESS_BUFFER(env, args[1]);

  Utf8Value name(env->isolate(), args[0]);
  SPREAD_ARG(args[1], ts_obj);

  UConverter* to_conv = nullptr;
  UErrorCode status = U_ZERO_ERROR;

  UChar* source = nullptr;
  MaybeStackBuffer<UChar> swapspace;
  const size_t length = ts_obj_length >> 1;

  if (IsLittleEndian()) {
    source = reinterpret_cast<UChar*>(ts_obj_data);
  } else {
    swapspace.AllocateSufficientStorage(length);
    source = static_cast<UChar*>(malloc(ts_obj_length >> 1));
    for (size_t n = 0, i = 0; i < length; n += 2, i += 1) {
      const uint8_t hi = static_cast<uint8_t>(ts_obj_data[n + 0]);
      const uint8_t lo = static_cast<uint8_t>(ts_obj_data[n + 1]);
      swapspace[i] = (hi << 8) | lo;
    }
    source = *swapspace;
  }

  uint32_t len;
  MaybeStackBuffer<char> buf;
  buf.AllocateSufficientStorage(length);

  OPEN_CONVERTER(to_conv, *name, status);
  ucnv_setSubstChars(to_conv, "?", 1, &status);
  status = U_ZERO_ERROR;

  len = ucnv_fromUChars(to_conv, *buf, length, source, length, &status);

  if (U_SUCCESS(status)) {
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(), *buf, len).ToLocalChecked());
    goto cleanup;
  }

 error:
  env->ThrowError(u_errorName(status));

 cleanup:
  if (to_conv != nullptr)
    ucnv_close(to_conv);
}

// Converts from UTF-8 to UCS2
// args[0] must be a buffer instance
// args[1] is a boolean, true = lenient, false = strict
void Ucs2FromUtf8(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  const bool lenient = args[1]->BooleanValue();

  UErrorCode status = U_ZERO_ERROR;

  MaybeStackBuffer<UChar> buf;
  int32_t len;

  if (lenient) {
    u_strFromUTF8Lenient(*buf, 1024, &len, ts_obj_data, ts_obj_length, &status);
  } else {
    u_strFromUTF8(*buf, 1024, &len, ts_obj_data, ts_obj_length, &status);
  }

  if (U_SUCCESS(status)) {
    // Used the static buf, just copy it into the new Buffer instance.
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(),
                   reinterpret_cast<char*>(*buf),
                   len * sizeof(UChar)).ToLocalChecked());
    return;
  } else if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    buf.AllocateSufficientStorage(len);
    if (lenient) {
      u_strFromUTF8Lenient(*buf, len, &len,
                           ts_obj_data,
                           ts_obj_length,
                           &status);
    } else {
      u_strFromUTF8(*buf, len, &len,
                    ts_obj_data,
                    ts_obj_length,
                    &status);
    }
    if (U_FAILURE(status))
      return env->ThrowError(u_errorName(status));
    if (IsBigEndian()) {
      uint16_t* dst = reinterpret_cast<uint16_t*>(*buf);
      SwapBytes(dst, dst, len);
    }
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(),
                  reinterpret_cast<char*>(*buf),
                  len << 1).ToLocalChecked());
    return;
  } else {
    return env->ThrowError(u_errorName(status));
  }
}

// Converts UCS2 into UTF-8
// args[0] must be a buffer instance
// args[1] is the options object (currently unused)
void Utf8FromUcs2(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  SPREAD_ARG(args[0], ts_obj);

  const size_t length = ts_obj_length >> 1;

  UChar* source = nullptr;
  MaybeStackBuffer<UChar> swapspace;
  if (IsLittleEndian()) {
    source = reinterpret_cast<UChar*>(ts_obj_data);
  } else {
    swapspace.AllocateSufficientStorage(length);
    for (size_t n = 0, i = 0; i < length; n += 2, i += 1) {
      const uint8_t hi = static_cast<uint8_t>(ts_obj_data[n + 0]);
      const uint8_t lo = static_cast<uint8_t>(ts_obj_data[n + 1]);
      swapspace[i] = (hi << 8) | lo;
    }
    source = *swapspace;
  }

  UErrorCode status = U_ZERO_ERROR;

  MaybeStackBuffer<char> buf;
  int32_t len;

  u_strToUTF8(*buf, 1024, &len, source, length, &status);
  if (U_SUCCESS(status)) {
    // Used the static buf, just copy it into the new Buffer instance.
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(), *buf, len).ToLocalChecked());
  } else if (status == U_BUFFER_OVERFLOW_ERROR) {
    status = U_ZERO_ERROR;
    buf.AllocateSufficientStorage(len);
    u_strToUTF8(*buf, len, &len, source, length, &status);
    if (U_FAILURE(status))
      return env->ThrowError(u_errorName(status));
    args.GetReturnValue().Set(
      Buffer::Copy(env->isolate(), *buf, len).ToLocalChecked());
  } else {
    return env->ThrowError(u_errorName(status));
  }
  return;
}

void Init(Local<Object> target,
          Local<Value> unused,
          Local<Context> context,
          void* priv) {
  Environment* env = Environment::GetCurrent(context);
  env->SetMethod(target, "toUnicode", ToUnicode);
  env->SetMethod(target, "toASCII", ToASCII);

  env->SetMethod(target, "getCodePointAt", GetCodePointAt);
  env->SetMethod(target, "getCharAt", GetCharAt);

  // One-Shot Converters.
  env->SetMethod(target, "convert", Convert);
  env->SetMethod(target, "convertFromUcs2", ConvertFromUcs2);
  env->SetMethod(target, "convertToUcs2", ConvertToUcs2);
  env->SetMethod(target, "convertToUcs2FromUtf8", Ucs2FromUtf8);
  env->SetMethod(target, "convertToUtf8FromUcs2", Utf8FromUcs2);
}

}  // namespace i18n
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(icu, node::i18n::Init)

#endif  // NODE_HAVE_I18N_SUPPORT
