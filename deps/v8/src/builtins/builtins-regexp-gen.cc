// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-regexp-gen.h"

#include <optional>

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/builtins/growable-fixed-array-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/common/globals.h"
#include "src/execution/protectors.h"
#include "src/heap/factory-inl.h"
#include "src/logging/counters.h"
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-regexp.h"
#include "src/objects/regexp-match-info.h"
#include "src/regexp/regexp-flags.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

// Tail calls the regular expression interpreter.
// static
void Builtins::Generate_RegExpInterpreterTrampoline(MacroAssembler* masm) {
  ExternalReference interpreter_code_entry =
      ExternalReference::re_match_for_call_from_js();
  masm->Jump(interpreter_code_entry);
}

// Tail calls the experimental regular expression engine.
// static
void Builtins::Generate_RegExpExperimentalTrampoline(MacroAssembler* masm) {
  ExternalReference interpreter_code_entry =
      ExternalReference::re_experimental_match_for_call_from_js();
  masm->Jump(interpreter_code_entry);
}

TNode<Smi> RegExpBuiltinsAssembler::SmiZero() { return SmiConstant(0); }

TNode<IntPtrT> RegExpBuiltinsAssembler::IntPtrZero() {
  return IntPtrConstant(0);
}

// -----------------------------------------------------------------------------
// ES6 section 21.2 RegExp Objects

TNode<JSRegExpResult> RegExpBuiltinsAssembler::AllocateRegExpResult(
    TNode<Context> context, TNode<Smi> length, TNode<Smi> index,
    TNode<String> input, TNode<JSRegExp> regexp, TNode<Number> last_index,
    TNode<BoolT> has_indices, TNode<FixedArray>* elements_out) {
  CSA_DCHECK(this, SmiLessThanOrEqual(
                       length, SmiConstant(JSArray::kMaxFastArrayLength)));
  CSA_DCHECK(this, SmiGreaterThan(length, SmiConstant(0)));

  // Allocate.

  Label result_has_indices(this), allocated(this);
  const ElementsKind elements_kind = PACKED_ELEMENTS;
  std::optional<TNode<AllocationSite>> no_gc_site = std::nullopt;
  TNode<IntPtrT> length_intptr = PositiveSmiUntag(length);
  // Note: The returned `var_elements` may be in young large object space, but
  // `var_array` is guaranteed to be in new space so we could skip write
  // barriers below.
  TVARIABLE(JSArray, var_array);
  TVARIABLE(FixedArrayBase, var_elements);

  GotoIf(has_indices, &result_has_indices, GotoHint::kFallthrough);
  {
    TNode<Map> map = CAST(LoadContextElementNoCell(
        LoadNativeContext(context), Context::REGEXP_RESULT_MAP_INDEX));
    std::tie(var_array, var_elements) =
        AllocateUninitializedJSArrayWithElements(
            elements_kind, map, length, no_gc_site, length_intptr,
            AllocationFlag::kNone, JSRegExpResult::kSize);
    Goto(&allocated);
  }

  BIND(&result_has_indices);
  {
    TNode<Map> map = CAST(LoadContextElementNoCell(
        LoadNativeContext(context),
        Context::REGEXP_RESULT_WITH_INDICES_MAP_INDEX));
    std::tie(var_array, var_elements) =
        AllocateUninitializedJSArrayWithElements(
            elements_kind, map, length, no_gc_site, length_intptr,
            AllocationFlag::kNone, JSRegExpResultWithIndices::kSize);
    Goto(&allocated);
  }

  BIND(&allocated);

  // Finish result initialization.

  TNode<JSRegExpResult> result =
      UncheckedCast<JSRegExpResult>(var_array.value());

  // Load undefined value once here to avoid multiple LoadRoots.
  TNode<Oddball> undefined_value = UncheckedCast<Oddball>(
      CodeAssembler::LoadRoot(RootIndex::kUndefinedValue));

  StoreObjectFieldNoWriteBarrier(result, JSRegExpResult::kIndexOffset, index);
  // TODO(jgruber,turbofan): Could skip barrier but the MemoryOptimizer
  // complains.
  StoreObjectField(result, JSRegExpResult::kInputOffset, input);
  StoreObjectFieldNoWriteBarrier(result, JSRegExpResult::kGroupsOffset,
                                 undefined_value);
  StoreObjectFieldNoWriteBarrier(result, JSRegExpResult::kNamesOffset,
                                 undefined_value);

  StoreObjectField(result, JSRegExpResult::kRegexpInputOffset, input);

  // If non-smi last_index then store an SmiZero instead.
  {
    TNode<Smi> last_index_smi = Select<Smi>(
        TaggedIsSmi(last_index), [=, this] { return CAST(last_index); },
        [=, this] { return SmiZero(); });
    StoreObjectField(result, JSRegExpResult::kRegexpLastIndexOffset,
                     last_index_smi);
  }

  Label finish_initialization(this);
  GotoIfNot(has_indices, &finish_initialization, GotoHint::kLabel);
  {
    static_assert(std::is_base_of_v<JSRegExpResult, JSRegExpResultWithIndices>,
                  "JSRegExpResultWithIndices is a subclass of JSRegExpResult");
    StoreObjectFieldNoWriteBarrier(
        result, JSRegExpResultWithIndices::kIndicesOffset, undefined_value);
    Goto(&finish_initialization);
  }

  BIND(&finish_initialization);

  // Finish elements initialization.

  FillFixedArrayWithValue(elements_kind, var_elements.value(), IntPtrZero(),
                          length_intptr, RootIndex::kUndefinedValue);

  if (elements_out) *elements_out = CAST(var_elements.value());
  return result;
}

TNode<Object> RegExpBuiltinsAssembler::FastLoadLastIndexBeforeSmiCheck(
    TNode<JSRegExp> regexp) {
  // Load the in-object field.
  static const int field_offset =
      JSRegExp::kHeaderSize + JSRegExp::kLastIndexFieldIndex * kTaggedSize;
  return LoadObjectField(regexp, field_offset);
}

TNode<JSAny> RegExpBuiltinsAssembler::SlowLoadLastIndex(TNode<Context> context,
                                                        TNode<JSAny> regexp) {
  return GetProperty(context, regexp, isolate()->factory()->lastIndex_string());
}

// The fast-path of StoreLastIndex when regexp is guaranteed to be an unmodified
// JSRegExp instance.
void RegExpBuiltinsAssembler::FastStoreLastIndex(TNode<JSRegExp> regexp,
                                                 TNode<Smi> value) {
  // Store the in-object field.
  static const int field_offset =
      JSRegExp::kHeaderSize + JSRegExp::kLastIndexFieldIndex * kTaggedSize;
  StoreObjectField(regexp, field_offset, value);
}

void RegExpBuiltinsAssembler::SlowStoreLastIndex(TNode<Context> context,
                                                 TNode<JSAny> regexp,
                                                 TNode<Object> value) {
  TNode<String> name =
      HeapConstantNoHole(isolate()->factory()->lastIndex_string());
  SetPropertyStrict(context, regexp, name, value);
}

TNode<Smi> RegExpBuiltinsAssembler::LoadCaptureCount(TNode<RegExpData> data) {
  return Select<Smi>(
      SmiEqual(LoadObjectField<Smi>(data, RegExpData::kTypeTagOffset),
               SmiConstant(RegExpData::Type::ATOM)),
      [=, this] { return SmiConstant(JSRegExp::kAtomCaptureCount); },
      [=, this] {
        return LoadObjectField<Smi>(data, IrRegExpData::kCaptureCountOffset);
      });
}

TNode<Smi> RegExpBuiltinsAssembler::RegistersForCaptureCount(
    TNode<Smi> capture_count) {
  // See also: JSRegExp::RegistersForCaptureCount.
  static_assert(Internals::IsValidSmi((JSRegExp::kMaxCaptures + 1) * 2));
  return SmiShl(SmiAdd(capture_count, SmiConstant(1)), 1);
}

TNode<JSRegExpResult> RegExpBuiltinsAssembler::ConstructNewResultFromMatchInfo(
    TNode<Context> context, TNode<JSRegExp> regexp,
    TNode<RegExpMatchInfo> match_info, TNode<String> string,
    TNode<Number> last_index) {
  Label named_captures(this), maybe_build_indices(this), out(this);

  TNode<IntPtrT> num_indices = PositiveSmiUntag(CAST(LoadObjectField(
      match_info, offsetof(RegExpMatchInfo, number_of_capture_registers_))));
  TNode<Smi> num_results = SmiTag(WordShr(num_indices, 1));
  TNode<Smi> start = LoadArrayElement(match_info, IntPtrConstant(0));
  TNode<Smi> end = LoadArrayElement(match_info, IntPtrConstant(1));

  // Calculate the substring of the first match before creating the result array
  // to avoid an unnecessary write barrier storing the first result.

  TNode<String> first =
      CAST(CallBuiltin(Builtin::kSubString, context, string, start, end));

  // Load flags and check if the result object needs to have indices.
  const TNode<Smi> flags =
      CAST(LoadObjectField(regexp, JSRegExp::kFlagsOffset));
  const TNode<BoolT> has_indices = IsSetSmi(flags, JSRegExp::kHasIndices);
  TNode<FixedArray> result_elements;
  TNode<JSRegExpResult> result =
      AllocateRegExpResult(context, num_results, start, string, regexp,
                           last_index, has_indices, &result_elements);

  UnsafeStoreFixedArrayElement(result_elements, 0, first);

  // If no captures exist we can skip named capture handling as well.
  GotoIf(SmiEqual(num_results, SmiConstant(1)), &maybe_build_indices);

  // Store all remaining captures.
  TNode<IntPtrT> limit = num_indices;

  TVARIABLE(IntPtrT, var_from_cursor, IntPtrConstant(2));
  TVARIABLE(IntPtrT, var_to_cursor, IntPtrConstant(1));

  Label loop(this, {&var_from_cursor, &var_to_cursor});

  Goto(&loop);
  BIND(&loop);
  {
    TNode<IntPtrT> from_cursor = var_from_cursor.value();
    TNode<IntPtrT> to_cursor = var_to_cursor.value();
    TNode<Smi> start_cursor = LoadArrayElement(match_info, from_cursor);

    Label next_iter(this);
    GotoIf(SmiEqual(start_cursor, SmiConstant(-1)), &next_iter);

    TNode<IntPtrT> from_cursor_plus1 =
        IntPtrAdd(from_cursor, IntPtrConstant(1));
    TNode<Smi> end_cursor = LoadArrayElement(match_info, from_cursor_plus1);

    TNode<String> capture = CAST(CallBuiltin(Builtin::kSubString, context,
                                             string, start_cursor, end_cursor));
    UnsafeStoreFixedArrayElement(result_elements, to_cursor, capture);
    Goto(&next_iter);

    BIND(&next_iter);
    var_from_cursor = IntPtrAdd(from_cursor, IntPtrConstant(2));
    var_to_cursor = IntPtrAdd(to_cursor, IntPtrConstant(1));
    Branch(UintPtrLessThan(var_from_cursor.value(), limit), &loop,
           &named_captures);
  }

  BIND(&named_captures);
  {
    CSA_DCHECK(this, SmiGreaterThan(num_results, SmiConstant(1)));

    // Preparations for named capture properties. Exit early if the result does
    // not have any named captures to minimize performance impact.

    TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
        regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));

    // We reach this point only if captures exist, implying that the assigned
    // regexp engine must be able to handle captures.
    CSA_SBXCHECK(this, HasInstanceType(data, IR_REG_EXP_DATA_TYPE));

    // The names fixed array associates names at even indices with a capture
    // index at odd indices.
    TNode<Object> maybe_names =
        LoadObjectField(data, IrRegExpData::kCaptureNameMapOffset);
    GotoIf(TaggedEqual(maybe_names, SmiZero()), &maybe_build_indices,
           GotoHint::kLabel);

    // One or more named captures exist, add a property for each one.

    TNode<FixedArray> names = CAST(maybe_names);
    TNode<IntPtrT> names_length = LoadAndUntagFixedArrayBaseLength(names);
    CSA_DCHECK(this, IntPtrGreaterThan(names_length, IntPtrZero()));

    // Stash names in case we need them to build the indices array later.
    StoreObjectField(result, JSRegExpResult::kNamesOffset, names);

    // Allocate a new object to store the named capture properties.
    // TODO(jgruber): Could be optimized by adding the object map to the heap
    // root list.

    TNode<IntPtrT> num_properties = WordSar(names_length, 1);
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> map = LoadSlowObjectWithNullPrototypeMap(native_context);
    TNode<HeapObject> properties;
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      properties = AllocateSwissNameDictionary(num_properties);
    } else {
      properties = AllocateNameDictionary(num_properties);
    }

    TNode<JSObject> group_object = AllocateJSObjectFromMap(map, properties);
    StoreObjectField(result, JSRegExpResult::kGroupsOffset, group_object);

    TVARIABLE(IntPtrT, var_i, IntPtrZero());

    Label inner_loop(this, &var_i);

    Goto(&inner_loop);
    BIND(&inner_loop);
    {
      TNode<IntPtrT> i = var_i.value();
      TNode<IntPtrT> i_plus_1 = IntPtrAdd(i, IntPtrConstant(1));
      TNode<IntPtrT> i_plus_2 = IntPtrAdd(i_plus_1, IntPtrConstant(1));

      TNode<String> name = CAST(LoadFixedArrayElement(names, i));
      TNode<Smi> index = CAST(LoadFixedArrayElement(names, i_plus_1));
      TNode<HeapObject> capture =
          CAST(LoadFixedArrayElement(result_elements, SmiUntag(index)));

      // TODO(v8:8213): For maintainability, we should call a CSA/Torque
      // implementation of CreateDataProperty instead.

      // At this point the spec says to call CreateDataProperty. However, we can
      // skip most of the steps and go straight to adding/updating a dictionary
      // entry because we know a bunch of useful facts:
      // - All keys are non-numeric internalized strings
      // - Receiver has no prototype
      // - Receiver isn't used as a prototype
      // - Receiver isn't any special object like a Promise intrinsic object
      // - Receiver is extensible
      // - Receiver has no interceptors
      Label add_dictionary_property_slow(this, Label::kDeferred);
      TVARIABLE(IntPtrT, var_name_index);
      Label add_name_entry(this, &var_name_index),
          duplicate_name(this, &var_name_index), next(this);
      NameDictionaryLookup<PropertyDictionary>(
          CAST(properties), name, &duplicate_name, &var_name_index,
          &add_name_entry, kFindExistingOrInsertionIndex);
      BIND(&duplicate_name);
      GotoIf(IsUndefined(capture), &next);
      CSA_DCHECK(this,
                 TaggedEqual(LoadValueByKeyIndex<PropertyDictionary>(
                                 CAST(properties), var_name_index.value()),
                             UndefinedConstant()));
      StoreValueByKeyIndex<PropertyDictionary>(CAST(properties),
                                               var_name_index.value(), capture);
      Goto(&next);

      BIND(&add_name_entry);
      AddToDictionary<PropertyDictionary>(CAST(properties), name, capture,
                                          &add_dictionary_property_slow,
                                          var_name_index.value());
      Goto(&next);

      BIND(&next);
      var_i = i_plus_2;
      Branch(IntPtrGreaterThanOrEqual(var_i.value(), names_length),
             &maybe_build_indices, &inner_loop);

      BIND(&add_dictionary_property_slow);
      // If the dictionary needs resizing, the above Add call will jump here
      // before making any changes. This shouldn't happen because we allocated
      // the dictionary with enough space above.
      Unreachable();
    }
  }

  // Build indices if needed (i.e. if the /d flag is present) after named
  // capture groups are processed.
  BIND(&maybe_build_indices);
  GotoIfNot(has_indices, &out, GotoHint::kLabel);
  {
    const TNode<Object> maybe_names =
        LoadObjectField(result, JSRegExpResultWithIndices::kNamesOffset);
    const TNode<JSRegExpResultIndices> indices =
        UncheckedCast<JSRegExpResultIndices>(
            CallRuntime(Runtime::kRegExpBuildIndices, context, regexp,
                        match_info, maybe_names));
    StoreObjectField(result, JSRegExpResultWithIndices::kIndicesOffset,
                     indices);
    Goto(&out);
  }

  BIND(&out);
  return result;
}

void RegExpBuiltinsAssembler::GetStringPointers(
    TNode<RawPtrT> string_data, TNode<IntPtrT> offset,
    TNode<IntPtrT> last_index, TNode<IntPtrT> string_length,
    String::Encoding encoding, TVariable<RawPtrT>* var_string_start,
    TVariable<RawPtrT>* var_string_end) {
  DCHECK_EQ(var_string_start->rep(), MachineType::PointerRepresentation());
  DCHECK_EQ(var_string_end->rep(), MachineType::PointerRepresentation());

  const ElementsKind kind = (encoding == String::ONE_BYTE_ENCODING)
                                ? UINT8_ELEMENTS
                                : UINT16_ELEMENTS;

  TNode<IntPtrT> from_offset =
      ElementOffsetFromIndex(IntPtrAdd(offset, last_index), kind);
  *var_string_start =
      ReinterpretCast<RawPtrT>(IntPtrAdd(string_data, from_offset));

  TNode<IntPtrT> to_offset =
      ElementOffsetFromIndex(IntPtrAdd(offset, string_length), kind);
  *var_string_end = ReinterpretCast<RawPtrT>(IntPtrAdd(string_data, to_offset));
}

std::pair<TNode<RawPtrT>, TNode<BoolT>>
RegExpBuiltinsAssembler::LoadOrAllocateRegExpResultVector(
    TNode<Smi> register_count) {
  Label if_dynamic(this), out(this);
  TVARIABLE(BoolT, var_is_dynamic, Int32FalseConstant());
  TVARIABLE(RawPtrT, var_vector, UncheckedCast<RawPtrT>(IntPtrConstant(0)));

  // Too large?
  GotoIf(SmiAbove(register_count,
                  SmiConstant(Isolate::kJSRegexpStaticOffsetsVectorSize)),
         &if_dynamic, GotoHint::kFallthrough);

  auto address_of_regexp_static_result_offsets_vector = ExternalConstant(
      ExternalReference::address_of_regexp_static_result_offsets_vector(
          isolate()));
  var_vector = UncheckedCast<RawPtrT>(Load(
      MachineType::Pointer(), address_of_regexp_static_result_offsets_vector));

  // Owned by someone else?
  GotoIf(WordEqual(var_vector.value(), IntPtrConstant(0)), &if_dynamic,
         GotoHint::kFallthrough);

  // Take ownership of the static vector. See also:
  // RegExpResultVectorScope::Initialize.
  StoreNoWriteBarrier(MachineType::PointerRepresentation(),
                      address_of_regexp_static_result_offsets_vector,
                      IntPtrConstant(0));
  Goto(&out);

  BIND(&if_dynamic);
  var_is_dynamic = Int32TrueConstant();
  auto isolate_ptr = ExternalConstant(ExternalReference::isolate_address());
  var_vector = UncheckedCast<RawPtrT>(CallCFunction(
      ExternalConstant(ExternalReference::allocate_regexp_result_vector()),
      MachineType::Pointer(),
      std::make_pair(MachineType::Pointer(), isolate_ptr),
      std::make_pair(MachineType::Uint32(), SmiToInt32(register_count))));
  Goto(&out);

  BIND(&out);
  return {var_vector.value(), var_is_dynamic.value()};
}

void RegExpBuiltinsAssembler::FreeRegExpResultVector(
    TNode<RawPtrT> result_vector, TNode<BoolT> is_dynamic) {
  Label if_dynamic(this), out(this);

  GotoIf(is_dynamic, &if_dynamic, GotoHint::kFallthrough);

  // The vector must have been allocated.
  CSA_DCHECK(this, WordNotEqual(result_vector, IntPtrConstant(0)));

  // Return ownership of the static vector.
  auto address_of_regexp_static_result_offsets_vector = ExternalConstant(
      ExternalReference::address_of_regexp_static_result_offsets_vector(
          isolate()));
  CSA_DCHECK(
      this, WordEqual(UncheckedCast<RawPtrT>(
                          Load(MachineType::Pointer(),
                               address_of_regexp_static_result_offsets_vector)),
                      IntPtrConstant(0)));
  StoreNoWriteBarrier(MachineType::PointerRepresentation(),
                      address_of_regexp_static_result_offsets_vector,
                      result_vector);
  Goto(&out);

  BIND(&if_dynamic);
  auto isolate_ptr = ExternalConstant(ExternalReference::isolate_address());
  CallCFunction(
      ExternalConstant(ExternalReference::free_regexp_result_vector()),
      MachineType::Pointer() /* void */,
      std::make_pair(MachineType::Pointer(), isolate_ptr),
      std::make_pair(MachineType::Pointer(), result_vector));
  Goto(&out);

  BIND(&out);
}

namespace {

static constexpr int kInt32SizeLog2 = 2;
static_assert(kInt32Size == 1 << kInt32SizeLog2);

}  // namespace

TNode<RegExpMatchInfo>
RegExpBuiltinsAssembler::InitializeMatchInfoFromRegisters(
    TNode<Context> context, TNode<RegExpMatchInfo> match_info,
    TNode<Smi> register_count, TNode<String> subject,
    TNode<RawPtrT> result_offsets_vector) {
  TVARIABLE(RegExpMatchInfo, var_match_info, match_info);

  // Check that the last match info has space for the capture registers.
  {
    Label next(this);
    TNode<Smi> available_slots = LoadSmiArrayLength(var_match_info.value());
    GotoIf(SmiLessThanOrEqual(register_count, available_slots), &next,
           GotoHint::kLabel);

    // Grow.
    var_match_info =
        CAST(CallRuntime(Runtime::kRegExpGrowRegExpMatchInfo, context,
                         var_match_info.value(), register_count));
    Goto(&next);

    BIND(&next);
  }

  // Fill match_info.
  StoreObjectField(var_match_info.value(),
                   offsetof(RegExpMatchInfo, number_of_capture_registers_),
                   register_count);
  StoreObjectField(var_match_info.value(),
                   offsetof(RegExpMatchInfo, last_subject_), subject);
  StoreObjectField(var_match_info.value(),
                   offsetof(RegExpMatchInfo, last_input_), subject);

  // Fill match and capture offsets in match_info. They are located in the
  // region:
  //
  //   result_offsets_vector + 0
  //   ...
  //   result_offsets_vector + register_count * kInt32Size.
  {
    // The offset within result_offsets_vector.
    TNode<IntPtrT> loop_start = UncheckedCast<IntPtrT>(result_offsets_vector);
    TNode<IntPtrT> loop_end =
        IntPtrAdd(loop_start, SmiUntag(SmiShl(register_count, kInt32SizeLog2)));
    // The offset within RegExpMatchInfo.
    TNode<IntPtrT> to_offset =
        OffsetOfElementAt<RegExpMatchInfo>(SmiConstant(0));
    TVARIABLE(IntPtrT, var_to_offset, to_offset);

    VariableList vars({&var_to_offset}, zone());
    BuildFastLoop<IntPtrT>(
        vars, loop_start, loop_end,
        [&](TNode<IntPtrT> current_register_address) {
          TNode<Int32T> value = UncheckedCast<Int32T>(
              Load(MachineType::Int32(), current_register_address));
          TNode<Smi> smi_value = SmiFromInt32(value);
          StoreNoWriteBarrier(MachineRepresentation::kTagged,
                              var_match_info.value(), var_to_offset.value(),
                              smi_value);
          Increment(&var_to_offset, kTaggedSize);
        },
        kInt32Size, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  }

  return var_match_info.value();
}

TNode<RegExpMatchInfo> RegExpBuiltinsAssembler::RegExpExecInternal_Single(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> string,
    TNode<Number> last_index, Label* if_not_matched) {
  Label out(this), not_matched(this);
  TVARIABLE(RegExpMatchInfo, var_result);
  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));
  TNode<Smi> register_count_per_match =
      RegistersForCaptureCount(LoadCaptureCount(data));
  // Allocate space for one match.
  TNode<Smi> result_offsets_vector_length = register_count_per_match;
  TNode<RawPtrT> result_offsets_vector;
  TNode<BoolT> result_offsets_vector_is_dynamic;
  std::tie(result_offsets_vector, result_offsets_vector_is_dynamic) =
      LoadOrAllocateRegExpResultVector(result_offsets_vector_length);

  // Exception handling is necessary to free any allocated memory.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);

  {
    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);

    TNode<UintPtrT> num_matches = RegExpExecInternal(
        context, regexp, data, string, last_index, result_offsets_vector,
        SmiToInt32(result_offsets_vector_length));

    GotoIf(IntPtrEqual(num_matches, IntPtrConstant(0)), &not_matched);

    CSA_DCHECK(this, IntPtrEqual(num_matches, IntPtrConstant(1)));
    CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
    TNode<RegExpMatchInfo> last_match_info = CAST(LoadContextElementNoCell(
        context, Context::REGEXP_LAST_MATCH_INFO_INDEX));
    var_result = InitializeMatchInfoFromRegisters(
        context, last_match_info, register_count_per_match, string,
        result_offsets_vector);
    Goto(&out);
  }

  BIND(&if_exception);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  CallRuntime(Runtime::kReThrow, context, var_exception.value());
  Unreachable();

  BIND(&not_matched);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  Goto(if_not_matched);

  BIND(&out);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  return var_result.value();
}

TNode<UintPtrT> RegExpBuiltinsAssembler::RegExpExecInternal(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<RegExpData> data,
    TNode<String> string, TNode<Number> last_index,
    TNode<RawPtrT> result_offsets_vector,
    TNode<Int32T> result_offsets_vector_length) {
  CSA_DCHECK(this, TaggedEqual(data, LoadTrustedPointerFromObject(
                                         regexp, JSRegExp::kDataOffset,
                                         kRegExpDataIndirectPointerTag)));

  ToDirectStringAssembler to_direct(state(), string);

  TVARIABLE(UintPtrT, var_result, UintPtrConstant(0));
  Label out(this), atom(this), runtime(this, Label::kDeferred),
      retry_experimental(this, Label::kDeferred);

  // At this point, last_index is definitely a canonicalized non-negative
  // number, which implies that any non-Smi last_index is greater than
  // the maximal string length. If lastIndex > string.length then the matcher
  // must fail.

  CSA_DCHECK(this, IsNumberNormalized(last_index));
  CSA_DCHECK(this, IsNumberPositive(last_index));
  GotoIf(TaggedIsNotSmi(last_index), &out, GotoHint::kFallthrough);

  TNode<IntPtrT> int_string_length = LoadStringLengthAsWord(string);
  TNode<IntPtrT> int_last_index = PositiveSmiUntag(CAST(last_index));

  GotoIf(UintPtrGreaterThan(int_last_index, int_string_length), &out,
         GotoHint::kFallthrough);

  // Unpack the string. Note that due to SlicedString unpacking (which extracts
  // the parent string and offset), it's not valid to replace `string` with the
  // result of ToDirect here. Instead, we rely on in-place flattening done by
  // String::Flatten.
  // TODO(jgruber): Consider changing ToDirectStringAssembler behavior here
  // since this aspect is surprising. The result of `ToDirect` could always
  // equal the input in length and contents. SlicedString unpacking could
  // happen in `TryToSequential`.
  to_direct.ToDirect();

  // Dispatch on the type of the RegExp.
  // Since the type tag is in trusted space, it is safe to interpret
  // RegExpData as IrRegExpData/AtomRegExpData in the respective branches
  // without checks.
  {
    Label next(this), unreachable(this, Label::kDeferred);
    TNode<Int32T> tag =
        SmiToInt32(LoadObjectField<Smi>(data, RegExpData::kTypeTagOffset));

    int32_t values[] = {
        static_cast<uint8_t>(RegExpData::Type::IRREGEXP),
        static_cast<uint8_t>(RegExpData::Type::ATOM),
        static_cast<uint8_t>(RegExpData::Type::EXPERIMENTAL),
    };
    Label* labels[] = {&next, &atom, &next};

    static_assert(arraysize(values) == arraysize(labels));
    Switch(tag, &unreachable, values, labels, arraysize(values));

    BIND(&unreachable);
    Unreachable();

    BIND(&next);
  }

  // Check (number_of_captures + 1) * 2 <= offsets vector size.
  CSA_DCHECK(
      this, SmiLessThanOrEqual(RegistersForCaptureCount(LoadCaptureCount(data)),
                               SmiFromInt32(result_offsets_vector_length)));

  // Load the irregexp code or bytecode object and offsets into the subject
  // string. Both depend on whether the string is one- or two-byte.

  TVARIABLE(RawPtrT, var_string_start);
  TVARIABLE(RawPtrT, var_string_end);
#ifdef V8_ENABLE_SANDBOX
  using kVarCodeT = IndirectPointerHandleT;
#else
  using kVarCodeT = Object;
#endif
  TVARIABLE(kVarCodeT, var_code);
  TVARIABLE(Object, var_bytecode);

  {
    TNode<RawPtrT> direct_string_data = to_direct.PointerToData(&runtime);

    Label next(this), if_isonebyte(this), if_istwobyte(this, Label::kDeferred);
    Branch(to_direct.IsOneByte(), &if_isonebyte, &if_istwobyte);

    BIND(&if_isonebyte);
    {
      GetStringPointers(direct_string_data, to_direct.offset(), int_last_index,
                        int_string_length, String::ONE_BYTE_ENCODING,
                        &var_string_start, &var_string_end);
      var_code =
          LoadObjectField<kVarCodeT>(data, IrRegExpData::kLatin1CodeOffset);
      var_bytecode = LoadObjectField(data, IrRegExpData::kLatin1BytecodeOffset);
      Goto(&next);
    }

    BIND(&if_istwobyte);
    {
      GetStringPointers(direct_string_data, to_direct.offset(), int_last_index,
                        int_string_length, String::TWO_BYTE_ENCODING,
                        &var_string_start, &var_string_end);
      var_code =
          LoadObjectField<kVarCodeT>(data, IrRegExpData::kUc16CodeOffset);
      var_bytecode = LoadObjectField(data, IrRegExpData::kUc16BytecodeOffset);
      Goto(&next);
    }

    BIND(&next);
  }

  // Check that the irregexp code has been generated for the actual string
  // encoding.

#ifdef V8_ENABLE_SANDBOX
  GotoIf(
      Word32Equal(var_code.value(), Int32Constant(kNullIndirectPointerHandle)),
      &runtime);
#else
  GotoIf(TaggedIsSmi(var_code.value()), &runtime);
#endif

  Label if_exception(this, Label::kDeferred);

  {
    IncrementCounter(isolate()->counters()->regexp_entry_native(), 1);

    // Set up args for the final call into generated Irregexp code.

    MachineType type_int32 = MachineType::Int32();
    MachineType type_tagged = MachineType::AnyTagged();
    MachineType type_ptr = MachineType::Pointer();

    // Result: A NativeRegExpMacroAssembler::Result return code.
    MachineType retval_type = type_int32;

    // Argument 0: Original subject string.
    MachineType arg0_type = type_tagged;
    TNode<String> arg0 = string;

    // Argument 1: Previous index.
    MachineType arg1_type = type_int32;
    TNode<Int32T> arg1 = TruncateIntPtrToInt32(int_last_index);

    // Argument 2: Start of string data. This argument is ignored in the
    // interpreter.
    MachineType arg2_type = type_ptr;
    TNode<RawPtrT> arg2 = var_string_start.value();

    // Argument 3: End of string data. This argument is ignored in the
    // interpreter.
    MachineType arg3_type = type_ptr;
    TNode<RawPtrT> arg3 = var_string_end.value();

    // Argument 4: result offsets vector.
    MachineType arg4_type = type_ptr;
    TNode<RawPtrT> arg4 = result_offsets_vector;

    // Argument 5: Number of capture registers.
    MachineType arg5_type = type_int32;
    TNode<Int32T> arg5 = result_offsets_vector_length;

    // Argument 6: Indicate that this is a direct call from JavaScript.
    MachineType arg6_type = type_int32;
    TNode<Int32T> arg6 = Int32Constant(RegExp::CallOrigin::kFromJs);

    // Argument 7: Pass current isolate address.
    TNode<ExternalReference> isolate_address =
        ExternalConstant(ExternalReference::isolate_address());
    MachineType arg7_type = type_ptr;
    TNode<ExternalReference> arg7 = isolate_address;

    // Argument 8: Regular expression data object. This argument is ignored in
    // native irregexp code.
    MachineType arg8_type = type_tagged;
    TNode<IrRegExpData> arg8 = CAST(data);

#ifdef V8_ENABLE_SANDBOX
    TNode<RawPtrT> code_entry = LoadCodeEntryFromIndirectPointerHandle(
        var_code.value(), kRegExpEntrypointTag);
#else
    TNode<Code> code = CAST(var_code.value());
    TNode<RawPtrT> code_entry =
        LoadCodeInstructionStart(code, kRegExpEntrypointTag);
#endif

    // AIX uses function descriptors on CFunction calls. code_entry in this case
    // may also point to a Regex interpreter entry trampoline which does not
    // have a function descriptor. This method is ineffective on other platforms
    // and is equivalent to CallCFunction.
    TNode<Int32T> result =
        UncheckedCast<Int32T>(CallCFunctionWithoutFunctionDescriptor(
            code_entry, retval_type, std::make_pair(arg0_type, arg0),
            std::make_pair(arg1_type, arg1), std::make_pair(arg2_type, arg2),
            std::make_pair(arg3_type, arg3), std::make_pair(arg4_type, arg4),
            std::make_pair(arg5_type, arg5), std::make_pair(arg6_type, arg6),
            std::make_pair(arg7_type, arg7), std::make_pair(arg8_type, arg8)));

    // Check the result.
    TNode<IntPtrT> int_result = ChangeInt32ToIntPtr(result);
    var_result = UncheckedCast<UintPtrT>(int_result);
    static_assert(RegExp::kInternalRegExpSuccess == 1);
    static_assert(RegExp::kInternalRegExpFailure == 0);
    GotoIf(IntPtrGreaterThanOrEqual(
               int_result, IntPtrConstant(RegExp::kInternalRegExpFailure)),
           &out);
    // GotoHint::kLabel since the other two states are 1. unlikely and 2. it's
    // okay to be a bit slower there.
    GotoIf(
        IntPtrEqual(int_result, IntPtrConstant(RegExp::kInternalRegExpRetry)),
        &runtime, GotoHint::kLabel);
    GotoIf(IntPtrEqual(int_result,
                       IntPtrConstant(RegExp::kInternalRegExpException)),
           &if_exception);

    CSA_CHECK(this,
              IntPtrEqual(int_result,
                          IntPtrConstant(
                              RegExp::kInternalRegExpFallbackToExperimental)));
    Goto(&retry_experimental);
  }

  BIND(&if_exception);
  {
// A stack overflow was detected in RegExp code.
#ifdef DEBUG
    TNode<ExternalReference> exception_address =
        ExternalConstant(ExternalReference::Create(
            IsolateAddressId::kExceptionAddress, isolate()));
    TNode<Object> exception = LoadFullTagged(exception_address);
    CSA_DCHECK(this, IsTheHole(exception));
#endif  // DEBUG
    CallRuntime(Runtime::kThrowStackOverflow, context);
    Unreachable();
  }

  BIND(&retry_experimental);
  {
    // Set the implicit (untagged) arg.
    auto vector_arg = ExternalConstant(
        ExternalReference::Create(IsolateFieldId::kRegexpExecVectorArgument));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        result_offsets_vector);
    static_assert(
        Internals::IsValidSmi(Isolate::kJSRegexpStaticOffsetsVectorSize));
    TNode<Smi> result_as_smi = CAST(CallRuntime(
        Runtime::kRegExpExperimentalOneshotExec, context, regexp, string,
        last_index, SmiFromInt32(result_offsets_vector_length)));
    var_result = UncheckedCast<UintPtrT>(SmiUntag(result_as_smi));
#ifdef DEBUG
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        IntPtrConstant(0));
#endif  // DEBUG
    Goto(&out);
  }

  BIND(&runtime);
  {
    // Set the implicit (untagged) arg.
    auto vector_arg = ExternalConstant(
        ExternalReference::Create(IsolateFieldId::kRegexpExecVectorArgument));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        result_offsets_vector);
    static_assert(
        Internals::IsValidSmi(Isolate::kJSRegexpStaticOffsetsVectorSize));
    TNode<Smi> result_as_smi = CAST(
        CallRuntime(Runtime::kRegExpExec, context, regexp, string, last_index,
                    SmiFromInt32(result_offsets_vector_length)));
    var_result = UncheckedCast<UintPtrT>(SmiUntag(result_as_smi));
#ifdef DEBUG
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), vector_arg,
                        IntPtrConstant(0));
#endif  // DEBUG
    Goto(&out);
  }

  BIND(&atom);
  {
    var_result =
        RegExpExecAtom(context, CAST(data), string, CAST(last_index),
                       result_offsets_vector, result_offsets_vector_length);
    Goto(&out);
  }

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> RegExpBuiltinsAssembler::IsFastRegExpNoPrototype(
    TNode<Context> context, TNode<Object> object, TNode<Map> map) {
  Label out(this);
  TVARIABLE(BoolT, var_result);

  var_result = Int32FalseConstant();
  GotoIfForceSlowPath(&out);

  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<HeapObject> regexp_fun = CAST(
      LoadContextElementNoCell(native_context, Context::REGEXP_FUNCTION_INDEX));
  const TNode<Object> initial_map =
      LoadObjectField(regexp_fun, JSFunction::kPrototypeOrInitialMapOffset);
  const TNode<BoolT> has_initialmap = TaggedEqual(map, initial_map);

  var_result = has_initialmap;
  GotoIfNot(has_initialmap, &out, GotoHint::kFallthrough);

  // The smi check is required to omit ToLength(lastIndex) calls with possible
  // user-code execution on the fast path.
  TNode<Object> last_index = FastLoadLastIndexBeforeSmiCheck(CAST(object));
  var_result = TaggedIsPositiveSmi(last_index);
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> RegExpBuiltinsAssembler::IsFastRegExpNoPrototype(
    TNode<Context> context, TNode<Object> object) {
  CSA_DCHECK(this, TaggedIsNotSmi(object));
  return IsFastRegExpNoPrototype(context, object, LoadMap(CAST(object)));
}

void RegExpBuiltinsAssembler::BranchIfFastRegExp(
    TNode<Context> context, TNode<HeapObject> object, TNode<Map> map,
    PrototypeCheckAssembler::Flags prototype_check_flags,
    std::optional<DescriptorIndexNameValue> additional_property_to_check,
    Label* if_isunmodified, Label* if_ismodified) {
  CSA_DCHECK(this, TaggedEqual(LoadMap(object), map));

  GotoIfForceSlowPath(if_ismodified);

  // This should only be needed for String.p.(split||matchAll), but we are
  // conservative here.
  GotoIf(IsRegExpSpeciesProtectorCellInvalid(), if_ismodified,
         GotoHint::kFallthrough);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSFunction> regexp_fun = CAST(
      LoadContextElementNoCell(native_context, Context::REGEXP_FUNCTION_INDEX));
  TNode<Map> initial_map = CAST(
      LoadObjectField(regexp_fun, JSFunction::kPrototypeOrInitialMapOffset));
  TNode<BoolT> has_initialmap = TaggedEqual(map, initial_map);

  GotoIfNot(has_initialmap, if_ismodified, GotoHint::kFallthrough);

  // The smi check is required to omit ToLength(lastIndex) calls with possible
  // user-code execution on the fast path.
  TNode<Object> last_index = FastLoadLastIndexBeforeSmiCheck(CAST(object));
  GotoIfNot(TaggedIsPositiveSmi(last_index), if_ismodified,
            GotoHint::kFallthrough);

  // Verify the prototype.

  TNode<Map> initial_proto_initial_map = CAST(LoadContextElementNoCell(
      native_context, Context::REGEXP_PROTOTYPE_MAP_INDEX));

  DescriptorIndexNameValue properties_to_check[2];
  int property_count = 0;
  properties_to_check[property_count++] = DescriptorIndexNameValue{
      JSRegExp::kExecFunctionDescriptorIndex, RootIndex::kexec_string,
      Context::REGEXP_EXEC_FUNCTION_INDEX};
  if (additional_property_to_check) {
    properties_to_check[property_count++] = *additional_property_to_check;
  }

  PrototypeCheckAssembler prototype_check_assembler(
      state(), prototype_check_flags, native_context, initial_proto_initial_map,
      base::Vector<DescriptorIndexNameValue>(properties_to_check,
                                             property_count));

  TNode<HeapObject> prototype = LoadMapPrototype(map);
  prototype_check_assembler.CheckAndBranch(prototype, if_isunmodified,
                                           if_ismodified);
}
void RegExpBuiltinsAssembler::BranchIfFastRegExpForSearch(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(
      context, object, LoadMap(object),
      PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
      DescriptorIndexNameValue{JSRegExp::kSymbolSearchFunctionDescriptorIndex,
                               RootIndex::ksearch_symbol,
                               Context::REGEXP_SEARCH_FUNCTION_INDEX},
      if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfFastRegExpForMatch(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(
      context, object, LoadMap(object),
      PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
      DescriptorIndexNameValue{JSRegExp::kSymbolMatchFunctionDescriptorIndex,
                               RootIndex::kmatch_symbol,
                               Context::REGEXP_MATCH_FUNCTION_INDEX},
      if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfFastRegExp_Strict(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(context, object, LoadMap(object),
                     PrototypeCheckAssembler::kCheckPrototypePropertyConstness,
                     std::nullopt, if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfFastRegExp_Permissive(
    TNode<Context> context, TNode<HeapObject> object, Label* if_isunmodified,
    Label* if_ismodified) {
  BranchIfFastRegExp(context, object, LoadMap(object),
                     PrototypeCheckAssembler::kCheckFull, std::nullopt,
                     if_isunmodified, if_ismodified);
}

void RegExpBuiltinsAssembler::BranchIfRegExpResult(const TNode<Context> context,
                                                   const TNode<Object> object,
                                                   Label* if_isunmodified,
                                                   Label* if_ismodified) {
  // Could be a Smi.
  const TNode<Map> map = LoadReceiverMap(object);

  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_regexp_result_map = LoadContextElementNoCell(
      native_context, Context::REGEXP_RESULT_MAP_INDEX);

  Label maybe_result_with_indices(this);
  Branch(TaggedEqual(map, initial_regexp_result_map), if_isunmodified,
         &maybe_result_with_indices, BranchHint::kTrue);
  BIND(&maybe_result_with_indices);
  {
    static_assert(std::is_base_of_v<JSRegExpResult, JSRegExpResultWithIndices>,
                  "JSRegExpResultWithIndices is a subclass of JSRegExpResult");
    const TNode<Object> initial_regexp_result_with_indices_map =
        LoadContextElementNoCell(native_context,
                                 Context::REGEXP_RESULT_WITH_INDICES_MAP_INDEX);
    Branch(TaggedEqual(map, initial_regexp_result_with_indices_map),
           if_isunmodified, if_ismodified);
  }
}

TNode<UintPtrT> RegExpBuiltinsAssembler::RegExpExecAtom(
    TNode<Context> context, TNode<AtomRegExpData> data,
    TNode<String> subject_string, TNode<Smi> last_index,
    TNode<RawPtrT> result_offsets_vector,
    TNode<Int32T> result_offsets_vector_length) {
  auto f = ExternalConstant(ExternalReference::re_atom_exec_raw());
  auto isolate_ptr = ExternalConstant(ExternalReference::isolate_address());
  auto result = UncheckedCast<IntPtrT>(CallCFunction(
      f, MachineType::IntPtr(),
      std::make_pair(MachineType::Pointer(), isolate_ptr),
      std::make_pair(MachineType::TaggedPointer(), data),
      std::make_pair(MachineType::TaggedPointer(), subject_string),
      std::make_pair(MachineType::Int32(), SmiToInt32(last_index)),
      std::make_pair(MachineType::Pointer(), result_offsets_vector),
      std::make_pair(MachineType::Int32(), result_offsets_vector_length)));
  return Unsigned(result);
}

// Fast path stub for ATOM regexps. String matching is done by StringIndexOf,
// and {match_info} is updated on success.
// The slow path is implemented in RegExp::AtomExec.
TF_BUILTIN(RegExpExecAtom, RegExpBuiltinsAssembler) {
  auto regexp = Parameter<JSRegExp>(Descriptor::kRegExp);
  auto subject_string = Parameter<String>(Descriptor::kString);
  auto last_index = Parameter<Smi>(Descriptor::kLastIndex);
  auto match_info = Parameter<RegExpMatchInfo>(Descriptor::kMatchInfo);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, TaggedIsPositiveSmi(last_index));

  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));
  CSA_SBXCHECK(this, HasInstanceType(data, ATOM_REG_EXP_DATA_TYPE));

  // Callers ensure that last_index is in-bounds.
  CSA_DCHECK(this,
             UintPtrLessThanOrEqual(SmiUntag(last_index),
                                    LoadStringLengthAsWord(subject_string)));

  const TNode<String> needle_string =
      LoadObjectField<String>(data, AtomRegExpData::kPatternOffset);

  // ATOM patterns are guaranteed to not be the empty string (these are
  // intercepted and replaced in JSRegExp::Initialize.
  //
  // This is especially relevant for crbug.com/1075514: atom patterns are
  // non-empty and thus guaranteed not to match at the end of the string.
  CSA_DCHECK(this, IntPtrGreaterThan(LoadStringLengthAsWord(needle_string),
                                     IntPtrConstant(0)));

  const TNode<Smi> match_from =
      CAST(CallBuiltin(Builtin::kStringIndexOf, context, subject_string,
                       needle_string, last_index));

  Label if_failure(this), if_success(this);
  Branch(SmiEqual(match_from, SmiConstant(-1)), &if_failure, &if_success);

  BIND(&if_success);
  {
    CSA_DCHECK(this, TaggedIsPositiveSmi(match_from));
    CSA_DCHECK(this, UintPtrLessThan(SmiUntag(match_from),
                                     LoadStringLengthAsWord(subject_string)));

    const int kNumRegisters = 2;
    static_assert(kNumRegisters <= RegExpMatchInfo::kMinCapacity);

    const TNode<Smi> match_to =
        SmiAdd(match_from, LoadStringLengthAsSmi(needle_string));

    StoreObjectField(match_info,
                     offsetof(RegExpMatchInfo, number_of_capture_registers_),
                     SmiConstant(kNumRegisters));
    StoreObjectField(match_info, offsetof(RegExpMatchInfo, last_subject_),
                     subject_string);
    StoreObjectField(match_info, offsetof(RegExpMatchInfo, last_input_),
                     subject_string);
    UnsafeStoreArrayElement(match_info, 0, match_from,
                            UNSAFE_SKIP_WRITE_BARRIER);
    UnsafeStoreArrayElement(match_info, 1, match_to, UNSAFE_SKIP_WRITE_BARRIER);

    Return(match_info);
  }

  BIND(&if_failure);
  Return(NullConstant());
}

TNode<String> RegExpBuiltinsAssembler::FlagsGetter(TNode<Context> context,
                                                   TNode<JSAny> regexp,
                                                   bool is_fastpath) {
  TVARIABLE(String, result);
  Label runtime(this, Label::kDeferred), done(this, &result);
  if (is_fastpath) {
    GotoIfForceSlowPath(&runtime);
  }

  Isolate* isolate = this->isolate();

  const TNode<IntPtrT> int_one = IntPtrConstant(1);
  TVARIABLE(Uint32T, var_length, Uint32Constant(0));
  TVARIABLE(IntPtrT, var_flags);

  // First, count the number of characters we will need and check which flags
  // are set.

  if (is_fastpath) {
    // Refer to JSRegExp's flag property on the fast-path.
    CSA_DCHECK(this, IsJSRegExp(CAST(regexp)));
    const TNode<Smi> flags_smi =
        CAST(LoadObjectField(CAST(regexp), JSRegExp::kFlagsOffset));
    var_flags = SmiUntag(flags_smi);

#define CASE_FOR_FLAG(Lower, Camel, ...)                                \
  do {                                                                  \
    Label next(this);                                                   \
    GotoIfNot(IsSetWord(var_flags.value(), JSRegExp::k##Camel), &next); \
    var_length = Uint32Add(var_length.value(), Uint32Constant(1));      \
    Goto(&next);                                                        \
    BIND(&next);                                                        \
  } while (false);

    REGEXP_FLAG_LIST(CASE_FOR_FLAG)
#undef CASE_FOR_FLAG
  } else {
    DCHECK(!is_fastpath);

    // Fall back to GetProperty stub on the slow-path.
    var_flags = IntPtrZero();

#define CASE_FOR_FLAG(NAME, FLAG)                                          \
  do {                                                                     \
    Label next(this);                                                      \
    const TNode<Object> flag = GetProperty(                                \
        context, regexp, isolate->factory()->InternalizeUtf8String(NAME)); \
    Label if_isflagset(this);                                              \
    BranchIfToBooleanIsTrue(flag, &if_isflagset, &next);                   \
    BIND(&if_isflagset);                                                   \
    var_length = Uint32Add(var_length.value(), Uint32Constant(1));         \
    var_flags = Signed(WordOr(var_flags.value(), IntPtrConstant(FLAG)));   \
    Goto(&next);                                                           \
    BIND(&next);                                                           \
  } while (false)

    CASE_FOR_FLAG("hasIndices", JSRegExp::kHasIndices);
    CASE_FOR_FLAG("global", JSRegExp::kGlobal);
    CASE_FOR_FLAG("ignoreCase", JSRegExp::kIgnoreCase);
    CASE_FOR_FLAG("multiline", JSRegExp::kMultiline);
    CASE_FOR_FLAG("dotAll", JSRegExp::kDotAll);
    CASE_FOR_FLAG("unicode", JSRegExp::kUnicode);
    CASE_FOR_FLAG("sticky", JSRegExp::kSticky);
    CASE_FOR_FLAG("unicodeSets", JSRegExp::kUnicodeSets);
#undef CASE_FOR_FLAG

#define CASE_FOR_FLAG(NAME, V8_FLAG_EXTERN_REF, FLAG)                      \
  do {                                                                     \
    Label next(this);                                                      \
    TNode<Word32T> flag_value = UncheckedCast<Word32T>(                    \
        Load(MachineType::Uint8(), ExternalConstant(V8_FLAG_EXTERN_REF))); \
    GotoIf(Word32Equal(Word32And(flag_value, Int32Constant(0xFF)),         \
                       Int32Constant(0)),                                  \
           &next);                                                         \
    const TNode<Object> flag = GetProperty(                                \
        context, regexp, isolate->factory()->InternalizeUtf8String(NAME)); \
    Label if_isflagset(this);                                              \
    BranchIfToBooleanIsTrue(flag, &if_isflagset, &next);                   \
    BIND(&if_isflagset);                                                   \
    var_length = Uint32Add(var_length.value(), Uint32Constant(1));         \
    var_flags = Signed(WordOr(var_flags.value(), IntPtrConstant(FLAG)));   \
    Goto(&next);                                                           \
    BIND(&next);                                                           \
  } while (false)

    CASE_FOR_FLAG(
        "linear",
        ExternalReference::address_of_enable_experimental_regexp_engine(),
        JSRegExp::kLinear);
#undef CASE_FOR_FLAG
  }

  // Allocate a string of the required length and fill it with the
  // corresponding char for each set flag.

  {
    const TNode<SeqOneByteString> string =
        CAST(AllocateSeqOneByteString(var_length.value()));

    TVARIABLE(IntPtrT, var_offset,
              IntPtrSub(FieldSliceSeqOneByteStringChars(string).offset,
                        IntPtrConstant(1)));

#define CASE_FOR_FLAG(Lower, Camel, LowerCamel, Char, ...)              \
  do {                                                                  \
    Label next(this);                                                   \
    GotoIfNot(IsSetWord(var_flags.value(), JSRegExp::k##Camel), &next); \
    const TNode<Int32T> value = Int32Constant(Char);                    \
    StoreNoWriteBarrier(MachineRepresentation::kWord8, string,          \
                        var_offset.value(), value);                     \
    var_offset = IntPtrAdd(var_offset.value(), int_one);                \
    Goto(&next);                                                        \
    BIND(&next);                                                        \
  } while (false);

    REGEXP_FLAG_LIST(CASE_FOR_FLAG)
#undef CASE_FOR_FLAG

    if (is_fastpath) {
      result = string;
      Goto(&done);

      BIND(&runtime);
      {
        result =
            CAST(CallRuntime(Runtime::kRegExpStringFromFlags, context, regexp));
        Goto(&done);
      }

      BIND(&done);
      return result.value();
    } else {
      return string;
    }
  }
}

// ES#sec-regexpinitialize
// Runtime Semantics: RegExpInitialize ( obj, pattern, flags )
TNode<Object> RegExpBuiltinsAssembler::RegExpInitialize(
    const TNode<Context> context, const TNode<JSRegExp> regexp,
    const TNode<Object> maybe_pattern, const TNode<Object> maybe_flags) {
  // Normalize pattern.
  const TNode<Object> pattern = Select<Object>(
      IsUndefined(maybe_pattern), [=, this] { return EmptyStringConstant(); },
      [=, this] { return ToString_Inline(context, maybe_pattern); });

  // Normalize flags.
  const TNode<Object> flags = Select<Object>(
      IsUndefined(maybe_flags), [=, this] { return EmptyStringConstant(); },
      [=, this] { return ToString_Inline(context, maybe_flags); });

  // Initialize.

  return CallRuntime(Runtime::kRegExpInitializeAndCompile, context, regexp,
                     pattern, flags);
}

// ES#sec-regexp-pattern-flags
// RegExp ( pattern, flags )
TF_BUILTIN(RegExpConstructor, RegExpBuiltinsAssembler) {
  auto pattern = Parameter<JSAny>(Descriptor::kPattern);
  auto flags = Parameter<JSAny>(Descriptor::kFlags);
  auto new_target = Parameter<JSAny>(Descriptor::kJSNewTarget);
  auto context = Parameter<Context>(Descriptor::kContext);

  Isolate* isolate = this->isolate();

  TVARIABLE(JSAny, var_flags, flags);
  TVARIABLE(JSAny, var_pattern, pattern);
  TVARIABLE(JSAny, var_new_target, new_target);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSFunction> regexp_function = CAST(
      LoadContextElementNoCell(native_context, Context::REGEXP_FUNCTION_INDEX));

  TNode<BoolT> pattern_is_regexp = IsRegExp(context, pattern);

  {
    Label next(this);

    GotoIfNot(IsUndefined(new_target), &next);
    var_new_target = regexp_function;

    GotoIfNot(pattern_is_regexp, &next);
    GotoIfNot(IsUndefined(flags), &next);

    TNode<Object> value =
        GetProperty(context, pattern, isolate->factory()->constructor_string());

    GotoIfNot(TaggedEqual(value, regexp_function), &next);
    Return(pattern);

    BIND(&next);
  }

  {
    Label next(this), if_patternisfastregexp(this),
        if_patternisslowregexp(this);
    GotoIf(TaggedIsSmi(pattern), &next);

    GotoIf(IsJSRegExp(CAST(pattern)), &if_patternisfastregexp);

    Branch(pattern_is_regexp, &if_patternisslowregexp, &next);

    BIND(&if_patternisfastregexp);
    {
      TNode<JSAny> source =
          CAST(LoadObjectField(CAST(pattern), JSRegExp::kSourceOffset));
      var_pattern = source;

      {
        Label inner_next(this);
        GotoIfNot(IsUndefined(flags), &inner_next);

        var_flags = FlagsGetter(context, pattern, true);
        Goto(&inner_next);

        BIND(&inner_next);
      }

      Goto(&next);
    }

    BIND(&if_patternisslowregexp);
    {
      var_pattern =
          GetProperty(context, pattern, isolate->factory()->source_string());

      {
        Label inner_next(this);
        GotoIfNot(IsUndefined(flags), &inner_next);

        var_flags =
            GetProperty(context, pattern, isolate->factory()->flags_string());
        Goto(&inner_next);

        BIND(&inner_next);
      }

      Goto(&next);
    }

    BIND(&next);
  }

  // Allocate.

  TVARIABLE(JSRegExp, var_regexp);
  {
    Label allocate_jsregexp(this), allocate_generic(this, Label::kDeferred),
        next(this);
    Branch(TaggedEqual(var_new_target.value(), regexp_function),
           &allocate_jsregexp, &allocate_generic);

    BIND(&allocate_jsregexp);
    {
      const TNode<Map> initial_map = CAST(LoadObjectField(
          regexp_function, JSFunction::kPrototypeOrInitialMapOffset));
      var_regexp = CAST(AllocateJSObjectFromMap(initial_map));
      Goto(&next);
    }

    BIND(&allocate_generic);
    {
      ConstructorBuiltinsAssembler constructor_assembler(this->state());
      var_regexp = CAST(constructor_assembler.FastNewObject(
          context, regexp_function, CAST(var_new_target.value())));
      Goto(&next);
    }

    BIND(&next);
  }

  // Clear data field, as a GC can be triggered before it is initialized with a
  // correct trusted pointer handle.
  ClearTrustedPointerField(var_regexp.value(), JSRegExp::kDataOffset);

  const TNode<Object> result = RegExpInitialize(
      context, var_regexp.value(), var_pattern.value(), var_flags.value());
  Return(result);
}

// ES#sec-regexp.prototype.compile
// RegExp.prototype.compile ( pattern, flags )
TF_BUILTIN(RegExpPrototypeCompile, RegExpBuiltinsAssembler) {
  auto maybe_receiver = Parameter<Object>(Descriptor::kReceiver);
  auto maybe_pattern = Parameter<Object>(Descriptor::kPattern);
  auto maybe_flags = Parameter<Object>(Descriptor::kFlags);
  auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, maybe_receiver, JS_REG_EXP_TYPE,
                         "RegExp.prototype.compile");
  const TNode<JSRegExp> receiver = CAST(maybe_receiver);

  TVARIABLE(Object, var_flags, maybe_flags);
  TVARIABLE(Object, var_pattern, maybe_pattern);

  // Handle a JSRegExp pattern.
  {
    Label next(this);

    GotoIf(TaggedIsSmi(maybe_pattern), &next);
    GotoIfNot(IsJSRegExp(CAST(maybe_pattern)), &next);

    // {maybe_flags} must be undefined in this case, otherwise throw.
    {
      Label maybe_flags_is_undefined(this);
      GotoIf(IsUndefined(maybe_flags), &maybe_flags_is_undefined);

      ThrowTypeError(context, MessageTemplate::kRegExpFlags);

      BIND(&maybe_flags_is_undefined);
    }

    const TNode<JSRegExp> pattern = CAST(maybe_pattern);
    const TNode<String> new_flags = FlagsGetter(context, pattern, true);
    const TNode<Object> new_pattern =
        LoadObjectField(pattern, JSRegExp::kSourceOffset);

    var_flags = new_flags;
    var_pattern = new_pattern;

    Goto(&next);
    BIND(&next);
  }

  const TNode<Object> result = RegExpInitialize(
      context, receiver, var_pattern.value(), var_flags.value());
  Return(result);
}

// Fast-path implementation for flag checks on an unmodified JSRegExp instance.
TNode<BoolT> RegExpBuiltinsAssembler::FastFlagGetter(TNode<JSRegExp> regexp,
                                                     JSRegExp::Flag flag) {
  TNode<Smi> flags = CAST(LoadObjectField(regexp, JSRegExp::kFlagsOffset));
  TNode<Smi> mask = SmiConstant(flag);
  return ReinterpretCast<BoolT>(SmiToInt32(
      SmiShr(SmiAnd(flags, mask),
             base::bits::CountTrailingZeros(static_cast<int>(flag)))));
}

TNode<Number> RegExpBuiltinsAssembler::AdvanceStringIndex(
    TNode<String> string, TNode<Number> index, TNode<BoolT> is_unicode,
    bool is_fastpath) {
  CSA_DCHECK(this, IsNumberNormalized(index));
  if (is_fastpath) CSA_DCHECK(this, TaggedIsPositiveSmi(index));

  // Default to last_index + 1.
  // TODO(pwong): Consider using TrySmiAdd for the fast path to reduce generated
  // code.
  TNode<Number> index_plus_one = NumberInc(index);
  TVARIABLE(Number, var_result, index_plus_one);

  // TODO(v8:9880): Given that we have to convert index from Number to UintPtrT
  // anyway, consider using UintPtrT index to simplify the code below.

  // Advancing the index has some subtle issues involving the distinction
  // between Smis and HeapNumbers. There's three cases:
  // * {index} is a Smi, {index_plus_one} is a Smi. The standard case.
  // * {index} is a Smi, {index_plus_one} overflows into a HeapNumber.
  //   In this case we can return the result early, because
  //   {index_plus_one} > {string}.length.
  // * {index} is a HeapNumber, {index_plus_one} is a HeapNumber. This can only
  //   occur when {index} is outside the Smi range since we normalize
  //   explicitly. Again we can return early.
  if (is_fastpath) {
    // Must be in Smi range on the fast path. We control the value of {index}
    // on all call-sites and can never exceed the length of the string.
    static_assert(String::kMaxLength + 2 < Smi::kMaxValue);
    CSA_DCHECK(this, TaggedIsPositiveSmi(index_plus_one));
  }

  Label if_isunicode(this), out(this);
  GotoIfNot(is_unicode, &out);

  // Keep this unconditional (even on the fast path) just to be safe.
  Branch(TaggedIsPositiveSmi(index_plus_one), &if_isunicode, &out,
         BranchHint::kTrue);

  BIND(&if_isunicode);
  {
    TNode<UintPtrT> string_length = Unsigned(LoadStringLengthAsWord(string));
    TNode<UintPtrT> untagged_plus_one =
        Unsigned(SmiUntag(CAST(index_plus_one)));
    GotoIfNot(UintPtrLessThan(untagged_plus_one, string_length), &out,
              GotoHint::kFallthrough);

    TNode<Int32T> lead =
        StringCharCodeAt(string, Unsigned(SmiUntag(CAST(index))));
    GotoIfNot(Word32Equal(Word32And(lead, Int32Constant(0xFC00)),
                          Int32Constant(0xD800)),
              &out, GotoHint::kLabel);

    TNode<Int32T> trail = StringCharCodeAt(string, untagged_plus_one);
    GotoIfNot(Word32Equal(Word32And(trail, Int32Constant(0xFC00)),
                          Int32Constant(0xDC00)),
              &out);

    // At a surrogate pair, return index + 2.
    TNode<Number> index_plus_two = NumberInc(index_plus_one);
    var_result = index_plus_two;

    Goto(&out);
  }

  BIND(&out);
  return var_result.value();
}

// ES#sec-createregexpstringiterator
// CreateRegExpStringIterator ( R, S, global, fullUnicode )
TNode<JSAny> RegExpMatchAllAssembler::CreateRegExpStringIterator(
    TNode<NativeContext> native_context, TNode<JSAny> regexp,
    TNode<String> string, TNode<BoolT> global, TNode<BoolT> full_unicode) {
  TNode<Map> map = CAST(LoadContextElementNoCell(
      native_context,
      Context::INITIAL_REGEXP_STRING_ITERATOR_PROTOTYPE_MAP_INDEX));

  // 4. Let iterator be ObjectCreate(%RegExpStringIteratorPrototype%, «
  // [[IteratingRegExp]], [[IteratedString]], [[Global]], [[Unicode]],
  // [[Done]] »).
  TNode<HeapObject> iterator = Allocate(JSRegExpStringIterator::kHeaderSize);
  StoreMapNoWriteBarrier(iterator, map);
  StoreObjectFieldRoot(iterator,
                       JSRegExpStringIterator::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(iterator, JSRegExpStringIterator::kElementsOffset,
                       RootIndex::kEmptyFixedArray);

  // 5. Set iterator.[[IteratingRegExp]] to R.
  StoreObjectFieldNoWriteBarrier(
      iterator, JSRegExpStringIterator::kIteratingRegExpOffset, regexp);

  // 6. Set iterator.[[IteratedString]] to S.
  StoreObjectFieldNoWriteBarrier(
      iterator, JSRegExpStringIterator::kIteratedStringOffset, string);

  // 7. Set iterator.[[Global]] to global.
  // 8. Set iterator.[[Unicode]] to fullUnicode.
  // 9. Set iterator.[[Done]] to false.
  TNode<Int32T> global_flag =
      Word32Shl(ReinterpretCast<Int32T>(global),
                Int32Constant(JSRegExpStringIterator::GlobalBit::kShift));
  TNode<Int32T> unicode_flag =
      Word32Shl(ReinterpretCast<Int32T>(full_unicode),
                Int32Constant(JSRegExpStringIterator::UnicodeBit::kShift));
  TNode<Int32T> iterator_flags = Word32Or(global_flag, unicode_flag);
  StoreObjectFieldNoWriteBarrier(iterator, JSRegExpStringIterator::kFlagsOffset,
                                 SmiFromInt32(iterator_flags));

  return CAST(iterator);
}

// Generates the fast path for @@split. {regexp} is an unmodified, non-sticky
// JSRegExp, {string} is a String, and {limit} is a Smi.
TNode<JSArray> RegExpBuiltinsAssembler::RegExpPrototypeSplitBody(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> string,
    TNode<Smi> limit) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, Word32BinaryNot(FastFlagGetter(regexp, JSRegExp::kSticky)));

  TNode<IntPtrT> int_limit = SmiUntag(limit);

  const ElementsKind elements_kind = PACKED_ELEMENTS;

  Label done(this);
  Label return_empty_array(this, Label::kDeferred);
  TVARIABLE(JSArray, var_result);

  // Exception handling is necessary to free any allocated memory.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);

  // Allocate the results vector. Allocate space for exactly one result,
  // forcing the engine to return after each match. This is necessary due to
  // the specialized AdvanceStringIndex logic below.
  TNode<RegExpData> data = CAST(LoadTrustedPointerFromObject(
      regexp, JSRegExp::kDataOffset, kRegExpDataIndirectPointerTag));
  TNode<Smi> capture_count = LoadCaptureCount(data);
  TNode<Smi> register_count_per_match = RegistersForCaptureCount(capture_count);
  TNode<RawPtrT> result_offsets_vector;
  TNode<BoolT> result_offsets_vector_is_dynamic;
  std::tie(result_offsets_vector, result_offsets_vector_is_dynamic) =
      LoadOrAllocateRegExpResultVector(register_count_per_match);
  TNode<Int32T> result_offsets_vector_length =
      SmiToInt32(register_count_per_match);

  {
    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);

    // If the limit is zero, return an empty array.
    GotoIf(SmiEqual(limit, SmiZero()), &return_empty_array);

    TNode<Smi> string_length = LoadStringLengthAsSmi(string);

    // If passed the empty {string}, return either an empty array or a singleton
    // array depending on whether the {regexp} matches.
    {
      Label next(this), if_stringisempty(this, Label::kDeferred);
      Branch(SmiEqual(string_length, SmiZero()), &if_stringisempty, &next,
             BranchHint::kFalse);

      BIND(&if_stringisempty);
      {
        TNode<IntPtrT> num_matches = UncheckedCast<IntPtrT>(RegExpExecInternal(
            context, regexp, data, string, SmiZero(), result_offsets_vector,
            result_offsets_vector_length));

        Label if_matched(this), if_not_matched(this);
        Branch(IntPtrEqual(num_matches, IntPtrConstant(0)), &if_not_matched,
               &if_matched);

        BIND(&if_matched);
        {
          CSA_DCHECK(this, IntPtrEqual(num_matches, IntPtrConstant(1)));
          CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
          TNode<RegExpMatchInfo> last_match_info =
              CAST(LoadContextElementNoCell(
                  context, Context::REGEXP_LAST_MATCH_INFO_INDEX));

          InitializeMatchInfoFromRegisters(context, last_match_info,
                                           register_count_per_match, string,
                                           result_offsets_vector);
          Goto(&return_empty_array);
        }

        BIND(&if_not_matched);
        {
          TNode<Smi> length = SmiConstant(1);
          TNode<IntPtrT> capacity = IntPtrConstant(1);
          std::optional<TNode<AllocationSite>> allocation_site = std::nullopt;
          CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
          TNode<Map> array_map =
              LoadJSArrayElementsMap(elements_kind, CAST(context));
          var_result = AllocateJSArray(elements_kind, array_map, capacity,
                                       length, allocation_site);

          TNode<FixedArray> fixed_array =
              CAST(LoadElements(var_result.value()));
          UnsafeStoreFixedArrayElement(fixed_array, 0, string);

          Goto(&done);
        }
      }

      BIND(&next);
    }

    // Loop preparations.

    GrowableFixedArray array(state());

    TVARIABLE(Smi, var_last_matched_until, SmiZero());
    TVARIABLE(Smi, var_next_search_from, SmiZero());

    Label loop(this,
               {array.var_array(), array.var_length(), array.var_capacity(),
                &var_last_matched_until, &var_next_search_from}),
        push_suffix_and_out(this), out(this);
    Goto(&loop);

    BIND(&loop);
    {
      TNode<Smi> next_search_from = var_next_search_from.value();
      TNode<Smi> last_matched_until = var_last_matched_until.value();

      // We're done if we've reached the end of the string.
      GotoIf(SmiEqual(next_search_from, string_length), &push_suffix_and_out);

      // Search for the given {regexp}.

      TNode<IntPtrT> num_matches = UncheckedCast<IntPtrT>(RegExpExecInternal(
          context, regexp, data, string, next_search_from,
          result_offsets_vector, result_offsets_vector_length));

      // We're done if no match was found.
      GotoIf(IntPtrEqual(num_matches, IntPtrConstant(0)), &push_suffix_and_out);

      TNode<Int32T> match_from_int32 = UncheckedCast<Int32T>(
          Load(MachineType::Int32(), result_offsets_vector, IntPtrConstant(0)));
      TNode<Smi> match_from = SmiFromInt32(match_from_int32);

      // We're also done if the match is at the end of the string.
      GotoIf(SmiEqual(match_from, string_length), &push_suffix_and_out);

      // Set the LastMatchInfo.
      // TODO(jgruber): We could elide all but the last of these. BUT this is
      // tricky due to how we omit any match at the end of the string, which
      // makes it hard to tell if we're at the 'last match except for
      // empty-match-at-end-of-string'.
      CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
      TNode<RegExpMatchInfo> match_info = CAST(LoadContextElementNoCell(
          context, Context::REGEXP_LAST_MATCH_INFO_INDEX));
      match_info = InitializeMatchInfoFromRegisters(
          context, match_info, register_count_per_match, string,
          result_offsets_vector);

      TNode<Smi> match_to = LoadArrayElement(match_info, IntPtrConstant(1));

      // Advance index and continue if the match is empty.
      {
        Label next(this);

        GotoIfNot(SmiEqual(match_to, next_search_from), &next);
        GotoIfNot(SmiEqual(match_to, last_matched_until), &next);

        TNode<BoolT> is_unicode =
            Word32Or(FastFlagGetter(regexp, JSRegExp::kUnicode),
                     FastFlagGetter(regexp, JSRegExp::kUnicodeSets));
        TNode<Number> new_next_search_from =
            AdvanceStringIndex(string, next_search_from, is_unicode, true);
        var_next_search_from = CAST(new_next_search_from);
        Goto(&loop);

        BIND(&next);
      }

      // A valid match was found, add the new substring to the array.
      {
        TNode<Smi> from = last_matched_until;
        TNode<Smi> to = match_from;
        array.Push(CallBuiltin(Builtin::kSubString, context, string, from, to));
        GotoIf(WordEqual(array.length(), int_limit), &out);
      }

      // Add all captures to the array.
      {
        TNode<IntPtrT> int_num_registers =
            PositiveSmiUntag(register_count_per_match);

        TVARIABLE(IntPtrT, var_reg, IntPtrConstant(2));

        Label nested_loop(this, {array.var_array(), array.var_length(),
                                 array.var_capacity(), &var_reg}),
            nested_loop_out(this);
        Branch(IntPtrLessThan(var_reg.value(), int_num_registers), &nested_loop,
               &nested_loop_out);

        BIND(&nested_loop);
        {
          TNode<IntPtrT> reg = var_reg.value();
          TNode<Smi> from = LoadArrayElement(match_info, reg);
          TNode<Smi> to = LoadArrayElement(match_info, reg, 1 * kTaggedSize);

          Label select_capture(this), select_undefined(this), store_value(this);
          TVARIABLE(Object, var_value);
          Branch(SmiEqual(to, SmiConstant(-1)), &select_undefined,
                 &select_capture);

          BIND(&select_capture);
          {
            var_value =
                CallBuiltin(Builtin::kSubString, context, string, from, to);
            Goto(&store_value);
          }

          BIND(&select_undefined);
          {
            var_value = UndefinedConstant();
            Goto(&store_value);
          }

          BIND(&store_value);
          {
            array.Push(var_value.value());
            GotoIf(WordEqual(array.length(), int_limit), &out);

            TNode<IntPtrT> new_reg = IntPtrAdd(reg, IntPtrConstant(2));
            var_reg = new_reg;

            Branch(IntPtrLessThan(new_reg, int_num_registers), &nested_loop,
                   &nested_loop_out);
          }
        }

        BIND(&nested_loop_out);
      }

      var_last_matched_until = match_to;
      var_next_search_from = match_to;
      Goto(&loop);
    }

    BIND(&push_suffix_and_out);
    {
      TNode<Smi> from = var_last_matched_until.value();
      TNode<Smi> to = string_length;
      array.Push(CallBuiltin(Builtin::kSubString, context, string, from, to));
      Goto(&out);
    }

    BIND(&out);
    {
      var_result = array.ToJSArray(context);
      Goto(&done);
    }

    BIND(&return_empty_array);
    {
      TNode<Smi> length = SmiZero();
      TNode<IntPtrT> capacity = IntPtrZero();
      std::optional<TNode<AllocationSite>> allocation_site = std::nullopt;
      CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
      TNode<Map> array_map =
          LoadJSArrayElementsMap(elements_kind, CAST(context));
      var_result = AllocateJSArray(elements_kind, array_map, capacity, length,
                                   allocation_site);
      Goto(&done);
    }
  }

  BIND(&if_exception);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  CallRuntime(Runtime::kReThrow, context, var_exception.value());
  Unreachable();

  BIND(&done);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  return var_result.value();
}

TNode<IntPtrT> RegExpBuiltinsAssembler::RegExpExecInternal_Batched(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
    TNode<RegExpData> data, const VariableList& merge_vars,
    OncePerBatchFunction once_per_batch, OncePerMatchFunction once_per_match) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, FastFlagGetter(regexp, JSRegExp::kGlobal));

  // This calls into irregexp and loops over the returned result. Roughly:
  //
  // max_matches = .. that fit into the given offsets array;
  // num_matches_in_batch = max_matches;
  // index = 0;
  // while (num_matches_in_batch == max_matches) {
  //   num_matches_in_batch = ExecInternal(..., index);
  //   for (i = 0; i < num_matches_in_batch; i++) {
  //     .. handle match i
  //   }
  //   index = MaybeAdvanceZeroLength(last_end_index)
  // }

  Label out(this);

  // Exception handling is necessary to free any allocated memory.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred);

  // Determine the number of result slots we want and allocate them.
  TNode<Smi> register_count_per_match =
      RegistersForCaptureCount(LoadCaptureCount(data));
  // TODO(jgruber): Consider a different length selection that considers the
  // register count per match and can go higher than the current static offsets
  // size. Could be helpful for patterns that 1. have many captures and 2.
  // match many times in the given string.
  TNode<Smi> result_offsets_vector_length =
      SmiMax(register_count_per_match,
             SmiConstant(Isolate::kJSRegexpStaticOffsetsVectorSize));
  TNode<RawPtrT> result_offsets_vector;
  TNode<BoolT> result_offsets_vector_is_dynamic;
  std::tie(result_offsets_vector, result_offsets_vector_is_dynamic) =
      LoadOrAllocateRegExpResultVector(result_offsets_vector_length);

  TNode<BoolT> is_unicode =
      Word32Or(FastFlagGetter(regexp, JSRegExp::kUnicode),
               FastFlagGetter(regexp, JSRegExp::kUnicodeSets));

  TVARIABLE(IntPtrT, var_last_match_offsets_vector, IntPtrConstant(0));
  TVARIABLE(Int32T, var_start_of_last_match, Int32Constant(0));
  TVARIABLE(Int32T, var_last_index, Int32Constant(0));
  FastStoreLastIndex(regexp, SmiConstant(0));

  TNode<IntPtrT> max_matches_in_batch =
      IntPtrDiv(SmiUntag(result_offsets_vector_length),
                SmiUntag(register_count_per_match));
  // Initialize such that we always enter the loop initially:
  TVARIABLE(IntPtrT, var_num_matches_in_batch, max_matches_in_batch);
  TVARIABLE(IntPtrT, var_num_matches, IntPtrConstant(0));

  // Loop over multiple batch executions:
  VariableList outer_loop_merge_vars(
      {&var_num_matches_in_batch, &var_num_matches, &var_last_index,
       &var_start_of_last_match, &var_last_match_offsets_vector},
      zone());
  outer_loop_merge_vars.insert(outer_loop_merge_vars.end(), merge_vars.begin(),
                               merge_vars.end());
  Label outer_loop(this, outer_loop_merge_vars);
  Label outer_loop_exit(this);
  Goto(&outer_loop);
  BIND(&outer_loop);
  {
    // Loop condition:
    GotoIf(
        IntPtrLessThan(var_num_matches_in_batch.value(), max_matches_in_batch),
        &outer_loop_exit);

    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);

    var_num_matches_in_batch = UncheckedCast<IntPtrT>(RegExpExecInternal(
        context, regexp, data, subject, SmiFromInt32(var_last_index.value()),
        result_offsets_vector, SmiToInt32(result_offsets_vector_length)));

    GotoIf(IntPtrEqual(var_num_matches_in_batch.value(), IntPtrConstant(0)),
           &outer_loop_exit);

    var_num_matches =
        IntPtrAdd(var_num_matches.value(), var_num_matches_in_batch.value());

    // At least one match was found. Construct the result array.
    //
    // Loop over the current batch of results:
    {
      once_per_batch(var_num_matches_in_batch.value());

      TNode<IntPtrT> register_count_per_match_intptr =
          SmiUntag(register_count_per_match);
      VariableList inner_loop_merge_vars(
          {&var_last_index, &var_start_of_last_match,
           &var_last_match_offsets_vector},
          zone());
      inner_loop_merge_vars.insert(inner_loop_merge_vars.end(),
                                   merge_vars.begin(), merge_vars.end());
      // Has to be IntPtrT for BuildFastLoop.
      TNode<IntPtrT> inner_loop_start =
          UncheckedCast<IntPtrT>(result_offsets_vector);
      TNode<IntPtrT> inner_loop_increment = WordShl(
          register_count_per_match_intptr, IntPtrConstant(kInt32SizeLog2));
      TNode<IntPtrT> inner_loop_end = IntPtrAdd(
          inner_loop_start,
          IntPtrMul(inner_loop_increment, var_num_matches_in_batch.value()));

      TVARIABLE(IntPtrT, var_inner_loop_index);
      BuildFastLoop<IntPtrT>(
          inner_loop_merge_vars, var_inner_loop_index, inner_loop_start,
          inner_loop_end,
          [&](TNode<IntPtrT> current_match_offsets_vector) {
            TNode<Int32T> start = UncheckedCast<Int32T>(
                Load(MachineType::Int32(), current_match_offsets_vector,
                     IntPtrConstant(0)));
            TNode<Int32T> end = UncheckedCast<Int32T>(
                Load(MachineType::Int32(), current_match_offsets_vector,
                     IntPtrConstant(kInt32Size)));

            once_per_match(UncheckedCast<RawPtrT>(current_match_offsets_vector),
                           start, end);

            var_last_match_offsets_vector = current_match_offsets_vector;
            var_start_of_last_match = start;
            var_last_index = end;
          },
          inner_loop_increment, LoopUnrollingMode::kYes,
          IndexAdvanceMode::kPost, IndexAdvanceDirection::kUp);
    }

    GotoIf(
        Word32NotEqual(var_start_of_last_match.value(), var_last_index.value()),
        &outer_loop, GotoHint::kLabel);

    // For zero-length matches we need to run AdvanceStringIndex.
    var_last_index = SmiToInt32(CAST(AdvanceStringIndex(
        subject, SmiFromInt32(var_last_index.value()), is_unicode, true)));

    Goto(&outer_loop);
  }
  BIND(&outer_loop_exit);

  // If there were no matches, just return.
  GotoIf(IntPtrEqual(var_num_matches.value(), IntPtrConstant(0)), &out);

  // Otherwise initialize the last match info and the result JSArray.
  CSA_DCHECK(this, TaggedEqual(context, LoadNativeContext(context)));
  TNode<RegExpMatchInfo> last_match_info = CAST(
      LoadContextElementNoCell(context, Context::REGEXP_LAST_MATCH_INFO_INDEX));

  InitializeMatchInfoFromRegisters(context, last_match_info,
                                   register_count_per_match, subject,
                                   var_last_match_offsets_vector.value());

  Goto(&out);

  BIND(&if_exception);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  CallRuntime(Runtime::kReThrow, context, var_exception.value());
  Unreachable();

  BIND(&out);
  FreeRegExpResultVector(result_offsets_vector,
                         result_offsets_vector_is_dynamic);
  return var_num_matches.value();
}

TNode<Union<Null, JSArray>> RegExpBuiltinsAssembler::RegExpMatchGlobal(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
    TNode<RegExpData> data) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, FastFlagGetter(regexp, JSRegExp::kGlobal));

  TVARIABLE((Union<Null, JSArray>), var_result, NullConstant());
  Label out(this);
  GrowableFixedArray array(state());

  VariableList merge_vars(
      {array.var_array(), array.var_length(), array.var_capacity()}, zone());
  TNode<IntPtrT> num_matches = RegExpExecInternal_Batched(
      context, regexp, subject, data, merge_vars,
      [&](TNode<IntPtrT> num_matches_in_batch) {
        array.Reserve(UncheckedCast<IntPtrT>(
            IntPtrAdd(array.length(), num_matches_in_batch)));
      },
      [&](TNode<RawPtrT> match_offsets, TNode<Int32T> match_start,
          TNode<Int32T> match_end) {
        TNode<Smi> start = SmiFromInt32(match_start);
        TNode<Smi> end = SmiFromInt32(match_end);

        // TODO(jgruber): Consider inlining this or at least reducing the number
        // of redundant checks.
        TNode<String> matched_string = CAST(
            CallBuiltin(Builtin::kSubString, context, subject, start, end));
        array.Push(matched_string);
      });

  CSA_DCHECK(this, IntPtrEqual(num_matches, array.length()));

  // No matches, return null.
  GotoIf(IntPtrEqual(num_matches, IntPtrConstant(0)), &out);

  // Otherwise create the JSArray.
  var_result = array.ToJSArray(context);
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<String> RegExpBuiltinsAssembler::AppendStringSlice(
    TNode<Context> context, TNode<String> to_string, TNode<String> from_string,
    TNode<Smi> slice_start, TNode<Smi> slice_end) {
  // TODO(jgruber): Consider inlining this.
  CSA_DCHECK(this, SmiLessThanOrEqual(slice_start, slice_end));
  TNode<String> slice = CAST(CallBuiltin(Builtin::kSubString, context,
                                         from_string, slice_start, slice_end));
  return CAST(
      CallBuiltin(Builtin::kStringAdd_CheckNone, context, to_string, slice));
}

TNode<String> RegExpBuiltinsAssembler::RegExpReplaceGlobalSimpleString(
    TNode<Context> context, TNode<JSRegExp> regexp, TNode<String> subject,
    TNode<RegExpData> data, TNode<String> replace_string) {
  CSA_DCHECK(this, IsFastRegExpPermissive(context, regexp));
  CSA_DCHECK(this, FastFlagGetter(regexp, JSRegExp::kGlobal));

  // The replace_string is 'simple' if it doesn't contain a '$' character.
  CSA_SLOW_DCHECK(this,
                  SmiEqual(StringBuiltinsAssembler{state()}.IndexOfDollarChar(
                               context, replace_string),
                           SmiConstant(-1)));

  TNode<Smi> replace_string_length = LoadStringLengthAsSmi(replace_string);

  TVARIABLE(String, var_result, EmptyStringConstant());
  TVARIABLE(Smi, var_last_match_end, SmiConstant(0));

  VariableList merge_vars({&var_result, &var_last_match_end}, zone());
  RegExpExecInternal_Batched(
      context, regexp, subject, data, merge_vars,
      [&](TNode<IntPtrT> num_matches_in_batch) {},
      [&](TNode<RawPtrT> match_offsets, TNode<Int32T> match_start,
          TNode<Int32T> match_end) {
        TNode<Smi> start = SmiFromInt32(match_start);
        TNode<Smi> end = SmiFromInt32(match_end);

        // Append the slice between this and the previous match.
        var_result = AppendStringSlice(context, var_result.value(), subject,
                                       var_last_match_end.value(), start);

        // Append the replace_string.
        {
          Label next(this);
          GotoIf(SmiEqual(replace_string_length, SmiConstant(0)), &next);

          var_result = CAST(CallBuiltin(Builtin::kStringAdd_CheckNone, context,
                                        var_result.value(), replace_string));
          Goto(&next);

          BIND(&next);
        }

        var_last_match_end = end;
      });

  var_result = AppendStringSlice(context, var_result.value(), subject,
                                 var_last_match_end.value(),
                                 LoadStringLengthAsSmi(subject));
  return var_result.value();
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
