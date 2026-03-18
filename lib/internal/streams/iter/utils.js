'use strict';

// New Streams API - Utility Functions

const {
  Array,
  ArrayPrototypeSlice,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeSet,
  Uint8Array,
} = primordials;

const { TextEncoder } = require('internal/encoding');
const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
  },
} = require('internal/errors');
const { isUint8Array } = require('internal/util/types');

// Shared TextEncoder instance for string conversion.
const encoder = new TextEncoder();

// Default high water marks for push and multi-consumer streams. These values
// are somewhat arbitrary but have been tested across various workloads and
// appear to yield the best overall throughput/latency balance.

/** Default high water mark for push streams (single-consumer). */
const kPushDefaultHWM = 4;

/** Default high water mark for broadcast and share streams (multi-consumer). */
const kMultiConsumerDefaultHWM = 16;

/**
 * Convert a chunk (string or Uint8Array) to Uint8Array.
 * Strings are UTF-8 encoded.
 * @param {Uint8Array|string} chunk
 * @returns {Uint8Array}
 */
function toUint8Array(chunk) {
  if (typeof chunk === 'string') {
    return encoder.encode(chunk);
  }
  if (!isUint8Array(chunk)) {
    throw new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Uint8Array'], chunk);
  }
  return chunk;
}

/**
 * Check if all chunks in an array are already Uint8Array (no strings).
 * Short-circuits on the first string found.
 * @param {Array<Uint8Array|string>} chunks
 * @returns {boolean}
 */
function allUint8Array(chunks) {
  for (let i = 0; i < chunks.length; i++) {
    if (typeof chunks[i] === 'string') return false;
  }
  return true;
}

/**
 * Concatenate multiple Uint8Arrays into a single Uint8Array.
 * @param {Uint8Array[]} chunks
 * @returns {Uint8Array}
 */
function concatBytes(chunks) {
  if (chunks.length === 0) {
    return new Uint8Array(0);
  }
  if (chunks.length === 1) {
    return chunks[0];
  }

  const len = chunks.length;
  const lengths = new Array(len);
  let total = 0;
  for (let i = 0; i < len; i++) {
    const l = TypedArrayPrototypeGetByteLength(chunks[i]);
    lengths[i] = l;
    total += l;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < len; i++) {
    TypedArrayPrototypeSet(result, chunks[i], offset);
    offset += lengths[i];
  }
  return result;
}

/**
 * Check if a value is PullOptions (object without transform or write property).
 * @param {unknown} value
 * @returns {boolean}
 */
function isPullOptions(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !('transform' in value) &&
    !('write' in value)
  );
}

/**
 * Check if a value is a valid transform (function or transform object).
 * @param {unknown} value
 * @returns {boolean}
 */
function isTransform(value) {
  return typeof value === 'function' ||
    (value !== null && typeof value === 'object' &&
     typeof value.transform === 'function');
}

/**
 * Parse variadic arguments for pull/pullSync.
 * Returns { transforms, options }
 * @param {Array} args
 * @returns {{ transforms: Array, options: object|undefined }}
 */
function parsePullArgs(args) {
  if (args.length === 0) {
    return { __proto__: null, transforms: [], options: undefined };
  }

  let transforms;
  let options;
  const last = args[args.length - 1];
  if (isPullOptions(last)) {
    transforms = ArrayPrototypeSlice(args, 0, -1);
    options = last;
  } else {
    transforms = args;
    options = undefined;
  }

  for (let i = 0; i < transforms.length; i++) {
    if (!isTransform(transforms[i])) {
      throw new ERR_INVALID_ARG_TYPE(
        `transforms[${i}]`, ['Function', 'Object with transform()'],
        transforms[i]);
    }
  }

  return { __proto__: null, transforms, options };
}

/**
 * Validate backpressure option value.
 * @param {string} value
 */
function validateBackpressure(value) {
  if (value !== 'strict' &&
      value !== 'block' &&
      value !== 'drop-oldest' &&
      value !== 'drop-newest') {
    throw new ERR_INVALID_ARG_VALUE(
      'options.backpressure', value,
      'must be "strict", "block", "drop-oldest", or "drop-newest"');
  }
}

module.exports = {
  kPushDefaultHWM,
  kMultiConsumerDefaultHWM,
  toUint8Array,
  allUint8Array,
  concatBytes,
  isPullOptions,
  isTransform,
  parsePullArgs,
  validateBackpressure,
};
