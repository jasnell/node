'use strict';

// New Streams API - Consumers & Utilities
//
// bytes(), text(), arrayBuffer() - collect entire stream
// tap(), tapSync() - observe without modifying
// merge() - temporal combining of sources
// ondrain() - backpressure drain utility

const {
  ArrayBufferPrototypeGetByteLength,
  ArrayBufferPrototypeSlice,
  ArrayIsArray,
  ArrayPrototypeFilter,
  ArrayPrototypeMap,
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  PromisePrototypeThen,
  PromiseResolve,
  SafePromiseAllReturnVoid,
  SafePromiseRace,
  SymbolAsyncIterator,
  SymbolIterator,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
} = primordials;

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_OUT_OF_RANGE,
  },
} = require('internal/errors');
const { TextDecoder } = require('internal/encoding');
const {
  validateAbortSignal,
  validateFunction,
  validateInteger,
  validateObject,
} = require('internal/validators');

const {
  isAsyncIterable,
  isSyncIterable,
} = require('internal/streams/iter/from');

const {
  concatBytes,
} = require('internal/streams/iter/utils');

const {
  drainableProtocol,
} = require('internal/streams/iter/types');

// =============================================================================
// Type Guards
// =============================================================================

function isMergeOptions(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !isAsyncIterable(value) &&
    !isSyncIterable(value)
  );
}

// Normalize a yielded value to a Uint8Array[] batch. Sources should yield
// Uint8Array[] but a raw Uint8Array or string is tolerated by wrapping it.
function ensureBatch(batch) {
  if (ArrayIsArray(batch)) return batch;
  return [batch];
}

// =============================================================================
// Shared chunk collection helpers
// =============================================================================

/**
 * Collect chunks from a sync source into an array.
 * @param {Iterable<Uint8Array[]>} source
 * @param {number} [limit]
 * @returns {Uint8Array[]}
 */
function collectSync(source, limit) {
  const chunks = [];
  let totalBytes = 0;

  for (const raw of source) {
    const batch = ensureBatch(raw);
    for (let i = 0; i < batch.length; i++) {
      const chunk = batch[i];
      if (limit !== undefined) {
        totalBytes += TypedArrayPrototypeGetByteLength(chunk);
        if (totalBytes > limit) {
          throw new ERR_OUT_OF_RANGE('totalBytes', `<= ${limit}`, totalBytes);
        }
      }
      ArrayPrototypePush(chunks, chunk);
    }
  }

  return chunks;
}

/**
 * Collect chunks from an async or sync source into an array.
 * @param {AsyncIterable<Uint8Array[]>|Iterable<Uint8Array[]>} source
 * @param {AbortSignal} [signal]
 * @param {number} [limit]
 * @returns {Promise<Uint8Array[]>}
 */
async function collectAsync(source, signal, limit) {
  signal?.throwIfAborted();

  const chunks = [];

  // Fast path: no signal and no limit
  if (!signal && limit === undefined) {
    if (isAsyncIterable(source)) {
      for await (const raw of source) {
        const batch = ensureBatch(raw);
        for (let i = 0; i < batch.length; i++) {
          ArrayPrototypePush(chunks, batch[i]);
        }
      }
    } else if (isSyncIterable(source)) {
      for (const raw of source) {
        const batch = ensureBatch(raw);
        for (let i = 0; i < batch.length; i++) {
          ArrayPrototypePush(chunks, batch[i]);
        }
      }
    } else {
      throw new ERR_INVALID_ARG_TYPE('source', ['AsyncIterable', 'Iterable'], source);
    }
    return chunks;
  }

  // Slow path: with signal or limit checks
  let totalBytes = 0;

  if (isAsyncIterable(source)) {
    for await (const raw of source) {
      const batch = ensureBatch(raw);
      signal?.throwIfAborted();
      for (let i = 0; i < batch.length; i++) {
        const chunk = batch[i];
        if (limit !== undefined) {
          totalBytes += TypedArrayPrototypeGetByteLength(chunk);
          if (totalBytes > limit) {
            throw new ERR_OUT_OF_RANGE('totalBytes', `<= ${limit}`, totalBytes);
          }
        }
        ArrayPrototypePush(chunks, chunk);
      }
    }
  } else if (isSyncIterable(source)) {
    for (const raw of source) {
      const batch = ensureBatch(raw);
      signal?.throwIfAborted();
      for (let i = 0; i < batch.length; i++) {
        const chunk = batch[i];
        if (limit !== undefined) {
          totalBytes += TypedArrayPrototypeGetByteLength(chunk);
          if (totalBytes > limit) {
            throw new ERR_OUT_OF_RANGE('totalBytes', `<= ${limit}`, totalBytes);
          }
        }
        ArrayPrototypePush(chunks, chunk);
      }
    }
  } else {
    throw new ERR_INVALID_ARG_TYPE('source', ['AsyncIterable', 'Iterable'], source);
  }

  return chunks;
}

/**
 * Convert a Uint8Array to its backing ArrayBuffer, slicing if necessary.
 * @param {Uint8Array} data
 * @returns {ArrayBuffer}
 */
function toArrayBuffer(data) {
  const byteOffset = TypedArrayPrototypeGetByteOffset(data);
  const byteLength = TypedArrayPrototypeGetByteLength(data);
  const buffer = TypedArrayPrototypeGetBuffer(data);
  if (byteOffset === 0 &&
      byteLength === ArrayBufferPrototypeGetByteLength(buffer)) {
    return buffer;
  }
  return ArrayBufferPrototypeSlice(buffer, byteOffset,
                                   byteOffset + byteLength);
}

// =============================================================================
// Shared option validation
// =============================================================================

function validateConsumerOptions(options) {
  validateObject(options, 'options');
  if (options.signal !== undefined) {
    validateAbortSignal(options.signal, 'options.signal');
  }
  if (options.limit !== undefined) {
    validateInteger(options.limit, 'options.limit', 0);
  }
  if (options.encoding !== undefined) {
    if (typeof options.encoding !== 'string') {
      throw new ERR_INVALID_ARG_TYPE('options.encoding', 'string',
                                     options.encoding);
    }
    try {
      new TextDecoder(options.encoding);
    } catch {
      throw new ERR_INVALID_ARG_VALUE('options.encoding', options.encoding);
    }
  }
}

function validateSyncConsumerOptions(options) {
  validateObject(options, 'options');
  if (options.limit !== undefined) {
    validateInteger(options.limit, 'options.limit', 0);
  }
  if (options.encoding !== undefined) {
    if (typeof options.encoding !== 'string') {
      throw new ERR_INVALID_ARG_TYPE('options.encoding', 'string',
                                     options.encoding);
    }
    try {
      new TextDecoder(options.encoding);
    } catch {
      throw new ERR_INVALID_ARG_VALUE('options.encoding', options.encoding);
    }
  }
}

// =============================================================================
// Sync Consumers
// =============================================================================

/**
 * Collect all bytes from a sync source.
 * @param {Iterable<Uint8Array[]>} source
 * @param {{ limit?: number }} [options]
 * @returns {Uint8Array}
 */
function bytesSync(source, options = { __proto__: null }) {
  validateSyncConsumerOptions(options);
  return concatBytes(collectSync(source, options?.limit));
}

/**
 * Collect and decode text from a sync source.
 * @param {Iterable<Uint8Array[]>} source
 * @param {{ encoding?: string, limit?: number }} [options]
 * @returns {string}
 */
function textSync(source, options = { __proto__: null }) {
  validateSyncConsumerOptions(options);
  const data = concatBytes(collectSync(source, options.limit));
  const decoder = new TextDecoder(options.encoding ?? 'utf-8', {
    __proto__: null,
    fatal: true,
    ignoreBOM: true,
  });
  return decoder.decode(data);
}

/**
 * Collect bytes as ArrayBuffer from a sync source.
 * @param {Iterable<Uint8Array[]>} source
 * @param {{ limit?: number }} [options]
 * @returns {ArrayBuffer}
 */
function arrayBufferSync(source, options = { __proto__: null }) {
  validateSyncConsumerOptions(options);
  return toArrayBuffer(concatBytes(collectSync(source, options.limit)));
}

/**
 * Collect all chunks as an array from a sync source.
 * @param {Iterable<Uint8Array[]>} source
 * @param {{ limit?: number }} [options]
 * @returns {Uint8Array[]}
 */
function arraySync(source, options = { __proto__: null }) {
  validateSyncConsumerOptions(options);
  return collectSync(source, options.limit);
}

// =============================================================================
// Async Consumers
// =============================================================================

/**
 * Collect all bytes from an async or sync source.
 * @param {AsyncIterable<Uint8Array[]>|Iterable<Uint8Array[]>} source
 * @param {{ signal?: AbortSignal, limit?: number }} [options]
 * @returns {Promise<Uint8Array>}
 */
async function bytes(source, options = { __proto__: null }) {
  validateConsumerOptions(options);
  const chunks = await collectAsync(source, options.signal, options.limit);
  return concatBytes(chunks);
}

/**
 * Collect and decode text from an async or sync source.
 * @param {AsyncIterable<Uint8Array[]>|Iterable<Uint8Array[]>} source
 * @param {{ encoding?: string, signal?: AbortSignal, limit?: number }} [options]
 * @returns {Promise<string>}
 */
async function text(source, options = { __proto__: null }) {
  validateConsumerOptions(options);
  const chunks = await collectAsync(source, options.signal, options.limit);
  const data = concatBytes(chunks);
  const decoder = new TextDecoder(options.encoding ?? 'utf-8', {
    __proto__: null,
    fatal: true,
    ignoreBOM: true,
  });
  return decoder.decode(data);
}

/**
 * Collect bytes as ArrayBuffer from an async or sync source.
 * @param {AsyncIterable<Uint8Array[]>|Iterable<Uint8Array[]>} source
 * @param {{ signal?: AbortSignal, limit?: number }} [options]
 * @returns {Promise<ArrayBuffer>}
 */
async function arrayBuffer(source, options = { __proto__: null }) {
  validateConsumerOptions(options);
  const chunks = await collectAsync(source, options.signal, options.limit);
  return toArrayBuffer(concatBytes(chunks));
}

/**
 * Collect all chunks as an array from an async or sync source.
 * @param {AsyncIterable<Uint8Array[]>|Iterable<Uint8Array[]>} source
 * @param {{ signal?: AbortSignal, limit?: number }} [options]
 * @returns {Promise<Uint8Array[]>}
 */
async function array(source, options = { __proto__: null }) {
  validateConsumerOptions(options);
  return collectAsync(source, options.signal, options.limit);
}

// =============================================================================
// Tap Utilities
// =============================================================================

/**
 * Create a pass-through transform that observes chunks without modifying them.
 * @param {Function} callback
 * @returns {Function}
 */
function tap(callback) {
  validateFunction(callback, 'callback');
  return async (chunks, options) => {
    await callback(chunks, options);
    return chunks;
  };
}

/**
 * Create a sync pass-through transform that observes chunks.
 * @param {Function} callback
 * @returns {Function}
 */
function tapSync(callback) {
  validateFunction(callback, 'callback');
  return (chunks) => {
    callback(chunks);
    return chunks;
  };
}

// =============================================================================
// Drain Utility
// =============================================================================

/**
 * Wait for a drainable object's backpressure to clear.
 * @param {object} drainable
 * @returns {Promise<boolean>|null}
 */
function ondrain(drainable) {
  if (
    drainable === null ||
    drainable === undefined ||
    typeof drainable !== 'object'
  ) {
    return null;
  }

  if (
    !(drainableProtocol in drainable) ||
    typeof drainable[drainableProtocol] !== 'function'
  ) {
    return null;
  }

  try {
    return drainable[drainableProtocol]();
  } catch {
    return null;
  }
}

// =============================================================================
// Merge Utility
// =============================================================================

/**
 * Merge multiple async iterables by yielding values in temporal order.
 * @param {...(AsyncIterable<Uint8Array[]>|object)} args
 * @returns {AsyncIterable<Uint8Array[]>}
 */
function merge(...args) {
  let sources;
  let options;

  if (args.length > 0 && isMergeOptions(args[args.length - 1])) {
    options = args[args.length - 1];
    sources = ArrayPrototypeSlice(args, 0, -1);
  } else {
    sources = args;
  }

  if (options?.signal !== undefined) {
    validateAbortSignal(options.signal, 'options.signal');
  }

  return {
    __proto__: null,
    async *[SymbolAsyncIterator]() {
      const signal = options?.signal;

      signal?.throwIfAborted();

      if (sources.length === 0) return;

      if (sources.length === 1) {
        for await (const batch of sources[0]) {
          signal?.throwIfAborted();
          yield batch;
        }
        return;
      }

      // Multiple sources - race them
      const states = ArrayPrototypeMap(sources, (source) => {
        let iterator;
        if (source[SymbolAsyncIterator]) {
          iterator = source[SymbolAsyncIterator]();
        } else if (source[SymbolIterator]) {
          // Wrap sync iterator to async
          const syncIter = source[SymbolIterator]();
          iterator = {
            __proto__: null,
            next() { return PromiseResolve(syncIter.next()); },
            return() {
              return PromiseResolve(syncIter.return?.() ??
                { __proto__: null, done: true, value: undefined });
            },
          };
        } else {
          throw new ERR_INVALID_ARG_TYPE(
            'source', ['AsyncIterable', 'Iterable'], source);
        }
        return { __proto__: null, iterator, done: false, pending: null };
      });

      const startIterator = (state, index) => {
        if (!state.done && !state.pending) {
          state.pending = PromisePrototypeThen(
            state.iterator.next(),
            (result) => ({ __proto__: null, index, result }));
        }
      };

      // Start all
      for (let i = 0; i < states.length; i++) {
        startIterator(states[i], i);
      }

      try {
        while (true) {
          signal?.throwIfAborted();

          const pending = ArrayPrototypeFilter(
            ArrayPrototypeMap(states,
                              (state) => state.pending),
            (p) => p !== null);

          if (pending.length === 0) break;

          const { index, result } = await SafePromiseRace(pending);

          states[index].pending = null;

          if (result.done) {
            states[index].done = true;
          } else {
            yield result.value;
            startIterator(states[index], index);
          }
        }
      } finally {
        // Clean up: return all iterators
        await SafePromiseAllReturnVoid(states, async (state) => {
          if (!state.done && state.iterator.return) {
            try {
              await state.iterator.return();
            } catch {
              // Ignore return errors
            }
          }
        });
      }
    },
  };
}

module.exports = {
  bytes,
  bytesSync,
  text,
  textSync,
  arrayBuffer,
  arrayBufferSync,
  array,
  arraySync,
  tap,
  tapSync,
  merge,
  ondrain,
};
