'use strict';

// New Streams API - Pull Pipeline
//
// pull(), pullSync(), pipeTo(), pipeToSync()
// Pull-through pipelines with transforms. Data flows on-demand from source
// through transforms to consumer.

const {
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  String,
  SymbolAsyncIterator,
  SymbolIterator,
  TypedArrayPrototypeGetByteLength,
} = primordials;

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_OPERATION_FAILED,
  },
} = require('internal/errors');
const { isError, lazyDOMException } = require('internal/util');
const { validateAbortSignal } = require('internal/validators');
const {
  isPromise,
  isUint8Array,
} = require('internal/util/types');
const { AbortController } = require('internal/abort_controller');

const {
  normalizeAsyncSource,
  normalizeSyncSource,
  isSyncIterable,
  isAsyncIterable,
  isUint8ArrayBatch,
} = require('internal/streams/iter/from');

const {
  isPullOptions,
  isTransform,
  parsePullArgs,
  toUint8Array,
} = require('internal/streams/iter/utils');

// =============================================================================
// Type Guards and Helpers
// =============================================================================

/**
 * Check if a value is a TransformObject (has transform property).
 * @returns {boolean}
 */
function isTransformObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    'transform' in value &&
    typeof value.transform === 'function'
  );
}

/**
 * Check if a value is a Writer (has write method).
 * @returns {boolean}
 */
function isWriter(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    'write' in value &&
    typeof value.write === 'function'
  );
}

/**
 * Parse variadic arguments for pipeTo/pipeToSync.
 * Returns { transforms, writer, options }
 * @returns {object}
 */
function parsePipeToArgs(args) {
  if (args.length === 0) {
    throw new ERR_INVALID_ARG_VALUE('args', args, 'pipeTo requires a writer argument');
  }

  let options;
  let writerIndex = args.length - 1;

  // Check if last arg is options
  const last = args[args.length - 1];
  if (isPullOptions(last) && !isWriter(last)) {
    options = last;
    writerIndex = args.length - 2;
  }

  if (writerIndex < 0) {
    throw new ERR_INVALID_ARG_VALUE('args', args, 'pipeTo requires a writer argument');
  }

  const writer = args[writerIndex];
  if (!isWriter(writer)) {
    throw new ERR_INVALID_ARG_TYPE('writer', 'object with a write method', writer);
  }

  const transforms = ArrayPrototypeSlice(args, 0, writerIndex);
  for (let i = 0; i < transforms.length; i++) {
    if (!isTransform(transforms[i])) {
      throw new ERR_INVALID_ARG_TYPE(
        `transforms[${i}]`, ['Function', 'Object with transform()'],
        transforms[i]);
    }
  }

  return {
    __proto__: null,
    transforms,
    writer,
    options,
  };
}

// =============================================================================
// Transform Output Flattening
// =============================================================================

/**
 * Flatten transform yield to Uint8Array chunks (sync).
 * @yields {Uint8Array}
 */
function* flattenTransformYieldSync(value) {
  if (isUint8Array(value)) {
    yield value;
    return;
  }
  if (typeof value === 'string') {
    yield toUint8Array(value);
    return;
  }
  // Must be Iterable<TransformYield>
  if (isSyncIterable(value)) {
    for (const item of value) {
      yield* flattenTransformYieldSync(item);
    }
    return;
  }
  throw new ERR_INVALID_ARG_TYPE('value', ['Uint8Array', 'string', 'Iterable'], value);
}

/**
 * Flatten transform yield to Uint8Array chunks (async).
 * @yields {Uint8Array}
 */
async function* flattenTransformYieldAsync(value) {
  if (isUint8Array(value)) {
    yield value;
    return;
  }
  if (typeof value === 'string') {
    yield toUint8Array(value);
    return;
  }
  // Check for async iterable first
  if (isAsyncIterable(value)) {
    for await (const item of value) {
      yield* flattenTransformYieldAsync(item);
    }
    return;
  }
  // Must be sync Iterable<TransformYield>
  if (isSyncIterable(value)) {
    for (const item of value) {
      yield* flattenTransformYieldAsync(item);
    }
    return;
  }
  throw new ERR_INVALID_ARG_TYPE('value', ['Uint8Array', 'string', 'Iterable', 'AsyncIterable'], value);
}

/**
 * Process transform result (sync).
 * @yields {Uint8Array[]}
 */
function* processTransformResultSync(result) {
  if (result === null) {
    return;
  }
  if (isUint8ArrayBatch(result)) {
    if (result.length > 0) {
      yield result;
    }
    return;
  }
  // Iterable or Generator
  if (isSyncIterable(result)) {
    const batch = [];
    for (const item of result) {
      for (const chunk of flattenTransformYieldSync(item)) {
        ArrayPrototypePush(batch, chunk);
      }
    }
    if (batch.length > 0) {
      yield batch;
    }
    return;
  }
  throw new ERR_INVALID_ARG_TYPE('result', ['Array', 'Iterable'], result);
}

/**
 * Process transform result (async).
 * @yields {Uint8Array[]}
 */
async function* processTransformResultAsync(result) {
  // Handle Promise
  if (isPromise(result)) {
    const resolved = await result;
    yield* processTransformResultAsync(resolved);
    return;
  }
  if (result === null) {
    return;
  }
  if (isUint8ArrayBatch(result)) {
    if (result.length > 0) {
      yield result;
    }
    return;
  }
  // Check for async iterable/generator first
  if (isAsyncIterable(result)) {
    const batch = [];
    for await (const item of result) {
      // Fast path: item is already Uint8Array
      if (isUint8Array(item)) {
        ArrayPrototypePush(batch, item);
        continue;
      }
      // Slow path: flatten the item
      for await (const chunk of flattenTransformYieldAsync(item)) {
        ArrayPrototypePush(batch, chunk);
      }
    }
    if (batch.length > 0) {
      yield batch;
    }
    return;
  }
  // Sync Iterable or Generator
  if (isSyncIterable(result)) {
    const batch = [];
    for (const item of result) {
      // Fast path: item is already Uint8Array
      if (isUint8Array(item)) {
        ArrayPrototypePush(batch, item);
        continue;
      }
      // Slow path: flatten the item
      for await (const chunk of flattenTransformYieldAsync(item)) {
        ArrayPrototypePush(batch, chunk);
      }
    }
    if (batch.length > 0) {
      yield batch;
    }
    return;
  }
  throw new ERR_INVALID_ARG_TYPE('result', ['Array', 'Iterable', 'AsyncIterable'], result);
}

// =============================================================================
// Sync Pipeline Implementation
// =============================================================================

/**
 * Apply a single stateless sync transform to a source.
 * @yields {Uint8Array[]}
 */
function* applyStatelessSyncTransform(source, transform) {
  for (const chunks of source) {
    const result = transform(chunks);
    yield* processTransformResultSync(result);
  }
  // Flush
  const flush = transform(null);
  if (flush != null) {
    yield* processTransformResultSync(flush);
  }
}

/**
 * Apply a single stateful sync transform to a source.
 * @yields {Uint8Array[]}
 */
function* withFlushSync(source) {
  yield* source;
  yield null;
}

function* applyStatefulSyncTransform(source, transform) {
  const output = transform(withFlushSync(source));
  for (const item of output) {
    const batch = [];
    for (const chunk of flattenTransformYieldSync(item)) {
      ArrayPrototypePush(batch, chunk);
    }
    if (batch.length > 0) {
      yield batch;
    }
  }
}

/**
 * Create a sync pipeline from source through transforms.
 * @yields {Uint8Array[]}
 */
function* createSyncPipeline(source, transforms) {
  let current = normalizeSyncSource(source);

  // Apply transforms. Stateless transforms handle their own flush internally.
  for (let i = 0; i < transforms.length; i++) {
    const transform = transforms[i];
    if (isTransformObject(transform)) {
      current = applyStatefulSyncTransform(current, transform.transform);
    } else {
      current = applyStatelessSyncTransform(current, transform);
    }
  }

  yield* current;
}

// =============================================================================
// Async Pipeline Implementation
// =============================================================================

/**
 * Apply a single stateless async transform to a source.
 * @yields {Uint8Array[]}
 */
async function* applyStatelessAsyncTransform(source, transform, options) {
  for await (const chunks of source) {
    const result = transform(chunks, options);
    // Fast path: result is already Uint8Array[] (common case)
    if (result === null) continue;
    if (isUint8ArrayBatch(result)) {
      if (result.length > 0) {
        yield result;
      }
      continue;
    }
    // Handle Promise of Uint8Array[]
    if (isPromise(result)) {
      const resolved = await result;
      if (resolved === null) continue;
      if (isUint8ArrayBatch(resolved)) {
        if (resolved.length > 0) {
          yield resolved;
        }
        continue;
      }
      // Fall through to slow path
      yield* processTransformResultAsync(resolved);
      continue;
    }
    // Fast path: sync generator/iterable - collect all yielded items
    if (isSyncIterable(result) && !isAsyncIterable(result)) {
      const batch = [];
      for (const item of result) {
        if (isUint8ArrayBatch(item)) {
          for (let i = 0; i < item.length; i++) {
            ArrayPrototypePush(batch, item[i]);
          }
        } else if (isUint8Array(item)) {
          ArrayPrototypePush(batch, item);
        } else if (item !== null && item !== undefined) {
          for await (const chunk of flattenTransformYieldAsync(item)) {
            ArrayPrototypePush(batch, chunk);
          }
        }
      }
      if (batch.length > 0) {
        yield batch;
      }
      continue;
    }
    // Slow path for other types
    yield* processTransformResultAsync(result);
  }
  // Flush: signal end-of-stream to the transform
  const flush = transform(null, options);
  if (flush != null) {
    yield* processTransformResultAsync(flush);
  }
}

/**
 * Apply a single stateful async transform to a source.
 * @yields {Uint8Array[]}
 */
async function* withFlushAsync(source) {
  for await (const batch of source) {
    yield batch;
  }
  yield null;
}

async function* applyStatefulAsyncTransform(source, transform, options) {
  const output = transform(withFlushAsync(source), options);
  for await (const item of output) {
    // Fast path: item is already a Uint8Array[] batch (e.g. compression transforms)
    if (isUint8ArrayBatch(item)) {
      if (item.length > 0) {
        yield item;
      }
      continue;
    }
    // Fast path: single Uint8Array
    if (isUint8Array(item)) {
      yield [item];
      continue;
    }
    // Slow path: flatten arbitrary transform yield
    const batch = [];
    for await (const chunk of flattenTransformYieldAsync(item)) {
      ArrayPrototypePush(batch, chunk);
    }
    if (batch.length > 0) {
      yield batch;
    }
  }
}

/**
 * Create an async pipeline from source through transforms.
 * @yields {Uint8Array[]}
 */
async function* createAsyncPipeline(source, transforms, signal) {
  // Check for abort
  signal?.throwIfAborted();

  // Normalize source
  let normalized;
  if (isAsyncIterable(source)) {
    normalized = normalizeAsyncSource(source);
  } else if (isSyncIterable(source)) {
    normalized = normalizeSyncSource(source);
  } else {
    throw new ERR_INVALID_ARG_TYPE('source', ['Iterable', 'AsyncIterable'], source);
  }

  // Fast path: no transforms, just yield normalized source directly
  if (transforms.length === 0) {
    for await (const batch of normalized) {
      signal?.throwIfAborted();
      yield batch;
    }
    return;
  }

  // Create internal controller for transform cancellation.
  // Note: if signal was already aborted, we threw above - no need to check here.
  const controller = new AbortController();
  let abortHandler;
  if (signal) {
    abortHandler = () => {
      controller.abort(signal.reason ??
        lazyDOMException('Aborted', 'AbortError'));
    };
    signal.addEventListener('abort', abortHandler, { __proto__: null, once: true });
  }

  // Apply transforms - each gets the controller's signal.
  // Stateless transforms handle their own flush (null) signal internally.
  let current = normalized;
  for (let i = 0; i < transforms.length; i++) {
    const transform = transforms[i];
    const options = { __proto__: null, signal: controller.signal };
    if (isTransformObject(transform)) {
      current = applyStatefulAsyncTransform(current, transform.transform,
                                            options);
    } else {
      current = applyStatelessAsyncTransform(current, transform, options);
    }
  }

  let completed = false;
  try {
    for await (const batch of current) {
      controller.signal.throwIfAborted();
      yield batch;
    }
    completed = true;
  } catch (error) {
    if (!controller.signal.aborted) {
      controller.abort(
        isError(error) ? error :
          new ERR_OPERATION_FAILED(String(error)));
    }
    throw error;
  } finally {
    if (!completed && !controller.signal.aborted) {
      // Consumer stopped early or generator return() was called.
      // If a transform listener throws here, let it propagate.
      controller.abort(lazyDOMException('Aborted', 'AbortError'));
    }
    // Clean up user signal listener to prevent holding controller alive
    if (signal && abortHandler) {
      signal.removeEventListener('abort', abortHandler);
    }
  }
}

// =============================================================================
// Public API: pull() and pullSync()
// =============================================================================

/**
 * Create a sync pull-through pipeline with transforms.
 * @param {Iterable} source - The sync streamable source
 * @param {...Function} transforms - Variadic transforms
 * @returns {Iterable<Uint8Array[]>}
 */
function pullSync(source, ...transforms) {
  for (let i = 0; i < transforms.length; i++) {
    if (!isTransform(transforms[i])) {
      throw new ERR_INVALID_ARG_TYPE(
        `transforms[${i}]`, ['Function', 'Object with transform()'],
        transforms[i]);
    }
  }
  return {
    __proto__: null,
    *[SymbolIterator]() {
      yield* createSyncPipeline(source, transforms);
    },
  };
}

/**
 * Create an async pull-through pipeline with transforms.
 * @param {Iterable|AsyncIterable} source - The streamable source
 * @param {...(Function|object)} args - Transforms, with optional PullOptions
 *   as last argument
 * @returns {AsyncIterable<Uint8Array[]>}
 */
function pull(source, ...args) {
  const { transforms, options } = parsePullArgs(args);
  if (options?.signal !== undefined) {
    validateAbortSignal(options.signal, 'options.signal');
  }

  return {
    __proto__: null,
    async *[SymbolAsyncIterator]() {
      yield* createAsyncPipeline(source, transforms, options?.signal);
    },
  };
}

// =============================================================================
// Public API: pipeTo() and pipeToSync()
// =============================================================================

/**
 * Write a sync source through transforms to a sync writer.
 * @param {Iterable<Uint8Array[]>} source
 * @param {...(Function|object)} args - Transforms, writer, and optional options
 * @returns {number} Total bytes written
 */
function pipeToSync(source, ...args) {
  const { transforms, writer, options } = parsePipeToArgs(args);

  // Handle transform-writer
  if (isTransformObject(writer)) {
    ArrayPrototypePush(transforms, writer);
  }

  // Create pipeline
  const pipeline = transforms.length > 0 ?
    createSyncPipeline(
      { [SymbolIterator]: () => source[SymbolIterator]() },
      transforms) :
    source;

  let totalBytes = 0;
  const hasWriteSync = typeof writer.writeSync === 'function';
  const hasWritevSync = typeof writer.writevSync === 'function';
  const hasEndSync = typeof writer.endSync === 'function';
  const hasFailSync = typeof writer.failSync === 'function';

  try {
    for (const batch of pipeline) {
      if (hasWritevSync && batch.length > 1) {
        writer.writevSync(batch);
        for (let i = 0; i < batch.length; i++) {
          totalBytes += TypedArrayPrototypeGetByteLength(batch[i]);
        }
      } else {
        for (let i = 0; i < batch.length; i++) {
          const chunk = batch[i];
          if (hasWriteSync) {
            writer.writeSync(chunk);
          } else {
            writer.write(chunk);
          }
          totalBytes += TypedArrayPrototypeGetByteLength(chunk);
        }
      }
    }

    if (!options?.preventClose) {
      if (!hasEndSync || writer.endSync() < 0) {
        writer.end?.();
      }
    }
  } catch (error) {
    if (!options?.preventFail) {
      const err = isError(error) ? error :
        new ERR_OPERATION_FAILED(String(error));
      if (!hasFailSync || !writer.failSync(err)) {
        writer.fail?.(err);
      }
    }
    throw error;
  }

  return totalBytes;
}

/**
 * Write an async source through transforms to a writer.
 * @param {AsyncIterable<Uint8Array[]>|Iterable<Uint8Array[]>} source
 * @param {...(Function|object)} args - Transforms, writer, and optional options
 * @returns {Promise<number>} Total bytes written
 */
async function pipeTo(source, ...args) {
  const { transforms, writer, options } = parsePipeToArgs(args);
  if (options?.signal !== undefined) {
    validateAbortSignal(options.signal, 'options.signal');
  }

  // Handle transform-writer
  if (isTransformObject(writer)) {
    ArrayPrototypePush(transforms, writer);
  }

  const signal = options?.signal;

  // Check for abort
  signal?.throwIfAborted();

  let totalBytes = 0;
  const hasWritev = typeof writer.writev === 'function';
  const hasWriteSync = typeof writer.writeSync === 'function';
  const hasWritevSync = typeof writer.writevSync === 'function';
  const hasEndSync = typeof writer.endSync === 'function';
  const hasFailSync = typeof writer.failSync === 'function';
  // Write a batch using try-fallback: sync first, async if needed.
  async function writeBatch(batch) {
    if (hasWritev && batch.length > 1) {
      if (!hasWritevSync || !writer.writevSync(batch)) {
        await writer.writev(batch, signal ? { __proto__: null, signal } :
          undefined);
      }
      for (let i = 0; i < batch.length; i++) {
        totalBytes += TypedArrayPrototypeGetByteLength(batch[i]);
      }
    } else {
      for (let i = 0; i < batch.length; i++) {
        const chunk = batch[i];
        if (!hasWriteSync || !writer.writeSync(chunk)) {
          const result = writer.write(
            chunk, signal ? { __proto__: null, signal } : undefined);
          if (result !== undefined) {
            await result;
          }
        }
        totalBytes += TypedArrayPrototypeGetByteLength(chunk);
      }
    }
  }

  try {
    // Fast path: no transforms - iterate directly
    if (transforms.length === 0) {
      if (isAsyncIterable(source)) {
        if (signal) {
          for await (const batch of source) {
            signal.throwIfAborted();
            await writeBatch(batch);
          }
        } else {
          for await (const batch of source) {
            await writeBatch(batch);
          }
        }
      } else if (signal) {
        for (const batch of source) {
          signal.throwIfAborted();
          await writeBatch(batch);
        }
      } else {
        for (const batch of source) {
          await writeBatch(batch);
        }
      }
    } else {
      const pipeline = createAsyncPipeline(source, transforms, signal);

      if (signal) {
        for await (const batch of pipeline) {
          signal.throwIfAborted();
          await writeBatch(batch);
        }
      } else {
        for await (const batch of pipeline) {
          await writeBatch(batch);
        }
      }
    }

    if (!options?.preventClose) {
      if (!hasEndSync || writer.endSync() < 0) {
        await writer.end?.(signal ? { __proto__: null, signal } : undefined);
      }
    }
  } catch (error) {
    if (!options?.preventFail) {
      const err = isError(error) ? error :
        new ERR_OPERATION_FAILED(String(error));
      if (!hasFailSync || !writer.failSync(err)) {
        await writer.fail?.(err);
      }
    }
    throw error;
  }

  return totalBytes;
}

module.exports = {
  pull,
  pullSync,
  pipeTo,
  pipeToSync,
};
