// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { pull, from, text, tap } = require('stream/iter');

async function testPullIdentity() {
  const data = await text(pull(from('hello-async')));
  assert.strictEqual(data, 'hello-async');
}

async function testPullStatelessTransform() {
  const upper = (chunks) => {
    if (chunks === null) return null;
    return chunks.map((c) => {
      const str = new TextDecoder().decode(c);
      return new TextEncoder().encode(str.toUpperCase());
    });
  };
  const data = await text(pull(from('abc'), upper));
  assert.strictEqual(data, 'ABC');
}

async function testPullStatefulTransform() {
  const stateful = {
    transform: async function*(source) {
      for await (const chunks of source) {
        if (chunks === null) {
          yield new TextEncoder().encode('-ASYNC-END');
          continue;
        }
        for (const chunk of chunks) {
          yield chunk;
        }
      }
    },
  };
  const data = await text(pull(from('data'), stateful));
  assert.strictEqual(data, 'data-ASYNC-END');
}

async function testPullWithAbortSignal() {
  const ac = new AbortController();
  ac.abort();

  async function* gen() {
    yield [new Uint8Array([1])];
  }

  const result = pull(gen(), { signal: ac.signal });
  await assert.rejects(
    async () => {
      // eslint-disable-next-line no-unused-vars
      for await (const _ of result) {
        assert.fail('Should not reach here');
      }
    },
    { name: 'AbortError' },
  );
}

async function testPullChainedTransforms() {
  const enc = new TextEncoder();
  const transforms = [
    (chunks) => {
      if (chunks === null) return null;
      return [...chunks, enc.encode('!')];
    },
    (chunks) => {
      if (chunks === null) return null;
      return [...chunks, enc.encode('?')];
    },
  ];
  const data = await text(pull(from('hello'), ...transforms));
  assert.strictEqual(data, 'hello!?');
}

// Source error → controller.abort() → transform listener throws →
// source error propagates to consumer; listener error becomes uncaught
// exception (per EventTarget spec behavior).
async function testTransformSignalListenerErrorOnSourceError() {
  // Listener errors from dispatchEvent are rethrown via process.nextTick,
  // so we must catch them as uncaught exceptions.
  const uncaughtErrors = [];
  const handler = (err) => uncaughtErrors.push(err);
  process.on('uncaughtException', handler);

  const throwingTransform = {
    transform(source, options) {
      options.signal.addEventListener('abort', () => {
        throw new Error('listener boom');
      });
      return source;
    },
  };

  async function* failingSource() {
    yield [new TextEncoder().encode('a')];
    throw new Error('source error');
  }

  await assert.rejects(
    async () => {
      // eslint-disable-next-line no-unused-vars
      for await (const _ of pull(failingSource(), throwingTransform)) {
        // Consume
      }
    },
    { message: 'source error' },
  );

  // Give the nextTick rethrow a chance to fire
  await new Promise(setImmediate);
  process.removeListener('uncaughtException', handler);

  assert.strictEqual(uncaughtErrors.length, 1);
  assert.strictEqual(uncaughtErrors[0].message, 'listener boom');
}

// Pull source error propagates to consumer
async function testPullSourceError() {
  async function* failingSource() {
    yield [new TextEncoder().encode('a')];
    throw new Error('source boom');
  }
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of pull(failingSource())) { /* consume */ }
  }, { message: 'source boom' });
}

// Tap callback error propagates through pipeline
async function testTapCallbackError() {
  const badTap = tap(() => { throw new Error('tap boom'); });
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of pull(from('hello'), badTap)) { /* consume */ }
  }, { message: 'tap boom' });
}

// Pull signal aborted mid-iteration (not pre-aborted)
async function testPullSignalAbortMidIteration() {
  const ac = new AbortController();
  const enc = new TextEncoder();
  async function* slowSource() {
    yield [enc.encode('a')];
    yield [enc.encode('b')];
    yield [enc.encode('c')];
  }
  const result = pull(slowSource(), { signal: ac.signal });
  const iter = result[Symbol.asyncIterator]();
  const first = await iter.next(); // Read first batch
  assert.strictEqual(first.done, false);
  ac.abort();
  await assert.rejects(() => iter.next(), { name: 'AbortError' });
}

// Pull consumer break (return()) cleans up transform signal
async function testPullConsumerBreakCleanup() {
  let signalAborted = false;
  const trackingTransform = {
    transform(source, options) {
      options.signal.addEventListener('abort', () => {
        signalAborted = true;
      });
      return source;
    },
  };
  async function* infiniteSource() {
    let i = 0;
    while (true) {
      yield [new TextEncoder().encode(`chunk${i++}`)];
    }
  }
  // Consumer breaks after first chunk
  // eslint-disable-next-line no-unused-vars
  for await (const _ of pull(infiniteSource(), trackingTransform)) {
    break;
  }
  // Give the abort handler a tick to fire
  await new Promise(setImmediate);
  assert.strictEqual(signalAborted, true);
}

// Pull transform returning a Promise
async function testPullTransformReturnsPromise() {
  const asyncTransform = async (chunks) => {
    if (chunks === null) return null;
    return chunks;
  };
  const result = await text(pull(from('hello'), asyncTransform));
  assert.strictEqual(result, 'hello');
}

// Stateless transform error propagates
async function testPullStatelessTransformError() {
  const badTransform = (chunks) => {
    if (chunks === null) return null;
    throw new Error('async stateless boom');
  };
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of pull(from('hello'), badTransform)) { /* consume */ }
  }, { message: 'async stateless boom' });
}

// Stateful transform error propagates
async function testPullStatefulTransformError() {
  const badStateful = {
    transform: async function*(source) { // eslint-disable-line require-yield
      for await (const chunks of source) {
        if (chunks === null) continue;
        throw new Error('async stateful boom');
      }
    },
  };
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of pull(from('hello'), badStateful)) { /* consume */ }
  }, { message: 'async stateful boom' });
}

// Stateless transform flush emitting data
async function testPullStatelessTransformFlush() {
  const withTrailer = (chunks) => {
    if (chunks === null) {
      return [new TextEncoder().encode('-TRAILER')];
    }
    return chunks;
  };
  const data = await text(pull(from('data'), withTrailer));
  assert.strictEqual(data, 'data-TRAILER');
}

// Stateless transform flush error propagates
async function testPullStatelessTransformFlushError() {
  const badFlush = (chunks) => {
    if (chunks === null) {
      throw new Error('async flush boom');
    }
    return chunks;
  };
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of pull(from('hello'), badFlush)) { /* consume */ }
  }, { message: 'async flush boom' });
}

// Pull with a sync iterable source (not async)
async function testPullWithSyncSource() {
  function* gen() {
    yield new TextEncoder().encode('sync-source');
  }
  const data = await text(pull(gen()));
  assert.strictEqual(data, 'sync-source');
}

// Pull transform yielding strings
async function testPullTransformYieldsStrings() {
  const stringTransform = (chunks) => {
    if (chunks === null) return null;
    return chunks.map((c) => new TextDecoder().decode(c));
  };
  const result = await text(pull(from('hello'), stringTransform));
  assert.strictEqual(result, 'hello');
}

// Run the uncaughtException test sequentially (it installs a global handler
// that would interfere with concurrent tests).
(async () => {
  await Promise.all([
    testPullIdentity(),
    testPullStatelessTransform(),
    testPullStatefulTransform(),
    testPullWithAbortSignal(),
    testPullChainedTransforms(),
    testPullSourceError(),
    testTapCallbackError(),
    testPullSignalAbortMidIteration(),
    testPullConsumerBreakCleanup(),
    testPullTransformReturnsPromise(),
    testPullTransformYieldsStrings(),
    testPullStatelessTransformError(),
    testPullStatefulTransformError(),
    testPullStatelessTransformFlush(),
    testPullStatelessTransformFlushError(),
    testPullWithSyncSource(),
  ]);
  // Run after all concurrent tests complete to avoid global handler races
  await testTransformSignalListenerErrorOnSourceError();
})().then(common.mustCall());
