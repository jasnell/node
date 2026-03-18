// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { pull, from, text, tap } = require('stream/iter');

async function testPullIdentity() {
  const source = from('hello-async');
  const result = pull(source);
  const data = await text(result);
  assert.strictEqual(data, 'hello-async');
}

async function testPullStatelessTransform() {
  const source = from('abc');
  const upper = (chunks) => {
    if (chunks === null) return null;
    return chunks.map((c) => {
      const str = new TextDecoder().decode(c);
      return new TextEncoder().encode(str.toUpperCase());
    });
  };
  const result = pull(source, upper);
  const data = await text(result);
  assert.strictEqual(data, 'ABC');
}

async function testPullStatefulTransform() {
  const source = from('data');
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
  const result = pull(source, stateful);
  const data = await text(result);
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
    (err) => err.name === 'AbortError',
  );
}

async function testPullChainedTransforms() {
  const source = from('hello');
  const transforms = [
    (chunks) => {
      if (chunks === null) return null;
      return [...chunks, new TextEncoder().encode('!')];
    },
    (chunks) => {
      if (chunks === null) return null;
      return [...chunks, new TextEncoder().encode('?')];
    },
  ];
  const result = pull(source, ...transforms);
  const data = await text(result);
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

  // Give the nextTick a chance to fire
  await new Promise((r) => setTimeout(r, 10));
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
  async function* slowSource() {
    yield [new TextEncoder().encode('a')];
    yield [new TextEncoder().encode('b')];
    yield [new TextEncoder().encode('c')];
  }
  const result = pull(slowSource(), { signal: ac.signal });
  const iter = result[Symbol.asyncIterator]();
  await iter.next(); // Read first batch
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
  await new Promise((r) => setTimeout(r, 10));
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

// Pull transform yielding strings
async function testPullTransformYieldsStrings() {
  const stringTransform = (chunks) => {
    if (chunks === null) return null;
    return chunks.map((c) => new TextDecoder().decode(c));
  };
  const result = await text(pull(from('hello'), stringTransform));
  assert.strictEqual(result, 'hello');
}

Promise.all([
  testPullIdentity(),
  testPullStatelessTransform(),
  testPullStatefulTransform(),
  testPullWithAbortSignal(),
  testPullChainedTransforms(),
  testTransformSignalListenerErrorOnSourceError(),
  testPullSourceError(),
  testTapCallbackError(),
  testPullSignalAbortMidIteration(),
  testPullConsumerBreakCleanup(),
  testPullTransformReturnsPromise(),
  testPullTransformYieldsStrings(),
]).then(common.mustCall());
