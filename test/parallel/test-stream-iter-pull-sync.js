// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { pullSync, fromSync, bytesSync, tapSync } = require('stream/iter');

async function testPullSyncIdentity() {
  // No transforms - just pass through
  const source = fromSync('hello');
  const result = pullSync(source);
  const data = bytesSync(result);
  assert.deepStrictEqual(data, new TextEncoder().encode('hello'));
}

async function testPullSyncStatelessTransform() {
  const source = fromSync('abc');
  const upper = (chunks) => {
    if (chunks === null) return null;
    return chunks.map((c) => {
      const str = new TextDecoder().decode(c);
      return new TextEncoder().encode(str.toUpperCase());
    });
  };
  const result = pullSync(source, upper);
  const data = bytesSync(result);
  assert.deepStrictEqual(data, new TextEncoder().encode('ABC'));
}

async function testPullSyncStatefulTransform() {
  const source = fromSync('data');
  const stateful = {
    transform: function*(source) {
      for (const chunks of source) {
        if (chunks === null) {
          // Flush: emit trailer
          yield new TextEncoder().encode('-END');
          continue;
        }
        for (const chunk of chunks) {
          yield chunk;
        }
      }
    },
  };
  const result = pullSync(source, stateful);
  const data = new TextDecoder().decode(bytesSync(result));
  assert.strictEqual(data, 'data-END');
}

async function testPullSyncChainedTransforms() {
  const source = fromSync('hello');
  const addExcl = (chunks) => {
    if (chunks === null) return null;
    return [...chunks, new TextEncoder().encode('!')];
  };
  const addQ = (chunks) => {
    if (chunks === null) return null;
    return [...chunks, new TextEncoder().encode('?')];
  };
  const result = pullSync(source, addExcl, addQ);
  const data = new TextDecoder().decode(bytesSync(result));
  assert.strictEqual(data, 'hello!?');
}

// PullSync source error propagates
async function testPullSyncSourceError() {
  function* failingSource() {
    yield [new TextEncoder().encode('a')];
    throw new Error('sync source boom');
  }
  assert.throws(() => {
    // eslint-disable-next-line no-unused-vars
    for (const _ of pullSync(failingSource())) { /* consume */ }
  }, { message: 'sync source boom' });
}

// PullSync with empty source
async function testPullSyncEmptySource() {
  function* empty() {}
  const result = bytesSync(pullSync(empty()));
  assert.strictEqual(result.length, 0);
}

// TapSync callback error propagates
async function testTapSyncCallbackError() {
  const badTap = tapSync(() => { throw new Error('tapSync boom'); });
  assert.throws(() => {
    // eslint-disable-next-line no-unused-vars
    for (const _ of pullSync(fromSync('hello'), badTap)) { /* consume */ }
  }, { message: 'tapSync boom' });
}

Promise.all([
  testPullSyncIdentity(),
  testPullSyncStatelessTransform(),
  testPullSyncStatefulTransform(),
  testPullSyncChainedTransforms(),
  testPullSyncSourceError(),
  testPullSyncEmptySource(),
  testTapSyncCallbackError(),
]).then(common.mustCall());
