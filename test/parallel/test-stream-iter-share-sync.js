// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  shareSync,
  fromSync,
  textSync,

} = require('stream/iter');

// =============================================================================
// Sync share
// =============================================================================

async function testShareSyncBasic() {
  const source = fromSync('sync shared');
  const shared = shareSync(source);

  const consumer = shared.pull();
  const data = textSync(consumer);
  assert.strictEqual(data, 'sync shared');
}

async function testShareSyncMultipleConsumers() {
  function* gen() {
    yield [new TextEncoder().encode('a')];
    yield [new TextEncoder().encode('b')];
    yield [new TextEncoder().encode('c')];
  }

  const shared = shareSync(gen(), { highWaterMark: 16 });

  const c1 = shared.pull();
  const c2 = shared.pull();

  const data1 = textSync(c1);
  const data2 = textSync(c2);

  assert.strictEqual(data1, 'abc');
  assert.strictEqual(data2, 'abc');
}

async function testShareSyncCancel() {
  const source = fromSync('data');
  const shared = shareSync(source);
  const consumer = shared.pull();

  shared.cancel();

  const batches = [];
  for (const batch of consumer) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 0);
}

// =============================================================================
// Source error propagation
// =============================================================================

async function testShareSyncSourceError() {
  function* failingSource() {
    yield [new TextEncoder().encode('ok')];
    throw new Error('sync share boom');
  }
  const shared = shareSync(failingSource());
  const consumer = shared.pull();
  assert.throws(() => {
    // eslint-disable-next-line no-unused-vars
    for (const _ of consumer) { /* consume */ }
  }, { message: 'sync share boom' });
}

Promise.all([
  testShareSyncBasic(),
  testShareSyncMultipleConsumers(),
  testShareSyncCancel(),
  testShareSyncSourceError(),
]).then(common.mustCall());
