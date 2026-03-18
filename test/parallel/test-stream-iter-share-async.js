// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  from,
  share,
  text,

} = require('stream/iter');

// =============================================================================
// Async share()
// =============================================================================

async function testBasicShare() {
  const source = from('hello shared');
  const shared = share(source);

  const consumer = shared.pull();
  const data = await text(consumer);
  assert.strictEqual(data, 'hello shared');
}

async function testShareMultipleConsumers() {
  async function* gen() {
    yield [new TextEncoder().encode('chunk1')];
    yield [new TextEncoder().encode('chunk2')];
    yield [new TextEncoder().encode('chunk3')];
  }

  const shared = share(gen(), { highWaterMark: 16 });

  const c1 = shared.pull();
  const c2 = shared.pull();

  assert.strictEqual(shared.consumerCount, 2);

  const [data1, data2] = await Promise.all([
    text(c1),
    text(c2),
  ]);

  assert.strictEqual(data1, 'chunk1chunk2chunk3');
  assert.strictEqual(data2, 'chunk1chunk2chunk3');
}

async function testShareConsumerCount() {
  const source = from('data');
  const shared = share(source);

  assert.strictEqual(shared.consumerCount, 0);

  const c1 = shared.pull();
  assert.strictEqual(shared.consumerCount, 1);

  const c2 = shared.pull();
  assert.strictEqual(shared.consumerCount, 2);

  // Cancel detaches all consumers
  shared.cancel();

  // Both should complete immediately
  const [data1, data2] = await Promise.all([
    text(c1),
    text(c2),
  ]);
  assert.strictEqual(data1, '');
  assert.strictEqual(data2, '');
}

async function testShareCancel() {
  const source = from('data');
  const shared = share(source);
  const consumer = shared.pull();

  shared.cancel();

  const batches = [];
  for await (const batch of consumer) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 0);
}

async function testShareCancelWithReason() {
  const source = from('data');
  const shared = share(source);
  const consumer = shared.pull();

  shared.cancel(new Error('share cancelled'));

  await assert.rejects(
    async () => {
      // eslint-disable-next-line no-unused-vars
      for await (const _ of consumer) {
        assert.fail('Should not reach here');
      }
    },
    { message: 'share cancelled' },
  );
}

async function testShareAbortSignal() {
  const ac = new AbortController();
  const source = from('data');
  const shared = share(source, { signal: ac.signal });
  const consumer = shared.pull();

  ac.abort();

  const batches = [];
  for await (const batch of consumer) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 0);
}

async function testShareAlreadyAborted() {
  const ac = new AbortController();
  ac.abort();

  const source = from('data');
  const shared = share(source, { signal: ac.signal });
  const consumer = shared.pull();

  const batches = [];
  for await (const batch of consumer) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 0);
}

// =============================================================================
// Source error propagation
// =============================================================================

async function testShareSourceError() {
  async function* failingSource() {
    yield [new TextEncoder().encode('a')];
    throw new Error('share source boom');
  }
  const shared = share(failingSource());
  const c1 = shared.pull();
  const c2 = shared.pull();

  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of c1) { /* consume */ }
  }, { message: 'share source boom' });
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of c2) { /* consume */ }
  }, { message: 'share source boom' });
}

async function testShareMultipleConsumersConcurrentPull() {
  // Regression test: multiple consumers pulling concurrently should each
  // receive all items even when only one item is pulled from source at a time.
  // Previously, consumers woken after a pull that found no data at their
  // cursor would return done:true prematurely (thundering herd bug).
  async function* slowSource() {
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r, 1));
      yield [new TextEncoder().encode(`item-${i}`)];
    }
  }
  const shared = share(slowSource());
  const c1 = shared.pull();
  const c2 = shared.pull();
  const c3 = shared.pull();

  const [t1, t2, t3] = await Promise.all([
    text(c1), text(c2), text(c3),
  ]);

  const expected = 'item-0item-1item-2item-3item-4';
  assert.strictEqual(t1, expected);
  assert.strictEqual(t2, expected);
  assert.strictEqual(t3, expected);
}

Promise.all([
  testBasicShare(),
  testShareMultipleConsumers(),
  testShareConsumerCount(),
  testShareCancel(),
  testShareCancelWithReason(),
  testShareAbortSignal(),
  testShareAlreadyAborted(),
  testShareSourceError(),
  testShareMultipleConsumersConcurrentPull(),
]).then(common.mustCall());
