// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { push, text } = require('stream/iter');

async function testStrictBackpressure() {
  const { writer, readable } = push({
    highWaterMark: 1,
    backpressure: 'strict',
  });

  // First write should succeed synchronously
  assert.strictEqual(writer.writeSync('a'), true);
  // Second write should fail synchronously (buffer full)
  assert.strictEqual(writer.writeSync('b'), false);

  // Consume to free space, then end
  const resultPromise = text(readable);
  writer.end();
  const data = await resultPromise;
  assert.strictEqual(data, 'a');
}

async function testDropOldest() {
  const { writer, readable } = push({
    highWaterMark: 2,
    backpressure: 'drop-oldest',
  });

  assert.strictEqual(writer.writeSync('first'), true);
  assert.strictEqual(writer.writeSync('second'), true);
  // This should drop 'first' — return value is true (write accepted via drop)
  assert.strictEqual(writer.writeSync('third'), true);
  writer.end();

  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  // Should have 'second' and 'third'
  const allBytes = [];
  for (const batch of batches) {
    for (const chunk of batch) {
      allBytes.push(...chunk);
    }
  }
  const result = new TextDecoder().decode(new Uint8Array(allBytes));
  assert.strictEqual(result, 'secondthird');
}

async function testDropNewest() {
  const { writer, readable } = push({
    highWaterMark: 1,
    backpressure: 'drop-newest',
  });

  assert.strictEqual(writer.writeSync('kept'), true);
  // This is silently dropped — return value is true (accepted but discarded)
  assert.strictEqual(writer.writeSync('dropped'), true);
  writer.end();

  const data = await text(readable);
  assert.strictEqual(data, 'kept');
}

async function testBlockBackpressure() {
  const { writer, readable } = push({ highWaterMark: 1, backpressure: 'block' });

  // Fill the buffer
  writer.writeSync('a');

  // Next write should block (not throw, not drop)
  let writeState = 'pending';
  const writePromise = writer.write('b').then(() => { writeState = 'resolved'; });

  // The write cannot resolve until the buffer is drained, so a microtask
  // tick is sufficient to confirm it is still blocked.
  await new Promise(setImmediate);
  assert.strictEqual(writeState, 'pending'); // Still blocked

  // Read from the consumer to drain
  const iter = readable[Symbol.asyncIterator]();
  const first = await iter.next(); // Drains 'a'
  assert.strictEqual(first.done, false);

  // After draining, the pending write resolves as a microtask
  await new Promise(setImmediate);
  assert.strictEqual(writeState, 'resolved'); // Now unblocked

  writer.endSync();
  const second = await iter.next(); // Read 'b'
  assert.strictEqual(second.done, false);
  await writePromise;
}

Promise.all([
  testStrictBackpressure(),
  testDropOldest(),
  testDropNewest(),
  testBlockBackpressure(),
]).then(common.mustCall());
