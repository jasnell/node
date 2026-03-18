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

  writer.writeSync('first');
  writer.writeSync('second');
  // This should drop 'first'
  writer.writeSync('third');
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

  writer.writeSync('kept');
  // This is silently dropped
  writer.writeSync('dropped');
  writer.end();

  const data = await text(readable);
  assert.strictEqual(data, 'kept');
}

async function testBlockBackpressure() {
  const { writer, readable } = push({ highWaterMark: 1, backpressure: 'block' });

  // Fill the buffer
  writer.writeSync('a');

  // Next write should block (not throw, not drop)
  let writeResolved = false;
  const writePromise = writer.write('b').then(() => { writeResolved = true; });

  // Give a tick for anything to resolve
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(writeResolved, false); // Still blocked

  // Read from the consumer to drain
  const iter = readable[Symbol.asyncIterator]();
  await iter.next(); // Drains 'a'
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(writeResolved, true); // Now unblocked

  writer.endSync();
  await iter.next(); // Read 'b'
  await writePromise;
}

Promise.all([
  testStrictBackpressure(),
  testDropOldest(),
  testDropNewest(),
  testBlockBackpressure(),
]).then(common.mustCall());
