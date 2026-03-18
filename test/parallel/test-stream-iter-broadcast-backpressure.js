// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { broadcast, text } = require('stream/iter');

// =============================================================================
// Backpressure policies
// =============================================================================

async function testDropOldest() {
  const { writer, broadcast: bc } = broadcast({
    highWaterMark: 2,
    backpressure: 'drop-oldest',
  });
  const consumer = bc.push();

  writer.writeSync('first');
  writer.writeSync('second');
  // This should drop 'first'
  writer.writeSync('third');
  writer.endSync();

  const data = await text(consumer);
  assert.strictEqual(data, 'secondthird');
}

async function testDropNewest() {
  const { writer, broadcast: bc } = broadcast({
    highWaterMark: 1,
    backpressure: 'drop-newest',
  });
  const consumer = bc.push();

  writer.writeSync('kept');
  // This should be silently dropped
  writer.writeSync('dropped');
  writer.endSync();

  const data = await text(consumer);
  assert.strictEqual(data, 'kept');
}

// =============================================================================
// Block backpressure
// =============================================================================

async function testBlockBackpressure() {
  const { writer, broadcast: bc } = broadcast({
    highWaterMark: 1,
    backpressure: 'block',
  });
  const consumer = bc.push();
  writer.writeSync('a');

  // Next write should block
  let writeResolved = false;
  const writePromise = writer.write('b').then(() => { writeResolved = true; });
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(writeResolved, false);

  // Drain consumer
  const iter = consumer[Symbol.asyncIterator]();
  await iter.next();
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(writeResolved, true);
  writer.endSync();
  await writePromise;
}

Promise.all([
  testDropOldest(),
  testDropNewest(),
  testBlockBackpressure(),
]).then(common.mustCall());
