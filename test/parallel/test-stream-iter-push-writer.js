// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { push, ondrain, text } = require('stream/iter');

async function testOndrain() {
  const { writer } = push({ highWaterMark: 1 });

  // With space available, ondrain resolves immediately
  const drainResult = ondrain(writer);
  assert.ok(drainResult instanceof Promise);
  const result = await drainResult;
  assert.strictEqual(result, true);

  // After close, ondrain returns null
  writer.end();
  assert.strictEqual(ondrain(writer), null);
}

async function testOndainNonDrainable() {
  // Non-drainable objects return null
  assert.strictEqual(ondrain(null), null);
  assert.strictEqual(ondrain({}), null);
  assert.strictEqual(ondrain('string'), null);
}

async function testWriteWithSignalRejects() {
  const { writer, readable } = push({ highWaterMark: 1 });

  // Fill the buffer so write will block
  writer.writeSync('a');

  const ac = new AbortController();
  const writePromise = writer.write('b', { signal: ac.signal });

  // Signal fires while write is pending
  ac.abort();

  await assert.rejects(writePromise, (err) => err.name === 'AbortError');

  // Clean up
  writer.end();
  // eslint-disable-next-line no-unused-vars
  for await (const _ of readable) { break; }
}

async function testWriteWithPreAbortedSignal() {
  const { writer, readable } = push({ highWaterMark: 1 });

  const ac = new AbortController();
  ac.abort();

  // Pre-aborted signal should reject immediately
  await assert.rejects(
    writer.write('data', { signal: ac.signal }),
    (err) => err.name === 'AbortError',
  );

  // Writer should still be usable for other writes
  writer.write('ok');
  writer.end();
  const data = await text(readable);
  assert.strictEqual(data, 'ok');
}

async function testCancelledWriteRemovedFromQueue() {
  const { writer, readable } = push({ highWaterMark: 1 });

  // Fill the buffer
  writer.writeSync('first');

  const ac = new AbortController();
  // This write should be queued since buffer is full
  const cancelledWrite = writer.write('cancelled', { signal: ac.signal });

  // Cancel it
  ac.abort();
  await cancelledWrite.catch(() => {});

  // Drain 'first' to make room for the replacement write
  const iter = readable[Symbol.asyncIterator]();
  await iter.next();

  // The cancelled write should NOT occupy a pending slot.
  // A new write should succeed now that the buffer has room.
  await writer.write('second');
  writer.end();

  const result = await iter.next();
  // 'second' should be the next (and only remaining) chunk
  const decoder = new TextDecoder();
  let data = '';
  for (const chunk of result.value) {
    data += decoder.decode(chunk, { stream: true });
  }
  assert.strictEqual(data, 'second');
  await iter.return();
}

async function testOndrainResolvesFalseOnConsumerBreak() {
  const { writer, readable } = push({ highWaterMark: 1 });

  // Fill the buffer so desiredSize = 0
  writer.writeSync('a');

  // Also queue a pending write so that reading one chunk
  // doesn't clear backpressure (the pending write refills the slot)
  const pendingWrite = writer.write('b');

  // Start a drain wait - still at capacity
  const drainPromise = ondrain(writer);

  // Consumer returns without draining enough to clear backpressure
  const iter = readable[Symbol.asyncIterator]();
  await iter.return();

  // Ondrain should resolve false since the consumer terminated
  const result = await drainPromise;
  assert.strictEqual(result, false);
  await pendingWrite.catch(() => {}); // Ignore write rejection
}

async function testOndrainRejectsOnConsumerThrow() {
  const { writer, readable } = push({ highWaterMark: 1 });

  // Fill the buffer so desiredSize = 0
  writer.writeSync('a');

  // Also queue a pending write so that reading one chunk
  // doesn't clear backpressure (the pending write refills the slot)
  const pendingWrite = writer.write('b');

  // Start a drain wait - still at capacity
  const drainPromise = ondrain(writer);

  // Consumer throws via iterator.throw() before draining enough
  // to clear backpressure. The drain should reject.
  const iter = readable[Symbol.asyncIterator]();
  await iter.throw(new Error('consumer error'));

  await assert.rejects(drainPromise, /consumer error/);
  await pendingWrite.catch(() => {}); // Ignore write rejection
}

async function testWritev() {
  const { writer, readable } = push({ highWaterMark: 10 });
  const enc = new TextEncoder();
  writer.writev([enc.encode('hel'), enc.encode('lo')]);
  writer.endSync();
  const result = await text(readable);
  assert.strictEqual(result, 'hello');
}

async function testWritevSync() {
  const { writer, readable } = push({ highWaterMark: 10 });
  const enc = new TextEncoder();
  assert.strictEqual(writer.writevSync([enc.encode('hel'), enc.encode('lo')]), true);
  writer.endSync();
  const result = await text(readable);
  assert.strictEqual(result, 'hello');
}

async function testWritevMixedTypes() {
  const { writer, readable } = push({ highWaterMark: 10 });
  // Mix strings and Uint8Arrays
  writer.writev(['hel', new TextEncoder().encode('lo')]);
  writer.endSync();
  const result = await text(readable);
  assert.strictEqual(result, 'hello');
}

async function testWriteAfterEnd() {
  const { writer } = push();
  writer.endSync();
  assert.strictEqual(writer.writeSync('fail'), false);
}

async function testWriteAfterFail() {
  const { writer } = push();
  writer.failSync(new Error('failed'));
  assert.strictEqual(writer.writeSync('fail'), false);
}

async function testFailSync() {
  const { writer, readable } = push();
  writer.writeSync('hello');
  assert.strictEqual(writer.failSync(new Error('boom')), true);
  // Second failSync returns false
  assert.strictEqual(writer.failSync(new Error('boom2')), false);
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of readable) { /* consume */ }
  }, { message: 'boom' });
}

async function testEndAsyncReturnValue() {
  const { writer } = push();
  writer.writeSync('hello');
  const total = await writer.end();
  assert.strictEqual(total, 5);
}

async function testWriteUint8Array() {
  const { writer, readable } = push();
  writer.write(new Uint8Array([72, 73])); // 'HI'
  writer.endSync();
  const result = await text(readable);
  assert.strictEqual(result, 'HI');
}

async function testOndrainWaitsForDrain() {
  const { writer, readable } = push({ highWaterMark: 1 });
  writer.writeSync('a'); // Fills buffer

  let drained = false;
  const drainPromise = ondrain(writer).then((v) => { drained = v; });

  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(drained, false); // Still waiting

  // Read to drain
  const iter = readable[Symbol.asyncIterator]();
  await iter.next();

  await drainPromise;
  assert.strictEqual(drained, true);
  writer.endSync();
}

Promise.all([
  testOndrain(),
  testOndainNonDrainable(),
  testWriteWithSignalRejects(),
  testWriteWithPreAbortedSignal(),
  testCancelledWriteRemovedFromQueue(),
  testOndrainResolvesFalseOnConsumerBreak(),
  testOndrainRejectsOnConsumerThrow(),
  testWritev(),
  testWritevSync(),
  testWritevMixedTypes(),
  testWriteAfterEnd(),
  testWriteAfterFail(),
  testFailSync(),
  testEndAsyncReturnValue(),
  testWriteUint8Array(),
  testOndrainWaitsForDrain(),
]).then(common.mustCall());
