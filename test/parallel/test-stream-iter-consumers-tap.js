// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  pull,
  push,
  tap,
  tapSync,
  text,
} = require('stream/iter');

// =============================================================================
// tap / tapSync
// =============================================================================

async function testTapSync() {
  const observed = [];
  const observer = tapSync((chunks) => {
    if (chunks !== null) {
      observed.push(chunks.length);
    }
  });

  // tapSync returns a function transform
  assert.strictEqual(typeof observer, 'function');

  // Test that it passes data through unchanged
  const input = [new Uint8Array([1]), new Uint8Array([2])];
  const result = observer(input);
  assert.deepStrictEqual(result, input);
  assert.deepStrictEqual(observed, [2]);

  // null (flush) passes through
  const flushResult = observer(null);
  assert.strictEqual(flushResult, null);
}

async function testTapAsync() {
  const observed = [];
  const observer = tap(async (chunks) => {
    if (chunks !== null) {
      observed.push(chunks.length);
    }
  });

  assert.strictEqual(typeof observer, 'function');

  const input = [new Uint8Array([1])];
  const result = await observer(input);
  assert.deepStrictEqual(result, input);
  assert.deepStrictEqual(observed, [1]);
}

async function testTapInPipeline() {
  const { writer, readable } = push();
  const seen = [];

  const observer = tap(async (chunks) => {
    if (chunks !== null) {
      for (const chunk of chunks) {
        seen.push(new TextDecoder().decode(chunk));
      }
    }
  });

  writer.write('hello');
  writer.end();

  // Use pull with tap as a transform
  const result = pull(readable, observer);
  const data = await text(result);

  assert.strictEqual(data, 'hello');
  assert.strictEqual(seen.length, 1);
  assert.strictEqual(seen[0], 'hello');
}

Promise.all([
  testTapSync(),
  testTapAsync(),
  testTapInPipeline(),
]).then(common.mustCall());
