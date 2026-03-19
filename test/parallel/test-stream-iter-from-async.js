// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { from, text, Stream } = require('stream/iter');

async function testFromString() {
  const readable = from('hello-async');
  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.deepStrictEqual(batches[0][0],
                         new TextEncoder().encode('hello-async'));
}

async function testFromAsyncGenerator() {
  async function* gen() {
    yield new Uint8Array([10, 20]);
    yield new Uint8Array([30, 40]);
  }
  const readable = from(gen());
  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 2);
  assert.deepStrictEqual(batches[0][0], new Uint8Array([10, 20]));
  assert.deepStrictEqual(batches[1][0], new Uint8Array([30, 40]));
}

async function testFromSyncIterableAsAsync() {
  // Sync iterable passed to from() should work
  function* gen() {
    yield new Uint8Array([1]);
    yield new Uint8Array([2]);
  }
  const readable = from(gen());
  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  // Sync iterables get batched together into a single batch
  assert.strictEqual(batches.length, 1);
  assert.strictEqual(batches[0].length, 2);
  assert.deepStrictEqual(batches[0][0], new Uint8Array([1]));
  assert.deepStrictEqual(batches[0][1], new Uint8Array([2]));
}

async function testFromToAsyncStreamableProtocol() {
  const sym = Symbol.for('Stream.toAsyncStreamable');
  const obj = {
    [sym]() {
      return 'async-protocol-data';
    },
  };
  async function* gen() {
    yield obj;
  }
  const readable = from(gen());
  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.deepStrictEqual(batches[0][0],
                         new TextEncoder().encode('async-protocol-data'));
}

function testFromRejectsNonStreamable() {
  assert.throws(
    () => from(12345),
    { code: 'ERR_INVALID_ARG_TYPE' },
  );
  assert.throws(
    () => from(null),
    { code: 'ERR_INVALID_ARG_TYPE' },
  );
}

async function testFromEmptyArray() {
  const readable = from([]);
  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 0);
}

// Also accessible via Stream namespace
async function testStreamNamespace() {
  const readable = Stream.from('via-namespace');
  const batches = [];
  for await (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.deepStrictEqual(batches[0][0], new TextEncoder().encode('via-namespace'));
}

async function testCustomToStringInStream() {
  // Objects with custom toString are coerced when yielded inside a stream
  const obj = { toString() { return 'from toString'; } };
  async function* source() {
    yield obj;
  }
  const result = await text(from(source()));
  assert.strictEqual(result, 'from toString');
}

async function testCustomToPrimitiveInStream() {
  const obj = {
    [Symbol.toPrimitive](hint) {
      if (hint === 'string') return 'from toPrimitive';
      return 42;
    },
  };
  async function* source() {
    yield obj;
  }
  const result = await text(from(source()));
  assert.strictEqual(result, 'from toPrimitive');
}

// Both toAsyncStreamable and toStreamable: async takes precedence
async function testFromAsyncStreamablePrecedence() {
  const obj = {
    [Symbol.for('Stream.toStreamable')]() { return 'sync version'; },
    [Symbol.for('Stream.toAsyncStreamable')]() { return 'async version'; },
  };
  async function* gen() { yield obj; }
  const result = await text(from(gen()));
  assert.strictEqual(result, 'async version');
}

Promise.all([
  testFromString(),
  testFromAsyncGenerator(),
  testFromSyncIterableAsAsync(),
  testFromToAsyncStreamableProtocol(),
  testFromRejectsNonStreamable(),
  testFromEmptyArray(),
  testStreamNamespace(),
  testCustomToStringInStream(),
  testCustomToPrimitiveInStream(),
  testFromAsyncStreamablePrecedence(),
]).then(common.mustCall());
