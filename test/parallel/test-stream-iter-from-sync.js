// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const { fromSync } = require('stream/iter');

async function testFromSyncString() {
  // String input should be UTF-8 encoded
  const readable = fromSync('hello');
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.strictEqual(batches[0].length, 1);
  assert.deepStrictEqual(batches[0][0],
                         new TextEncoder().encode('hello'));
}

async function testFromSyncUint8Array() {
  const input = new Uint8Array([1, 2, 3]);
  const readable = fromSync(input);
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.strictEqual(batches[0].length, 1);
  assert.deepStrictEqual(batches[0][0], input);
}

async function testFromSyncArrayBuffer() {
  const ab = new ArrayBuffer(4);
  new Uint8Array(ab).set([10, 20, 30, 40]);
  const readable = fromSync(ab);
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.deepStrictEqual(batches[0][0], new Uint8Array([10, 20, 30, 40]));
}

async function testFromSyncUint8ArrayArray() {
  // Array of Uint8Array should yield as a single batch
  const chunks = [new Uint8Array([1]), new Uint8Array([2])];
  const readable = fromSync(chunks);
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.strictEqual(batches[0].length, 2);
}

async function testFromSyncGenerator() {
  function* gen() {
    yield new Uint8Array([1, 2]);
    yield new Uint8Array([3, 4]);
  }
  const readable = fromSync(gen());
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 2);
  assert.deepStrictEqual(batches[0][0], new Uint8Array([1, 2]));
  assert.deepStrictEqual(batches[1][0], new Uint8Array([3, 4]));
}

async function testFromSyncNestedIterables() {
  // Nested arrays and strings should be flattened
  function* gen() {
    yield ['hello', ' ', 'world'];
  }
  const readable = fromSync(gen());
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.strictEqual(batches[0].length, 3);
}

async function testFromSyncToStreamableProtocol() {
  const sym = Symbol.for('Stream.toStreamable');
  const obj = {
    [sym]() {
      return 'protocol-data';
    },
  };
  function* gen() {
    yield obj;
  }
  const readable = fromSync(gen());
  const batches = [];
  for (const batch of readable) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 1);
  assert.deepStrictEqual(batches[0][0],
                         new TextEncoder().encode('protocol-data'));
}

async function testFromSyncRejectsNonStreamable() {
  assert.throws(
    () => fromSync(12345),
    { name: 'TypeError' },
  );
}

async function testFromSyncEmptyGenerator() {
  function* empty() {}
  let count = 0;
  // eslint-disable-next-line no-unused-vars
  for (const _ of fromSync(empty())) { count++; }
  assert.strictEqual(count, 0);
}

Promise.all([
  testFromSyncString(),
  testFromSyncUint8Array(),
  testFromSyncArrayBuffer(),
  testFromSyncUint8ArrayArray(),
  testFromSyncGenerator(),
  testFromSyncNestedIterables(),
  testFromSyncToStreamableProtocol(),
  testFromSyncRejectsNonStreamable(),
  testFromSyncEmptyGenerator(),
]).then(common.mustCall());
