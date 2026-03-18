// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const vm = require('vm');
const { from, fromSync, pull, text, bytesSync } = require('stream/iter');

// Cross-realm objects are created in a different VM context.
// They have different prototypes, so `instanceof` checks fail.
// These tests verify that stream/iter correctly handles cross-realm types.

// Helper: compare Uint8Array content regardless of realm.
function assertBytes(actual, expected) {
  assert.strictEqual(actual.length, expected.length,
                     `length mismatch: ${actual.length} !== ${expected.length}`);
  for (let i = 0; i < expected.length; i++) {
    assert.strictEqual(actual[i], expected[i], `byte mismatch at index ${i}`);
  }
}

// =============================================================================
// from() / fromSync() with cross-realm Uint8Array
// =============================================================================

async function testFromSyncCrossRealmUint8Array() {
  const crossRealm = vm.runInNewContext('new Uint8Array([1, 2, 3])');
  const readable = fromSync(crossRealm);
  const data = bytesSync(readable);
  assertBytes(data, new Uint8Array([1, 2, 3]));
}

async function testFromCrossRealmUint8Array() {
  const crossRealm = vm.runInNewContext('new Uint8Array([4, 5, 6])');
  const readable = from(crossRealm);
  const result = await text(readable);
  assert.strictEqual(result, '\x04\x05\x06');
}

// =============================================================================
// from() / fromSync() with cross-realm ArrayBuffer
// =============================================================================

async function testFromSyncCrossRealmArrayBuffer() {
  const crossRealm = vm.runInNewContext(
    'new Uint8Array([7, 8, 9]).buffer',
  );
  const readable = fromSync(crossRealm);
  const data = bytesSync(readable);
  assertBytes(data, new Uint8Array([7, 8, 9]));
}

async function testFromCrossRealmArrayBuffer() {
  const crossRealm = vm.runInNewContext(
    'new Uint8Array([10, 11, 12]).buffer',
  );
  const readable = from(crossRealm);
  const result = await text(readable);
  assert.strictEqual(result, '\x0a\x0b\x0c');
}

// =============================================================================
// from() / fromSync() with cross-realm Uint8Array[]
// =============================================================================

async function testFromSyncCrossRealmUint8ArrayArray() {
  const crossRealm = vm.runInNewContext(
    '[new Uint8Array([1, 2]), new Uint8Array([3, 4])]',
  );
  const readable = fromSync(crossRealm);
  const data = bytesSync(readable);
  assertBytes(data, new Uint8Array([1, 2, 3, 4]));
}

async function testFromCrossRealmUint8ArrayArray() {
  const crossRealm = vm.runInNewContext(
    '[new Uint8Array([5, 6]), new Uint8Array([7, 8])]',
  );
  const readable = from(crossRealm);
  const result = await text(readable);
  assert.strictEqual(result, '\x05\x06\x07\x08');
}

// =============================================================================
// pull() with cross-realm Uint8Array from transforms
// =============================================================================

async function testPullCrossRealmTransformOutput() {
  // Transform that returns cross-realm Uint8Array[] batches
  const source = from('hello');
  const crossRealmTransform = (chunks) => {
    if (chunks === null) return null;
    // Re-encode each chunk as cross-realm Uint8Array
    return vm.runInNewContext(
      `[new Uint8Array([${[...chunks[0]]}])]`,
    );
  };
  const result = pull(source, crossRealmTransform);
  const output = await text(result);
  assert.strictEqual(output, 'hello');
}

// =============================================================================
// from() with cross-realm Promise
// =============================================================================

async function testFromCrossRealmPromise() {
  const crossRealmPromise = vm.runInNewContext(
    'Promise.resolve("promised-data")',
  );
  async function* gen() {
    yield crossRealmPromise;
  }
  const readable = from(gen());
  const result = await text(readable);
  assert.strictEqual(result, 'promised-data');
}

// =============================================================================
// from() with cross-realm typed arrays (non-Uint8Array views)
// =============================================================================

async function testFromSyncCrossRealmInt32Array() {
  const crossRealm = vm.runInNewContext('new Int32Array([1])');
  const readable = fromSync(crossRealm);
  const data = bytesSync(readable);
  // Int32Array([1]) = 4 bytes: 01 00 00 00 (little-endian)
  assert.strictEqual(data.length, 4);
  assert.strictEqual(data[0], 1);
}

Promise.all([
  testFromSyncCrossRealmUint8Array(),
  testFromCrossRealmUint8Array(),
  testFromSyncCrossRealmArrayBuffer(),
  testFromCrossRealmArrayBuffer(),
  testFromSyncCrossRealmUint8ArrayArray(),
  testFromCrossRealmUint8ArrayArray(),
  testPullCrossRealmTransformOutput(),
  testFromCrossRealmPromise(),
  testFromSyncCrossRealmInt32Array(),
]).then(common.mustCall());
