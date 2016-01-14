'use strict';

require('../common');
const assert = require('assert');
const buffer = require('buffer');
const Buffer = buffer.Buffer;
const SlowBuffer = buffer.SlowBuffer;

const ones = [1, 1, 1, 1];

// should create a Buffer
let sb = SlowBuffer.unsafe(4);
assert(sb instanceof Buffer);
assert.strictEqual(sb.length, 4);
sb.fill(1);
assert.deepEqual(sb, ones);

// underlying ArrayBuffer should have the same length
assert.strictEqual(sb.buffer.byteLength, 4);

// should work without new
sb = SlowBuffer.unsafe(4);
assert(sb instanceof Buffer);
assert.strictEqual(sb.length, 4);
sb.fill(1);
assert.deepEqual(sb, ones);

// should work with edge cases
assert.strictEqual(SlowBuffer.unsafe(0).length, 0);
try {
  assert.strictEqual(
    SlowBuffer.unsafe(buffer.kMaxLength).length, buffer.kMaxLength);
} catch (e) {
  assert.equal(e.message, 'Invalid array buffer length');
}

// should work with number-coercible values
assert.strictEqual(SlowBuffer.unsafe('6').length, 6);
assert.strictEqual(SlowBuffer.unsafe(true).length, 1);

// should create zero-length buffer if parameter is not a number
assert.strictEqual(SlowBuffer.unsafe().length, 0);
assert.strictEqual(SlowBuffer.unsafe(NaN).length, 0);
assert.strictEqual(SlowBuffer.unsafe({}).length, 0);
assert.strictEqual(SlowBuffer.unsafe('string').length, 0);

// should throw with invalid length
assert.throws(function() {
  SlowBuffer.unsafe(Infinity);
}, 'invalid Buffer length');
assert.throws(function() {
  SlowBuffer.unsafe(-1);
}, 'invalid Buffer length');
assert.throws(function() {
  SlowBuffer.unsafe(buffer.kMaxLength + 1);
}, 'invalid Buffer length');
