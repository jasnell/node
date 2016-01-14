'use strict';
require('../common');
var assert = require('assert');

var util = require('util');

var buffer = require('buffer');

buffer.INSPECT_MAX_BYTES = 2;

var b = Buffer.unsafe(4);
b.fill('1234');

var s = buffer.SlowBuffer.unsafe(4);
s.fill('1234');

var expected = '<Buffer 31 32 ... >';

assert.strictEqual(util.inspect(b), expected);
assert.strictEqual(util.inspect(s), expected);

b = Buffer.unsafe(2);
b.fill('12');

s = buffer.SlowBuffer.unsafe(2);
s.fill('12');

expected = '<Buffer 31 32>';

assert.strictEqual(util.inspect(b), expected);
assert.strictEqual(util.inspect(s), expected);

buffer.INSPECT_MAX_BYTES = Infinity;

assert.doesNotThrow(function() {
  assert.strictEqual(util.inspect(b), expected);
  assert.strictEqual(util.inspect(s), expected);
});
