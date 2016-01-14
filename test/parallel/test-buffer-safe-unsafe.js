'use strict';

require('../common');
const SlowBuffer = require('buffer').SlowBuffer;
const assert = require('assert');

const safe = Buffer.zalloc(10);
const safeslow = SlowBuffer.zalloc(10);

function isZeroFilled(buf) {
  for (let n = 0; n < buf.length; n++)
    if (buf[n] > 0) return false;
  return true;
}

assert(isZeroFilled(safe));
assert(isZeroFilled(safeslow));
