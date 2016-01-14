'use strict';
// Flags: --zero-fill-buffers

// when using --zero-fill-buffers, every Buffer and SlowBuffer
// instance must be zero filled

require('../common');
const SlowBuffer = require('buffer').SlowBuffer;
const assert = require('assert');

const bufs = [
  Buffer.zalloc(10),
  SlowBuffer.zalloc(10),
  Buffer.alloc(10),
  SlowBuffer.alloc(10),
  new Buffer(10),
  new SlowBuffer(10)
];

function isZeroFilled(buf) {
  for (let n = 0; n < buf.length; n++)
    if (buf[n] > 0) return false;
  return true;
}

for (const buf of bufs)
  assert(isZeroFilled(buf));
