'use strict';
// Flags: --zero-fill-buffers

// when using --zero-fill-buffers, every Buffer and SlowBuffer
// instance must be zero filled

require('../common');
const SlowBuffer = require('buffer').SlowBuffer;
const assert = require('assert');

const bufs = [
  Buffer.safe(10),
  SlowBuffer.safe(10),
  Buffer.unsafe(10),
  SlowBuffer.unsafe(10),
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
