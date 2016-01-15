'use strict';
const SlowBuffer = require('buffer').SlowBuffer;
const assert = require('assert');
const common = require('../common.js');

const bench = common.createBenchmark(main, {
  type: ['fast-zalloc', 'slow-zalloc', 'fast-alloc', 'slow-alloc']
});

function main(conf) {
  const clazz = /^fast/.test(conf.type) ? Buffer : SlowBuffer;
  const fn = /zalloc/.test(conf.type) ? clazz.zalloc : clazz.alloc;

  for (var s = 'abcd'; s.length < 32 << 20; s += s);
  s.match(/./);  // Flatten string.
  assert.equal(s.length % 4, 0);
  bench.start();
  var b = fn(s.length / 4 * 3);
  b.write(s, 0, s.length, 'base64');
  for (var i = 0; i < 32; i += 1) b.base64Write(s, 0, s.length);
  bench.end(32);
}
