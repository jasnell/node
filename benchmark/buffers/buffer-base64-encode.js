'use strict';
const SlowBuffer = require('buffer').SlowBuffer;

const common = require('../common.js');
const bench = common.createBenchmark(main, {
  type: ['fast-zalloc', 'slow-zalloc', 'fast-alloc', 'slow-alloc']
});

function main(conf) {
  const clazz = /^fast/.test(conf.type) ? Buffer : SlowBuffer;
  const fn = /zalloc/.test(conf.type) ? clazz.zalloc : clazz.alloc;

  const N = 64 * 1024 * 1024;
  bench.start();
  const b = fn(N);
  let s = '';
  for (let i = 0; i < 256; ++i) s += String.fromCharCode(i);
  for (let i = 0; i < N; i += 256) b.write(s, i, 256, 'ascii');
  for (let i = 0; i < 32; ++i) b.toString('base64');
  bench.end(64);
}
