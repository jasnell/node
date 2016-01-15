'use strict';
const SlowBuffer = require('buffer').SlowBuffer;

const common = require('../common.js');
const bench = common.createBenchmark(main, {
  type: ['fast-zalloc', 'slow-zalloc', 'fast-alloc', 'slow-alloc'],
  len: [10, 1024, 2048, 4096, 8192],
  n: [1024]
});

function main(conf) {
  const len = +conf.len;
  const n = +conf.n;
  const clazz = /^fast/.test(conf.type) ? Buffer : SlowBuffer;
  const fn = /zalloc/.test(conf.type) ? clazz.zalloc : clazz.alloc;

  bench.start();
  for (let i = 0; i < n * 1024; i++) {
    fn(len);
  }
  bench.end(n);
}
