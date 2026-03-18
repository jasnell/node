// Object creation overhead benchmark.
// Measures the cost of constructing stream infrastructure (no data flow).
'use strict';

const common = require('../../common.js');
const { Readable, Writable, Transform, PassThrough } = require('stream');

const bench = common.createBenchmark(main, {
  api: ['classic', 'webstream', 'iter'],
  type: ['readable', 'writable', 'transform', 'pair'],
  n: [1e5],
}, {
  flags: ['--experimental-stream-iter'],
  // Iter has no standalone Transform class; transforms are plain functions.
  combinationFilter: ({ api, type }) =>
    !(api === 'iter' && type === 'transform'),
});

function main({ api, type, n }) {
  switch (api) {
    case 'classic':
      return benchClassic(type, n);
    case 'webstream':
      return benchWebStream(type, n);
    case 'iter':
      return benchIter(type, n);
  }
}

function benchClassic(type, n) {
  bench.start();
  switch (type) {
    case 'readable':
      for (let i = 0; i < n; i++) new Readable({ read() {} });
      break;
    case 'writable':
      for (let i = 0; i < n; i++) new Writable({ write(c, e, cb) { cb(); } });
      break;
    case 'transform':
      for (let i = 0; i < n; i++) new Transform({
        transform(c, e, cb) { cb(null, c); },
      });
      break;
    case 'pair':
      for (let i = 0; i < n; i++) new PassThrough();
      break;
  }
  bench.end(n);
}

function benchWebStream(type, n) {
  bench.start();
  switch (type) {
    case 'readable':
      for (let i = 0; i < n; i++) new ReadableStream({ pull() {} });
      break;
    case 'writable':
      for (let i = 0; i < n; i++) new WritableStream({ write() {} });
      break;
    case 'transform':
      for (let i = 0; i < n; i++) new TransformStream({
        transform(c, controller) { controller.enqueue(c); },
      });
      break;
    case 'pair': {
      // TransformStream gives a readable+writable pair
      for (let i = 0; i < n; i++) new TransformStream();
      break;
    }
  }
  bench.end(n);
}

function benchIter(type, n) {
  const { push, from, duplex } = require('stream/iter');

  bench.start();
  switch (type) {
    case 'readable':
      for (let i = 0; i < n; i++) from('x');
      break;
    case 'writable':
      // push() creates a writer+readable pair
      for (let i = 0; i < n; i++) push();
      break;
    case 'pair':
      // duplex() creates a bidirectional channel pair
      for (let i = 0; i < n; i++) duplex();
      break;
  }
  bench.end(n);
}
