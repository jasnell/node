'use strict';

require('../common');
const { throws } = require('assert');
const perf_hooks = require('perf_hooks');

// They work before they are denied
process.hrtime();
process.hrtime.bigint();
perf_hooks.performance.mark('A');
perf_hooks.performance.mark('A', 'A', 'A');
perf_hooks.performance.timerify(() => {});

// These console outputs are part of the test.
console.time('a');
console.timeEnd('a');

process.policy.deny('timing');

throws(() => process.hrtime(), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => process.hrtime.bigint(), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => perf_hooks.performance.mark('B'), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => perf_hooks.performance.measure('A', 'A', 'A'), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => perf_hooks.performance.clearMarks(), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => perf_hooks.performance.timerify(() => {}), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => console.time('A'), {
  code: 'ERR_ACCESS_DENIED'
});
