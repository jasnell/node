// Flags: --policy-deny=timing
'use strict';

require('../common');
const { throws } = require('assert');
const perf_hooks = require('perf_hooks');

throws(() => process.hrtime(), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => process.hrtime.bigint(), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => perf_hooks.performance.mark('A'), {
  code: 'ERR_ACCESS_DENIED'
});

// Mark was never set
throws(() => perf_hooks.performance.measure('A', 'A', 'A'), {
  code: 'ERR_INVALID_PERFORMANCE_MARK'
});

throws(() => perf_hooks.performance.measure('A', 'nodeStart', 'v8Start'), {
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
