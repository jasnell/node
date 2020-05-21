// Flags: --policy-deny=workers
'use strict';
require('../common');
const { throws } = require('assert');
const { Worker } = require('worker_threads');

throws(() => new Worker('', { eval: true }), {
  code: 'ERR_ACCESS_DENIED'
});
