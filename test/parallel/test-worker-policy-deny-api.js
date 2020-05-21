'use strict';
require('../common');
const { throws } = require('assert');
const { Worker } = require('worker_threads');

process.policy.deny('workers');

throws(() => new Worker('', { eval: true }), {
  code: 'ERR_ACCESS_DENIED'
});
