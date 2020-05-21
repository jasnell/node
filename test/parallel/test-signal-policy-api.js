'use strict';

require('../common');
const { throws } = require('assert');

process.policy.deny('signal');

throws(() => process.kill(1, 1), { code: 'ERR_ACCESS_DENIED' });
