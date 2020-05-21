// Flags: --policy-deny=signal
'use strict';

require('../common');
const { throws } = require('assert');

throws(() => process.kill(1, 1), { code: 'ERR_ACCESS_DENIED' });
