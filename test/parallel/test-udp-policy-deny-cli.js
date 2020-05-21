// Flags: --policy-deny=net.udp
'use strict';

require('../common');
const { throws } = require('assert');
const { createSocket } = require('dgram');

throws(() => createSocket('udp4'), { code: 'ERR_ACCESS_DENIED' });
