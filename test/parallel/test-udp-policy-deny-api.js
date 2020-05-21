'use strict';

require('../common');
const { throws } = require('assert');
const { createSocket } = require('dgram');

// Works before denying...
const socket = createSocket('udp4');

process.policy.deny('net.udp');

// After deny, creating a new socket fails
throws(() => createSocket('udp4'), { code: 'ERR_ACCESS_DENIED' });

// But the existing socket is still usable

socket.bind(0, () => socket.close());
