// Flags: --policy-deny=net,timing --policy-grant=net.tcp
'use strict';

require('../common');
const assert = require('assert');

assert(process.policy.granted('fs'));
assert(process.policy.granted('net.tcp'));
assert(!process.policy.granted('net'));
assert(!process.policy.granted('net.udp'));
assert(!process.policy.granted('timing'));

process.policy.deny('fs.in');

assert(process.policy.granted('fs'));
assert(!process.policy.granted('fs.in'));
assert(process.policy.granted('fs.out'));
