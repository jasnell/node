'use strict';

require('../common');
const { throws } = require('assert');
const child_process = require('child_process');

process.policy.deny('special.child_process');

throws(() => child_process.spawn('test'), { code: 'ERR_ACCESS_DENIED' });
throws(() => child_process.spawnSync('test'), { code: 'ERR_ACCESS_DENIED' });
throws(() => child_process.exec('test'), { code: 'ERR_ACCESS_DENIED' });
throws(() => child_process.execSync('test'), { code: 'ERR_ACCESS_DENIED' });
throws(() => child_process.execFile('test'), { code: 'ERR_ACCESS_DENIED' });
throws(() => child_process.execFileSync('test'), { code: 'ERR_ACCESS_DENIED' });
throws(() => child_process.fork('test'), { code: 'ERR_ACCESS_DENIED' });
