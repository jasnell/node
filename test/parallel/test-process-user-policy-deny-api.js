'use strict';

require('../common');
const { throws } = require('assert');
const os = require('os');

process.policy.deny('user,process');

throws(() => process.chdir(''), { code: 'ERR_ACCESS_DENIED' });
throws(() => process.title = '', { code: 'ERR_ACCESS_DENIED' });
throws(() => os.setPriority(1), { code: 'ERR_ACCESS_DENIED' });
throws(() => os.homedir(), { code: 'ERR_ACCESS_DENIED' });
throws(() => os.userInfo(1), { code: 'ERR_ACCESS_DENIED' });


[
  ['setegid', 'getegid'],
  ['setuuid', 'getuuid'],
  ['setgid', 'getgid'],
  ['setgroups', 'getgroups'],
  ['setuid', 'getuid'],
].forEach((i) => {
  if (process[i[0]])
    throws(() => process[i[0]](process[i[1]]()), { code: 'ERR_ACCESS_DENIED'});
});

if (process.initgroups) {
  const test = 'fhqwhgadshgnsdhjsdbkhsdabkfabkveyb';
  throws(() => process.initgroups(test, test), { code: 'ERR_ACCESS_DENIED' });
}
