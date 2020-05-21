'use strict';

const common = require('../common');
const { throws, rejects } = require('assert');
const dns = require('dns');

process.policy.deny('net');

const testCases = [
  'lookup',
  'resolve',
  'resolve4',
  'resolve6',
  'resolveAny',
  'resolveCname',
  'resolveMx',
  'resolveNaptr',
  'resolveNs',
  'resolvePtr',
  'resolveSoa',
  'resolveSrv',
  'resolveTxt',
  'reverse'
];

testCases.forEach((i) => {
  throws(() => dns[i]('anything', common.mustNotCall()), {
    code: 'ERR_ACCESS_DENIED'
  });
});

throws(() => dns.setServers(['123.123.123.123']), {
  code: 'ERR_ACCESS_DENIED'
});

throws(() => dns.lookupService('127.0.0.1', 123, common.mustNotCall()), {
  code: 'ERR_ACCESS_DENIED'
});

(async () => {
  await Promise.all(testCases.map((i) => {
    return rejects(dns.promises[i]('anything'), {
      code: 'ERR_ACCESS_DENIED'
    });
  }));

  throws(() => dns.promises.setServers(['123.123.123.123']), {
    code: 'ERR_ACCESS_DENIED'
  });

  rejects(dns.promises.lookupService('127.0.0.1', 123), {
    code: 'ERR_ACCESS_DENIED'
  });
})().then(common.mustCall());
