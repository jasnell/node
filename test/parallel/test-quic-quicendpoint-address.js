// Flags: --no-warnings
'use strict';

const common = require('../common');
if (!common.hasQuic)
  common.skip('missing quic');

const assert = require('assert');

const { createQuicSocket } = require('net');

async function Test(options, address) {
  const server = createQuicSocket(options);
  server.on('close', common.mustCall());

  assert.strictEqual(server.bound, false);
  assert.deepStrictEqual({}, server.address);

  await server.listen();

  assert.strictEqual(server.bound, true);
  assert.strictEqual(server.destroyed, false);
  assert.strictEqual(typeof server.address.port, 'number');
  assert.strictEqual(server.address, address);

  await server.close();

  assert.strictEqual(server.destroyed, true);
}

const tests = [
  Test({}, '0.0.0.0'),
  Test({ port: 0 }, '0.0.0.0'),
  Test({ address: '127.0.0.1', port: 0 }, '127.0.0.1'),
  Test({ address: 'localhost', port: 0 }, '127.0.0.1')
];

if (common.hasIPv6) {
  tests.push(
    Test({ type: 'udp6' }, '::'),
    Test({ type: 'udp6', address: 'localhost' }, '::1'));
}

Promise.all(tests);
