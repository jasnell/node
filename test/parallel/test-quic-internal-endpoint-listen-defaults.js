// Flags: --expose-internals --no-warnings
'use strict';

const common = require('../common');
if (!common.hasQuic)
  common.skip('missing quic');

const { Endpoint } = require('internal/quic/quic');
const { SocketAddress } = require('node:net');
const {
  ok,
  strictEqual,
  notStrictEqual,
} = require('node:assert');

const endpoint = new Endpoint();

ok(!endpoint.state.isListening);
ok(!endpoint.state.isReceiving);
ok(!endpoint.state.isBound);
strictEqual(endpoint.address, undefined);

endpoint.listen();

ok(endpoint.state.isListening);
ok(endpoint.state.isReceiving);
ok(endpoint.state.isBound);

ok(endpoint.address instanceof SocketAddress);

strictEqual(endpoint.address.address, '127.0.0.1');
strictEqual(endpoint.address.family, 'ipv4');
strictEqual(endpoint.address.flowlabel, 0);
notStrictEqual(endpoint.address.port, 0);

endpoint.close().then(common.mustCall(() => {
  ok(!endpoint.state.isListening);
  ok(!endpoint.state.isReceiving);
  ok(!endpoint.state.isBound);
  strictEqual(endpoint.address, undefined);
  notStrictEqual(endpoint.stats.destroyedAt, 0n);
}));
