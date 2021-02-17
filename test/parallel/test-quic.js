// Flags: --expose-internals
'use strict';

require('../common');
const {
  createEndpoint
} = require('net/quic');

const {
  kHandle
} = require('internal/quic/quic');

const endpoint = createEndpoint();

endpoint.listen();

const { address, port } = endpoint.address;

console.log(`listening at ${address} on port ${port}`)

setTimeout(() => endpoint.close(), 10000);
