// Flags: --expose-internals
'use strict';

require('../common');
const {
  createEndpoint
} = require('net/quic');

const endpoint = createEndpoint();

endpoint.listen({
  alpn: 'abc',
  async onSession(session) {
    console.log(session);
  },
});

const { address, port } = endpoint.address;

console.log(`listening at ${address} on port ${port}`)

endpoint.connect('https://example.org').then(console.log);

setTimeout(() => endpoint.close(), 10000);
