// Flags: --expose-internals
'use strict';

require('../common');
const {
  createEndpoint
} = require('net/quic');

(async () => {

  const endpoint = createEndpoint();

  endpoint.listen({
    alpn: 'abc',
    async onSession(session) {
      console.log(session);
    },
  });

  const { address, port } = endpoint.address;

  console.log(`listening at ${address} on port ${port}`)

  const session = await endpoint.connect('https://example.org');
  console.log(session.open());

  setTimeout(() => endpoint.close(), 10000);

})()
