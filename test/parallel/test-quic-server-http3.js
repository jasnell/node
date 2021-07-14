'use strict';

const common = require('../common');

if (!common.hasQuic)
  common.skip('quic support is not enabled');

const {
  Endpoint,
} = require('net/quic');

const fixtures = require('../common/fixtures');

const endpoint = new Endpoint({ address: { port: 12345 } });

endpoint.onsession = common.mustCall(({ session }) => {
  session.onstream = ({ stream, respondWith }) => {
    respondWith({
      headers: {
        ':status': 200,
        'content-type': 'text/plain',
      },
      body: 'right back at you',
    });
    console.log(stream.headers);
    stream.readableNodeStream().pipe(process.stdout);
  };
});

endpoint.listen({
  secure: {
    key: fixtures.readKey('rsa_private.pem'),
    cert: fixtures.readKey('rsa_cert.crt'),
  },
});

// Client....

const client = new Endpoint();
const req = client.connect(endpoint.address, { hostname: 'localhost', });

req.handshake.then(common.mustCall(() => {
  const stream = req.open({
    headers: {
      ':method': 'GET',
      ':path': '/',
      ':scheme': 'https',
      'host': '127.0.0.1:12345',
    },
    body: 'hello there',
  });

  stream.readableNodeStream().pipe(process.stdout);

  stream.closed.then(common.mustCall(() => {
    client.close();
    endpoint.close();
  }));
}));
