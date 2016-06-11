'use strict';

require('internal/util').assertCrypto(exports);

const tls = require('tls');
const url = require('url');
const http2 = require('internal/http2');
const util = require('util');

function initializeOptions(options) {
  options = options || {};
  options.ALPNProtocols = ['hc', 'h2'];
  options.NPNProtocols = ['hc', 'h2'];
  return options;
}

class Server extends tls.Server {
  constructor(options, requestListener) {
    super(initializeOptions(options), http2.connectionListener);
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
    this.on('tlsClientError', (err, conn) => {
      if (!this.emit('clientError', err, conn))
        conn.destroy(err);
    });
  }
}

exports.createServer = function createServer(options, requestListener) {
  return new Server(options, requestListener);
};
