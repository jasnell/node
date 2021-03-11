'use strict';

const {
  createEndpoint: _createEndpoint,
  initializeCallbacks,
} = internalBinding('quic');

const {
  EndpointConfig,
  SessionConfig,
  kHandle,
  kCreateClientContext,
  kCreateServerContext,
} = require('internal/quic/config');

const {
  SocketAddress,
  isSocketAddress,
  kHandle: kSocketAddressHandle,
} = require('internal/socketaddress');

const {
  isURLInstance,
} = require('internal/url');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  inspect,
} = require('util');

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
  },
} = require('internal/errors');

function onEndpointClose() {}
function onEndpointDone() {}
function onEndpointError() {}
function onSessionNew() {}
function onSessionCert() {}
function onSessionClientHello() {}
function onSessionClose() {}
function onSessionDatagram() {}
function onSessionHandshake() {}
function onSessionKeylog() {}
function onSessionPathValidation() {}
function onSessionUsePreferredAddress() {}
function onSessionQlog() {}
function onSessionOcspRequest() {}
function onSessionOcspResponse() {}
function onSessionTicket() {}
function onSessionVersionNegotiation() {}
function onStreamClose() {}
function onStreamError() {}
function onStreamReady() {}
function onStreamReset() {}
function onStreamHeaders() {}
function onStreamBlocked() {}

initializeCallbacks({
  onEndpointClose,
  onEndpointDone,
  onEndpointError,
  onSessionNew,
  onSessionCert,
  onSessionClientHello,
  onSessionClose,
  onSessionDatagram,
  onSessionHandshake,
  onSessionKeylog,
  onSessionPathValidation,
  onSessionUsePreferredAddress,
  onSessionQlog,
  onSessionOcspRequest,
  onSessionOcspResponse,
  onSessionTicket,
  onSessionVersionNegotiation,
  onStreamClose,
  onStreamError,
  onStreamReady,
  onStreamReset,
  onStreamHeaders,
  onStreamBlocked,
});

class Endpoint {
  constructor(options = new EndpointConfig()) {
    if (!EndpointConfig.isEndpointConfig(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'EndpointConfig',
          'Object'
        ], options);
      }
      options = new EndpointConfig(options);
    }

    this[kHandle] = _createEndpoint(options[kHandle]);
  }

  listen(options = new SessionConfig()) {
    if (!SessionConfig.isSessionConfig(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'SessionConfig',
          'Object'
        ], options);
      }
      options = new SessionConfig(options);
    }

    this[kHandle].listen(options[kHandle], options[kCreateServerContext]());
    return this;
  }

  async connect(address, options = new SessionConfig()) {
    if (!isSocketAddress(address)) {
      if (!isURLInstance(address)) {
        if (typeof address !== 'string') {
          throw new ERR_INVALID_ARG_TYPE('address', [
            'SocketAddress',
            'URL',
            'string'
          ], address);
        }
        address = new URL(address);
      }
      const { hostname, port } = address;
      // TODO(@jasnell): Get type....
      const ip = await options.onLookup(hostname, 'ipv4');
      console.log(ip, port);

      address = new SocketAddress({
        address: ip,
        port: port | 0,
        family: 'ipv4',
      });
    }

    return createSession(
      this[kHandle].createClientSession(
        address[kSocketAddressHandle],
        options[kHandle],
        options[kCreateClientContext]()));
  }

  async close() {}

  destroy() {}

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `Endpoint ${inspect({}, opts)}`;
  }
}

class Session {
  constructor() { throw new Error('Illegal constructor'); }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `Session ${inspect({}, opts)}`;
  }
}

function createSession(handle) {
  return Reflect.construct(function(handle) {
    this[kHandle] = handle;
  }, [handle], Session);
}

class Stream {

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `Stream ${inspect({}, opts)}`;
  }
}

module.exports = {
  Endpoint,
  EndpointConfig,
  SessionConfig,
};
