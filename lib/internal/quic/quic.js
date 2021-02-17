'use strict';

const {
  ArrayPrototypePush,
  PromiseAll,
  PromiseReject,
  PromisePrototypeThen,
  PromisePrototypeCatch,
  PromisePrototypeFinally,
  ReflectConstruct,
  SafeMap,
  SafeSet,
  Symbol,
} = primordials;

const {
  symbols: {
    owner_symbol,
  },
} = require('internal/async_hooks');

const {
  createEndpoint: _createEndpoint,
  initializeCallbacks,
} = internalBinding('quic');

const {
  EndpointConfig,
  EndpointInternalState,
  EndpointStatistics,
  SessionOptions,
  internalEndpointStats,

  kClose,
  kDestroy,
  kHandle,
  kMaybeBind,
  kState,
} = require('internal/quic/util');

const {
  InternalSocketAddress,
  SocketAddress,
  isSocketAddress,
  kHandle: kSocketAddressHandle,
} = require('internal/blocklist');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  inspect,
} = require('util');

const {
  validateObject,
} = require('internal/validators');

const {
  createDeferredPromise
} = require('internal/util');

const {
  isURLInstance
} = require('internal/url');

const {
  lookup,
} = require('dns/promises');

const {
  ADDRCONFIG: DNS_LOOKUP_FLAG_ADDRCONFIG,
} = require('dns');

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
  },
} = require('internal/errors');

const kOnSessionNew = Symbol('kOnSessionNew');

function onEndpointClose(context, code) {
  // TODO(@jasnell): Handle properly
  const err = code ? new Error('boom') : undefined;
  const owner = this[owner_symbol];
  owner[kDestroy](err);
}

function onEndpointDone() {
  const owner = this[owner_symbol];
  owner[kDestroy]();
}

function onEndpointError() {
  console.log('onEndpointError');
}

function onSessionNew(session) {
  const owner = this[owner_symbol];
  owner[kOnSessionNew](session);
}

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

async function defaultLookup(address, type = 'ipv4') {
  const family = type === 'ipv4' ? 4 : 6;
  const hints = DNS_LOOKUP_FLAG_ADDRCONFIG;
  if (family === 6 && address.startsWith('['))
    address = address.slice(1, -1);
  return await lookup(address, { family, hints });
}

function setClosePromise(state, promise, resolve, reject) {
  state.set('closePromise', {
    promise: PromisePrototypeFinally(
      promise, () => state.delete('closePromise')),
    resolve,
    reject
  });
}

async function getSocketAddressFromURL(origin, family, lookup) {
  if (typeof origin === 'string')
    origin = new URL(origin);
  if (!isURLInstance(origin))
    return undefined;

  let {
    hostname = 'localhost',
    port = 80,
  } = origin;

  // The URL getters return empty strings, and we can't have
  // that nonsense here.
  if (!hostname) hostname = 'localhost';
  if (!port) port = 80;

  const { address } = await lookup(hostname, family);

  return new SocketAddress({ address, port, family });
}

class Session {}

class ClientSession extends Session {}

class ServerSession extends Session {}

class Stream {}

class Endpoint {
  constructor() { throw new TypeError('Illegal constructor'); }

  async connect(origin, options = new SessionOptions()) {
    // TODO(@jasnell): Proper error
    if (this.destroyed)
      throw new Error('destroyed');

    validateObject(options, 'options');
    if (!(options instanceof SessionOptions))
      options = new SessionOptions(options);

    let address;
    if (isSocketAddress(origin)) {
      address = origin;
    } else {
      address = await getSocketAddressFromURL(
        origin,
        this[kState].get('family'),
        this[kState].get('lookup'));
    }

    if (!isSocketAddress(address)) {
      throw new ERR_INVALID_ARG_TYPE(
        'origin',
        [
          'net.SocketAddress',
          'URL',
          'string'
        ],
        origin);
    }

    return this[kHandle]?.createClientSession(
      address[kSocketAddressHandle],
      options[kHandle]);
  }

  listen(options = new SessionOptions()) {
    // TODO(@jasnell): Proper error
    if (this.destroyed)
      throw new Error('destroyed');
    if (this[kState].get('listening')) return this;
    validateObject(options, 'options');
    if (!(options instanceof SessionOptions))
      options = new SessionOptions(options);
    this[kHandle].listen(options[kHandle]);
    this[kState].set('onSession', options.onSession);
    this[kState].set('listening', true);
    return this;
  }

  close() {
    // TODO(@jasnell): Proper error
    if (this.destroyed)
      return PromiseReject(new Error('destroyed'));
    if (!this[kState].has('closePromise'))
      this[kClose]();

    const { promise } = this[kState].get('closePromise');
    return promise;
  }

  [kClose]() {
    const internal = this[kState].get('internal');
    internal.listening = false;

    const { promise, resolve, reject } = createDeferredPromise();

    const sessions = this[kState].get('sessions');

    if (!this.bound || sessions.size === 0) {
      setClosePromise(this[kState], promise, resolve, reject);
      this.destroy();
      return;
    }

    const reqs = [promise];
    for (const session of sessions) {
      ArrayPrototypePush(
        reqs,
        PromisePrototypeCatch(
          session.close(),
          (error) => this.destroy(error)));
    }

    setClosePromise(
      this[kState],
      PromiseAll(reqs),
      resolve,
      reject);
  }

  destroy(error) {
    if (this.destroyed) return;
    this[kState].set('destroyed', true);
    const stats = this[kState].get('stats');
    const sessions = this[kState].get('sessions');

    stats[kClose]();

    for (const session of sessions)
      session.destroy(error);

    this[kState].delete('internal');
    this[kState].delete('sessions');
    this[kState].delete('lookup');

    this[kHandle].waitForPendingCallbacks();
  }

  [kDestroy](error) {
    this[kHandle] = undefined;
    const closePromise = this[kState].get('closePromise');

    if (error && typeof closePromise?.reject === 'function')
      closePromise.reject(error);
    else if (typeof closePromise?.resolve === 'function')
      closePromise.resolve();
  }

  ref() {
    this[kHandle]?.ref();
    return this;
  }

  unref() {
    this[kHandle]?.unref();
    return this;
  }

  get address() {
    let ret = this[kState].get('address');
    if (ret === undefined ) {
      const addr = this[kHandle]?.address();
      if (addr === undefined) return;
      ret = new InternalSocketAddress(addr);
      this[kState].set('address', ret);
    }
    return ret;
  }

  get destroyed() {
    return !!this[kState].get('destroyed');
  }

  get stats() {
    return this[kState].get('stats');
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `Endpoint ${inspect({}, opts)}`;
  }

  [kOnSessionNew](session) {
    const serverSession = new ServerSession(session);
    this[kState].get('sessions').add(serverSession);
    const ret = this[kState].get('onSession')?.(serverSession);
    if (typeof ret?.then === 'function') {
      PromisePrototypeThen(ret, undefined, (err) => {
        // TODO(@jasnell): Implement properly
        console.log('boom!!!');
      });
    }
  }
}

function internalEndpoint(config, { lookup }) {
  this[kState] = new SafeMap();
  this[kHandle] = _createEndpoint(config[kHandle]);
  this[kHandle][owner_symbol] = this;
  this[kState].set('lookup', lookup);
  this[kState].set('family', config.family);
  this[kState].set('sessions', new SafeSet());
  this[kState].set(
    'stats',
    ReflectConstruct(
      internalEndpointStats,
      [this[kHandle].stats],
      EndpointStatistics));
  this[kState].set(
    'internal',
    new EndpointInternalState(
      this[kHandle].state));
}

function createEndpoint(config = new EndpointConfig(), overrides = {}) {
  validateObject(config, 'config');
  validateObject(overrides, 'overrides');

  if (!(config instanceof EndpointConfig))
    config = new EndpointConfig(config);

  const {
    lookup = defaultLookup,
  } = overrides;

  if (typeof lookup !== 'function')
    throw new ERR_INVALID_ARG_TYPE('overrides.lookup', 'function', lookup);

  return ReflectConstruct(
    internalEndpoint,
    [
      config,
      {
        lookup,
      }
    ],
    Endpoint);
}

module.exports = {
  EndpointConfig,
  SessionOptions,
  createEndpoint,
};
