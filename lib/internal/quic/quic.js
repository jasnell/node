'use strict';

const {
  ArrayPrototypePush,
  PromiseAll,
  PromisePrototypeCatch,
  PromisePrototypeFinally,
  PromiseResolve,
  ReflectConstruct,
  SafeMap,
  SafeSet,
} = primordials;

const {
  createEndpoint: _createEndpoint,
  UV_UDP_IPV6ONLY,
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
  kOptions,
  kMaybeBind,
  kState,
  kUdp,
} = require('internal/quic/util');

const {
  InternalBlockList
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
  createSocket
} = require('dgram');

const {
  lookup,
} = require('dns/promises');

const {
  ADDRCONFIG: DNS_LOOKUP_FLAG_ADDRCONFIG,
} = require('dns');

const {
  kStateSymbol: kDgramStateSymbol,
} = require('internal/dgram');

const {
  exceptionWithHostPort,
  codes: {
    ERR_INVALID_ARG_TYPE,
  },
} = require('internal/errors');

async function defaultLookup(address, type = 'udp4') {
  const family = type === 'udp4' ? 4 : 6;
  const hints = DNS_LOOKUP_FLAG_ADDRCONFIG;
  if (family === 6 && address.startsWith('['))
    address = address.slice(1, -1);
  return await lookup(address, { family, hints });
}

async function bindUdpWrap(kState) {
  // TODO(@jasnell): Support AbortSignal

  kState.set('bindState', 'pending');

  const handle = kState.get('udpWrap')[kDgramStateSymbol].handle;
  const lookup = kState.get('lookup') || defaultLookup;
  const address = kState.get('address');
  const port = kState.get('port');
  const {
    type = 'udp4',
    ipv6Only = false,
  } = kState.get('udp') || {};

  const { address: ip } = await lookup(address, type);
  const ip = address;

  try {
    const ret = handle.bind(ip, port, ipv6Only ? UV_UDP_IPV6ONLY : 0);
    if (ret)
      throw exceptionWithHostPort(ret, 'bind', ip, port);
    kState.set('bindState', 'bound');
  } catch (err) {
    kState.delete('bindState');
    throw err;
  }
}

function setClosePromise(state, promise, resolve, reject) {
  state.set('closePromise', {
    promise: PromisePrototypeFinally(
      promise, () => state.delete(closePromise)),
    resolve,
    reject
  });
}

class Endpoint {
  constructor() {
    throw new TypeError('Illegal constructor');
  }

  async connect(origin, options = new SessionOptions()) {
    validateObject(options, 'options');
    if (!(options instanceof SessionOptions))
      options = new SessionOptions(options);

    if (!isURLInstance(origin)) {
      if (typeof origin !== 'string')
        throw new ERR_INVALID_ARG_TYPE('origin', ['URL', 'string'], origin);
      origin = new URL(origin);
    }

    const state = this[kState];
    const lookup = state.get('lookup') || defaultLookup;
    const {
      type = 'udp4',
    } = state.get('udp') || {};
    const {
      hostname,
      port,
    } = origin;

    const [{ address: ip }] = await PromiseAll([
      await lookup(hostname, type),
      await this[kMaybeBind](),
    ]);
  }

  async listen(options = new SessionOptions()) {
    validateObject(options, 'options');
    if (!(options instanceof SessionOptions))
      options = new SessionOptions(options);

    await this[kMaybeBind]();

    this[kHandle].startListen(options[kHandle]);
    return this;
  }

  close() {
    if (!this[kState].has('closePromise'))
      this[kClose]();

    const { promise } = this[kState].get('closePromise');

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
    const stats = this[kState].get('stats');
    const sessions = this[kState].get('sessions');
    const udpWrap = this[kState].get('udpWrap');

    stats[kClose]();

    for (const session of sessions)
      session.destroy(error);

    this[kHandle].ondone = () => {
      udpWrap.close((err) => {
        if (err) error = err;
        this[kDestroy](error);
      });
    };
    this[kHandle].startWaitingForPendingCallbacks();
  }

  [kDestroy](error) {
    this[kHandle] = undefined;
    this[kState].delete('udpWrap');
    const closePromise = this[kState].get('closePromise');

    if (error && typeof closePromise?.reject === 'function')
      closePromise.reject(error);
    else if (typeof closePromise?.resolve === 'function')
      closePromise.resolve();
  }

  get bound() {
    return this[kState].get('bindState') === 'bound';
  }

  ref() {
    this[kUdp].ref();
    return this;
  }

  unref() {
    this[kUdp].unref();
    return this;
  }

  setTTL(ttl) {
    this[kState].get('udpWrap').setTTL(ttl);
    return this;
  }

  setMulticastTTL(ttl) {
    this[kState].get('udpWrap').setMulticastTTL(ttl);
    return this;
  }

  setBroadcast(on = true) {
    this[kState].get('udpWrap').setBroadcast(on);
    return this;
  }

  setMulticastLoopback(on = true) {
    this[kState].get('udpWrap').setMulticastLoopback(on);
    return this;
  }

  setMulticastInterface(iface) {
    this[kState].get('udpWrap').setMulticastInterface(iface);
    return this;
  }

  addMembership(address, iface) {
    this[kState].get('udpWrap').addMembership(address, iface);
    return this;
  }

  dropMembership(address, iface) {
    this[kState].get('udpWrap').dropMembership(address, iface);
    return this;
  }

  get blockList() {
    return this[kState].get('blockList');
  }

  get stats() {
    return this[kState].get('stats');
  }

  [kMaybeBind]() {
    if (this[kState].get('bindState') === 'bound')
      return PromiseResolve();

    if (!this[kState].has('bindPromise')) {
      this[kState].set(
        'bindPromise',
        PromisePrototypeFinally(
          bindUdpWrap(this[kState]),
          () => { this[kState].delete('bindPromise') }));
    }

    return this[kState].get('bindPromise');
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
}

function internalEndpoint(config, { lookup, udpWrap }) {
  const {
    address,
    port,
  } = config[kOptions];
  this[kState] = new SafeMap();
  this[kHandle] = _createEndpoint(
    config[kHandle],
    udpWrap[kDgramStateSymbol].handle);
  this[kState].set('udpWrap', udpWrap);
  this[kState].set('address', address);
  this[kState].set('port', port);
  this[kState].set('lookup', lookup);
  this[kState].set('udp', config[kOptions].udp);
  this[kState].set('sessions', new SafeSet());
  this[kState].set(
    'blockList',
    new InternalBlockList(this[kHandle].blockList));
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
    udpWrap = createSocket(config[kOptions].udp)
  } = overrides;

  if (typeof lookup !== 'function')
    throw new ERR_INVALID_ARG_TYPE('overrides.lookup', 'function', lookup);

  if (typeof udpWrap[kDgramStateSymbol] !== 'object' ||
      typeof udpWrap[kDgramStateSymbol].handle !== 'object') {
    throw new ERR_INVALID_ARG_TYPE(
      'overrides.udpWrap',
      'dgram.Socket',
      udpWrap);
  }

  return ReflectConstruct(
    internalEndpoint,
    [
      config,
      {
        lookup,
        udpWrap,
      }
    ],
    Endpoint);
}

module.exports = {
  EndpointConfig,
  SessionOptions,
  createEndpoint,
};
