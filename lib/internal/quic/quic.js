'use strict';

const {
  Promise,
  PromiseReject,
  SafeSet,
  Symbol,
  TypeError,
} = primordials;

const {
  createEndpoint: _createEndpoint,
} = internalBinding('quic');

// If the _createEndpoint is undefined, the Node.js binary
// was built without QUIC support, in which case we
// don't want to export anything here.
if (_createEndpoint === undefined)
  return;

const kState = Symbol('kState');
const kStats = Symbol('kStats');

const assert = require('internal/assert');

const {
  symbols: {
    owner_symbol,
  },
} = require('internal/async_hooks');

const {
  initializeBinding,
} = require('internal/quic/binding');

const {
  EndpointConfig,
  SessionConfig,
  kHandle,
  kSecureContext,
  validateResumeOptions,
} = require('internal/quic/config');

const {
  EndpointStats,
  kDetach: kDetachStats,
} = require('internal/quic/stats');

const {
  SocketAddress,
  kHandle: kSocketAddressHandle,
} = require('internal/socketaddress');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  inspect,
} = require('util');

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_STATE,
  },
  AbortError,
} = require('internal/errors');

const { validateObject } = require('internal/validators');

/**
 * @typedef {import('../socketaddress').SocketAddressOrOptions
 * } SocketAddressOrOptions
 * @typedef {import('./config').SessionConfigOrOptions} SessionConfigOrOptions
 * @typedef {import('./config').EndpointConfigOrOptions} EndpointConfigOrOptions
 */

initializeBinding();

/** @returns {{ promise: Promise, resolve: Function, reject: Function }} */
function deferred() {
  let res, rej;
  const promise = new Promise((resolve, reject) => {
    res = resolve;
    rej = reject;
  });
  return {
    promise,
    resolve: res,
    reject: rej,
  };
}

function onAbort() {
  this.destroy(new AbortError());
  this[kState].onAbort = undefined;
  this[kState].signal = undefined;
}

class Endpoint {
  [kState] = {
    onAbort: undefined,
    signal: undefined,
    close: {
      promise: undefined,
      resolve: undefined,
      reject: undefined,
    },
    destroyed: false,
    listening: false,
    sessions: new SafeSet(),
  };

  /**
   * @param {EndpointConfigOrOptions} [options]
   */
  constructor(options = new EndpointConfig()) {
    if (!EndpointConfig.isEndpointConfig(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'EndpointConfig',
          'Object',
        ], options);
      }
      options = new EndpointConfig(options);
    }

    this[kHandle] = _createEndpoint(options[kHandle]);
    this[kHandle][owner_symbol] = this;
    this[kStats] = new EndpointStats(this[kHandle].stats);

    if (options.signal !== undefined) {
      if (options.signal.aborted)
        throw new AbortError();
      this[kState].onAbort = onAbort.bind(this);
      this[kState].signal = options.signal;
      this[kState].signal.addEventListener(
        'abort',
        this[kState].onAbort,
        { once: true });
    }
  }

  /**
   * @param {SessionConfigOrOptions} [options]
   * @returns {Endpoint}
   */
  listen(options = new SessionConfig('server')) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('Endpoint is already destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('Endpoint is closing');
    if (this.listening)
      throw new ERR_INVALID_STATE('Endpoint is already listening');

    if (!SessionConfig.isSessionConfig(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'SessionConfig',
          'Object',
        ], options);
      }
      options = new SessionConfig('server', options);
    }
    if (options.side !== 'server') {
      throw new ERR_INVALID_ARG_VALUE(
        'options',
        options,
        'must be a server SessionConfig');
    }

    if (options.signal.aborted)
      throw AbortError();
    // TODO(@jasnell): Retain AbortSignal to associate with server sessions

    this[kHandle].listen(options[kHandle], options[kSecureContext]);
    this[kState].listening = true;
    return this;
  }

  /**
   * @param {SocketAddressOrOptions} address
   * @param {SessionConfigOrOptions} [options]
   * @param {Object} [resume]
   * @param {ArrayBuffer|TypedArray|DataView} resume.sessionTicket
   * @param {ArrayBuffer|TypedArray|DataView} resume.transportParams
   * @returns {Session}
   */
  connect(address, options = new SessionConfig('client'), resume = {}) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('Endpoint is already destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('Endpoint is closing');

    if (!SocketAddress.isSocketAddress(address)) {
      if (typeof address !== 'object' || address == null) {
        throw new ERR_INVALID_ARG_TYPE('address', [
          'SocketAddress',
          'Object',
        ], address);
      }
      address = new SocketAddress(address);
    }

    if (!SessionConfig.isSessionConfig(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'SessionConfig',
          'Object',
        ], options);
      }
      options = new SessionConfig('client', options);
    }

    if (options.side !== 'client') {
      throw new ERR_INVALID_ARG_VALUE(
        'options',
        options,
        'must be a client SessionConfig');
    }

    validateObject(resume, 'resume');
    const {
      sessionTicket,
      transportParams,
    } = resume;
    validateResumeOptions(sessionTicket, transportParams);

    if (options.signal.aborted)
      throw new AbortError();

    return createSession(
      this[kHandle].createClientSession(
        address[kSocketAddressHandle],
        options[kHandle],
        options[kSecureContext],
        sessionTicket,
        transportParams),
      options.signal);
  }

  /**
   * Begins a graceful close of the Endpoint.
   * * If the Endpoint is listening, new inbound Initial packets will be
   *   rejected.
   * * Attempts to create new outbound Sessions using connect() will be
   *   immediately rejected.
   * * Existing Sessions will be allowed to finish naturally, after which
   *   the Endpoint will be immediately destroyed.
   * * The Promise returned will be resolved when the Endpoint is destroyed,
   *   or rejected if a fatal errors occurs.
   *  @returns {Promise<void>}
   */
  close() {
    const state = this[kState];
    if (this.destroyed) {
      return PromiseReject(
        new ERR_INVALID_STATE('Endpoint is already destroyed'));
    }

    if (this.closing)
      return state.close.promise;

    const { promise, resolve, reject } = deferred();
    state.close.promise = promise.finally(() => {
      state.close.promise = undefined;
      state.close.resolve = undefined;
      state.close.reject = undefined;
    });
    state.close.resolve = resolve;
    state.close.reject = reject;
    // Signals that we're closing and waiting for onEndpointDone to be called
    this[kHandle].waitForPendingCallbacks();

    return state.close.promise;
  }

  /**
   * Immediately destroys the Endpoint.
   * * Any existing Sessions will be immediately, and abruptly terminated.
   * * The reference to the underlying EndpointWrap handle will be released
   *   allowing it to be garbage collected as soon as possible.
   * * The stats will be detached from the underlying EndpointWrap
   * @param {Error} [error]
   * @returns {void}
   */
  destroy(error) {
    const state = this[kState];
    if (state.destroyed)
      return;
    state.destroyed = true;

    for (const session of state.sessions)
      session.destroy(error);

    assert(state.sessions.size === 0);

    // TODO(@jasnell): Communicate to the handle that it's been destroyed.

    this[kStats][kDetachStats]();
    this[kHandle] = undefined;

    if (state.signal !== undefined && state.onAbort !== undefined) {
      state.signal.removeEventListener('abort', state.onAbort);
      state.signal = undefined;
      state.onAbort = undefined;
    }

    if (error != null && typeof state.close.reject === 'function')
      state.close.reject(error);
    else if (typeof state.close.resolve === 'function')
      state.close.resolve();
  }

  /** @type {boolean} */
  get closing() {
    return this[kState].close.promise !== undefined;
  }

  /** @type {boolean} */
  get destroyed() {
    return this[kState].destroyed;
  }

  /** @type {boolean} */
  get listening() {
    return this[kState].listening;
  }

  /** @type {import('./stats').EndpointStats} */
  get stats() { return this[kStats]; }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `Endpoint ${inspect({
      closing: this.closing,
      destroyed: this.destroyed,
      listening: this.listening,
      stats: this.stats,
    }, opts)}`;
  }
}

/**
 * @typedef {import('../abort_controller').AbortSignal} AbortSignal
 * @param {EndpointWrap} handle
 * @param {AbortSignal} signal
 * @returns {Session}
 */
function createSession(handle, signal) {}

class Session {
  constructor() {
    // eslint-disable-next-line no-restricted-syntax
    throw new TypeError('illegal constructor');
  }
}

class Stream {
  constructor() {
    // eslint-disable-next-line no-restricted-syntax
    throw new TypeError('illegal constructor');
  }
}

module.exports = {
  Endpoint,
  Session,
  Stream,
  EndpointConfig,
  SessionConfig,
};
