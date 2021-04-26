'use strict';

const {
  ObjectSetPrototypeOf,
  Promise,
  PromiseReject,
  ReflectConstruct,
  SafeMap,
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

const kInit = Symbol('kInit');
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
  makeTransferable,
  kClone,
  kDeserialize,
} = require('internal/worker/js_transferable');

const {
  defineEventHandler,
  NodeEventTarget,
} = require('internal/event_target');

const {
  EndpointConfig,
  SessionConfig,
  StreamOptions,
  ResponseOptions,
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

class Endpoint extends NodeEventTarget {
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

    super();
    this[kInit](_createEndpoint(options[kHandle]));
    return makeTransferable(this);
  }

  [kInit](handle) {
    this[kState] = {
      close: {
        promise: undefined,
        resolve: undefined,
        reject: undefined,
      },
      destroyed: false,
      listening: false,
      sessions: new SafeSet(),
    };

    this[kHandle] = handle;
    this[kHandle][owner_symbol] = this;
    this[kStats] = new EndpointStats(this[kHandle].stats);
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

    if (options.signal?.aborted)
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

    if (options.signal?.aborted)
      throw new AbortError();

    const session = createSession(
      this[kHandle].createClientSession(
        address[kSocketAddressHandle],
        options[kHandle],
        options[kSecureContext],
        sessionTicket,
        transportParams),
      options.signal);

    this[kState].sessions.add(session);
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

  [kClone]() {
    const handle = this[kHandle];
    return {
      data: { handle },
      deserializeInfo: 'internal/quic/quic:InternalEndpoint',
    };
  }

  [kDeserialize]({ handle }) {
    this[kInit](handle);
  }
}

class InternalEndpoint extends NodeEventTarget {
  constructor() {
    super();
    return makeTransferable(this);
  }
}

defineEventHandler(Endpoint.prototype, 'close');
defineEventHandler(Endpoint.prototype, 'error');
defineEventHandler(Endpoint.prototype, 'session');

InternalEndpoint.prototype.constructor = Endpoint;
ObjectSetPrototypeOf(
  InternalEndpoint.prototype,
  Endpoint.prototype);

/**
 * @typedef {import('../abort_controller').AbortSignal} AbortSignal
 * @param {EndpointWrap} handle
 * @param {AbortSignal} signal
 * @returns {Session}
 */
function createSession(handle, signal) {
  return ReflectConstruct(function() {
    this[kState] = {
      streams: new SafeMap(),
      signal,
    };
    this[kHandle] = handle;
    this[kState].signal = signal;
  }, [], Session);
}

class Session extends NodeEventTarget {

  constructor() {
    // eslint-disable-next-line no-restricted-syntax
    throw new TypeError('illegal constructor');
  }

  openStream(options = new StreamOptions()) {
    if (!StreamOptions.isStreamOptions(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'StreamOptions',
          'Object',
        ], options);
      }
      options = new StreamOptions(options);
    }
  }

  close() {}

  destroy(error) {}

  /** @type {boolean} */
  get closing() {}

  /** @type {boolean} */
  get destroyed() {}

  get stats() {}

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `Session ${inspect({
      closing: this.closing,
      destroyed: this.destroyed,
      listening: this.listening,
      stats: this.stats,
    }, opts)}`;
  }
}

defineEventHandler(Session.prototype, 'close');
defineEventHandler(Session.prototype, 'error');
defineEventHandler(Session.prototype, 'stream');

class Stream extends NodeEventTarget {
  constructor() {
    // eslint-disable-next-line no-restricted-syntax
    throw new TypeError('illegal constructor');
  }

  /** @type {number} */
  get id() {}

  /** @type {boolean} */
  get unidirectional() {}

  /** @type {boolean} */
  get peerInitiated() {}

  /**
   * @param {Error} [error]
   */
  destroy(error) {}

  /** @type {boolean} */
  get closing() {}

  /** @type {boolean} */
  get destroyed() {}

  get stats() {}

  /**
   * When supported by the protocol, sends response hints
   * (for instance, HTTP 1xx status headers) that preceed
   * the response. If respondWith is called first, or the
   * protocol does not support hints, responseHints() will
   * throw.
   * @param {Object|Map<string,string>} headers
   */
  responseHints(headers) {}

  /**
   * Initiates a response on this stream. Returns a Promise
   * that is fulfilled when the response has been completed.
   * If the Stream is peerInitiated and unidirectional, or if
   * respondWith has already been caled, respondWith will reject
   * immediately.
   * @returns {Promise<void>}
   */
  respondWith(options = new ResponseOptions()) {
    if (!ResponseOptions.isResponseOptions(options)) {
      if (options === null || typeof options !== 'object') {
        throw new ERR_INVALID_ARG_TYPE('options', [
          'ResponseOptions',
          'Object',
        ], options);
      }
      options = new ResponseOptions(options);
    }
  }

  /**
   * Return a Promise that is fulfilled with the stream data
   * contained in an ArrayBuffer
   * @returns {Promise<ArrayBuffer>}
   */
  arrayBuffer() {}

  /**
   * @typedef {import('../blob').Blob} Blob
   * Return a Promise that is fulfilled with the stream data
   * contained in a Blob.
   * @returns {Promise<Blob>}
   */
  blob() {}

  /**
   * @typedef {import('stream').Readable} Readable
   * Return a stream.Readable that may be used for consuming
   * the stream data.
   * @returns {Readable}
   */
  stream() {}

  /**
   * Return a Promise that is fulfilled with the stream data
   * contained as a string.
   * @returns {Promise<string>}
   */
  text() {}
}

defineEventHandler(Stream.prototype, 'close');
defineEventHandler(Stream.prototype, 'error');
defineEventHandler(Stream.prototype, 'headers');

module.exports = {
  Endpoint,
  InternalEndpoint,
  Session,
  Stream,
  EndpointConfig,
  SessionConfig,
};
