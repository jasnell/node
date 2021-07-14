'use strict';

const {
  Boolean,
  ObjectAssign,
  ObjectCreate,
  ObjectDefineProperties,
  PromiseReject,
  ReflectConstruct,
} = primordials;

const {
  createEndpoint: _createEndpoint,
  JSQuicBufferConsumer,
  QUIC_STREAM_HEADERS_KIND_INFO,
  QUIC_STREAM_HEADERS_KIND_INITIAL,
  QUIC_STREAM_HEADERS_KIND_TRAILING,
  QUIC_STREAM_HEADERS_FLAGS_NONE,
  QUIC_STREAM_HEADERS_FLAGS_TERMINAL,
} = internalBinding('quic');

// If the _createEndpoint is undefined, the Node.js binary
// was built without QUIC support, in which case we
// don't want to export anything here.
if (_createEndpoint === undefined)
  return;

const {
  acquireBody,
  setPromiseHandled,
  kBlocked,
  kDestroy,
  kHeaders,
  kMaybeStreamEvent,
  kResetStream,
  kState,
  kType,
} = require('internal/quic/common');

const {
  kHandle,
  ResponseOptions,
} = require('internal/quic/config');

const {
  symbols: {
    owner_symbol,
  },
} = require('internal/async_hooks');

const {
  kEnumerableProperty,
} = require('internal/webstreams/util');

const {
  createStreamStats,
  kDetach: kDetachStats,
  kStats,
} = require('internal/quic/stats');

const {
  createDeferredPromise,
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  Readable,
} = require('stream');

const {
  inspect,
} = require('util');

const {
  codes: {
    ERR_ILLEGAL_CONSTRUCTOR,
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_STATE,
    ERR_INVALID_THIS,
    ERR_QUIC_STREAM_RESET,
  },
} = require('internal/errors');

const {
  ReadableStream,
} = require('internal/webstreams/readablestream');

const {
  mapToHeaders,
  toHeaderObject,
} = require('internal/http2/util');

class Stream {
  constructor() { throw new ERR_ILLEGAL_CONSTRUCTOR(); }

  [kBlocked]() {
    blockedStream(this);
  }

  [kDestroy](error) {
    destroyStream(this, error);
  }

  [kHeaders](headers, kind) {
    streamHeaders(this, headers, kind);
  }

  [kResetStream](appErrorCode) {
    // A stream reset is a terminal state. If appErrorCode
    // is equal to NO_ERROR (0), then we simply destroy
    // the stream with no error and treat it as a normal
    // cancel. Any other error code triggers an error flow.
    let error;
    if (appErrorCode !== 0)
      error = new ERR_QUIC_STREAM_RESET(appErrorCode);
    destroyStream(this, error);
  }

  /**
   * A promise that is fulfilled when the Stream is
   * reported as being blocked. Whenever blocked is
   * fulfilled, a new promise is created.
   * @type {Promise<any>}
   */
  get blocked() {
    if (!isStream(this))
      return PromiseReject(new ERR_INVALID_THIS('Stream'));
    return this[kState].blocked.promise;
  }

  /**
   * A promise that is fulfilled when the Stream has
   * been closed. If the Stream closed normally, the
   * promise will be fulfilled with undefined. If the
   * Stream closed abnormally, the promise will be
   * rejected with a reason indicating why.
   * @readonly
   * @type {Promise<any>}
   */
  get closed() {
    if (!isStream(this))
      return PromiseReject(new ERR_INVALID_THIS('Stream'));
    return this[kState].closed.promise;
  }

  /**
   * @readonly
   * @type {bigint}
   */
  get id() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return this[kState].id;
  }

  /**
   * @readonly
   * @type {boolean}
   */
  get unidirectional() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return isStreamUnidirectional(this);
  }

  /**
   * @readonly
   * @type {boolean}
   */
  get serverInitiated() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return isStreamServerInitiated(this);
  }

  /**
   * Called by user-code to signal no further interest
   * in the Stream. It will be immediately destroyed.
   * Any data pending in the outbound and inbound queues
   * will be abandoned.
   * @param {any} [reason]
   */
  cancel(reason) {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    destroyStream(this, reason);
  }

  /**
   * @readonly
   * @type {import('./stats').StreamStats}
   */
  get stats() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return this[kStats];
  }

  /**
   * When supported by the protocol, sends response hints
   * (for instance, HTTP 1xx status headers) that preceed
   * the response. If respondWith is called first, or the
   * protocol does not support hints, responseHints() will
   * throw.
   * @param {Object|Map<string,string>} headers
   */
  responseHints(headers) {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    if (isStreamDestroyed(this))
      throw new ERR_INVALID_STATE('Stream is already destroyed');
    if (this[kState].hintsSent) {
      throw new ERR_INVALID_STATE(
        'Informational headers have already been sent');
    }
    if (this[kState].responded)
      throw new ERR_INVALID_STATE('A response has already been sent');

    stream[kHandle].sendHeaders(
      QUIC_STREAM_HEADERS_KIND_INFO,
      mapToHeaders(headers),
      QUIC_STREAM_HEADERS_FLAGS_NONE);
    this[kState].hintsSent = true;
  }

  /**
   * Initiates a response on this stream. Returns a Promise
   * that is fulfilled when the response has been completed.
   * If the Stream is peerInitiated and unidirectional, or if
   * respondWith has already been called, respondWith will reject
   * immediately. TODO(@jasnell): Finish the impl.
   * @returns {Promise<void>}
   */
  respondWith(response = new ResponseOptions()) {
    if (!isStream(this))
      PromiseReject(new ERR_INVALID_THIS('Stream'));
    return respondWith(this, response);
  }

  /**
   * @readonly
   * @type {boolean} Set to `true` if there is an active consumer.
   */
  get locked() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return isStreamLocked(this);
  }

  /**
   * @typedef {import('stream/web').ReadableStream} ReadableStream
   * @returns {ReadableStream}
   */
  readableStream() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    if (isStreamDestroyed(this))
      throw new ERR_INVALID_STATE('Stream is already destroyed');
    if (isStreamLocked(this))
      throw new ERR_INVALID_STATE('Stream is already being consumed');

    return acquireReadableStream(this);
  }

  /**
   * @returns {Readable}
   */
  streamReadable() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    if (isStreamDestroyed(this))
      throw new ERR_INVALID_STATE('Stream is already destroyed');
    if (isStreamLocked(this))
      throw new ERR_INVALID_STATE('Stream is already being consumed');

    return acquireStreamReadable(this);
  }

  get session() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return this[kState].session;
  }

  /**
   * @type {{}} The headers associated with this Stream, if any
   */
  get headers() {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    return this[kState].headers;
  }

  /**
   * @type {Promise<{}>} The trailers associated with this Stream, if any
   */
  get trailers() {
    if (!isStream(this))
      return PromiseReject(new ERR_INVALID_THIS('Stream'));
    return this[kState].trailers.promise;
  }

  [kInspect](depth, options) {
    if (!isStream(this))
      throw new ERR_INVALID_THIS('Stream');
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `${this[kType]} ${inspect({
      closed: this[kState].closed.promise,
      destroyed: isStreamDestroyed(this),
      id: this[kState].id,
      headers: this[kState].headers,
      locked: isStreamLocked(this),
      serverInitiated: isStreamServerInitiated(this),
      session: this[kState].session,
      stats: this[kStats],
      trailers: this[kState].trailers.promise,
      unidirectional: isStreamUnidirectional(this),
    }, opts)}`;
  }
}

ObjectDefineProperties(Stream.prototype, {
  blocked: kEnumerableProperty,
  closed: kEnumerableProperty,
  cancel: kEnumerableProperty,
  headers: kEnumerableProperty,
  id: kEnumerableProperty,
  locked: kEnumerableProperty,
  readableStream: kEnumerableProperty,
  respondWith: kEnumerableProperty,
  responseHints: kEnumerableProperty,
  serverInitiated: kEnumerableProperty,
  session: kEnumerableProperty,
  stats: kEnumerableProperty,
  streamReadable: kEnumerableProperty,
  trailers: kEnumerableProperty,
  unidirectional: kEnumerableProperty,
});

function createStream(handle, session) {
  const ret = ReflectConstruct(
    function() {
      this[kType] = 'Stream';
      this[kState] = {
        id: handle.id,
        blocked: undefined,
        closed: createDeferredPromise(),
        hints: ObjectCreate(null),
        hintsSent: false,
        headers: undefined,
        trailers: createDeferredPromise(),
        consumer: undefined,
        destroyed: false,
        responded: false,
        session,
      };
      this[kHandle] = handle;
      this[kStats] = createStreamStats(handle.stats);
      setNewBlockedPromise(this);
      setPromiseHandled(this[kState].closed.promise);
      setPromiseHandled(this[kState].trailers.promise);
    },
    [],
    Stream);
  ret[kHandle][owner_symbol] = ret;
  return ret;
}

function isStream(value) {
  return typeof value?.[kState] === 'object' && value?.[kType] === 'Stream';
}

function isStreamLocked(stream) {
  return stream[kState].consumer !== undefined;
}

function isStreamDestroyed(stream) {
  return stream[kHandle] === undefined;
}

function isStreamUnidirectional(stream) {
  return Boolean(stream[kState].id & 0b10n);
}

function isStreamServerInitiated(stream) {
  return Boolean(stream[kState].id & 0b01n);
}

function setStreamSource(stream, source) {
  if (isStreamDestroyed(stream))
    throw new ERR_INVALID_STATE('Stream is already destroyed');
  stream[kHandle].attachSource(source);
}

function setNewBlockedPromise(stream) {
  stream[kState].blocked = createDeferredPromise();
  setPromiseHandled(stream[kState].blocked.promise);
}

function blockedStream(stream) {
  stream[kState].blocked.resolve();
  setNewBlockedPromise(stream);
}

function destroyStream(stream, error) {
  if (isStreamDestroyed(stream))
    return;

  const handle = stream[kHandle];
  stream[kHandle][owner_symbol] = undefined;
  stream[kHandle] = undefined;

  //    state.inner = undefined;
  stream[kStats][kDetachStats]();

  handle.destroy();

  const {
    blocked,
    consumer,
    closed,
  } = stream[kState];

  blocked.reject(new ERR_INVALID_STATE('Stream has been canceled'));

  if (typeof consumer?.destroy === 'function')
    consumer.destroy(error);
  else if (typeof consumer?.cancel === 'function')
    consumer.cancel(error);

  if (error)
    closed.reject(error);
  else
    closed.resolve();
}

async function respondWith(stream, response) {
  // Using a thenable here instead of a real Promise will have
  // a negative performance impact. We support both but a Promise
  // is better.
  if (typeof response?.then === 'function')
    response = await response;

  if (stream[kState].responded)
    throw new ERR_INVALID_STATE('A response has already been sent');

  if (!ResponseOptions.isResponseOptions(response)) {
    if (response === null || typeof response !== 'object') {
      throw new ERR_INVALID_ARG_TYPE('response', [
        'ResponseOptions',
        'Object',
      ], response);
    }
    response = new ResponseOptions(response);
  }

  const {
    headers,
    // trailers,
    body,
  } = response;

  try {
    const actualBody = await acquireBody(body);
    if (headers !== undefined) {
      const actualHeaders = await headers;
      stream[kHandle].sendHeaders(
        QUIC_STREAM_HEADERS_KIND_INITIAL,
        mapToHeaders(actualHeaders),
        actualBody === undefined ?
            QUIC_STREAM_HEADERS_FLAGS_TERMINAL :
            QUIC_STREAM_HEADERS_FLAGS_NONE);
    }
    setStreamSource(stream, actualBody);
    stream[kState].responded = true;
  } catch (error) {
    destroyStream(stream, error);
  }
}

function acquireStreamReadable(stream) {
  const handle = new JSQuicBufferConsumer();
  handle.emit = (chunks, done) => {
    for (let n = 0; n < chunks.length; n++)
      stream[kState].consumer.push(chunks[n]);
    if (done)
      stream[kState].consumer.push(null);
  };
  stream[kState].consumer = new Readable({
    [kHandle]: handle,
    read(size) {
      // Nothing to do here, the data should already
      // be flowing if it's available.
    }
  });
  stream[kHandle].attachConsumer(handle);
  return stream[kState].consumer;
}

function acquireReadableStream(stream) {
  let controller;
  const handle = new JSQuicBufferConsumer();
  handle.emit = (chunks, done) => {
    for (let n = 0; n < chunks.length; n++)
      controller.enqueue(chunks[n]);
    if (done)
      controller.close();
  };
  stream[kState].consumer = new ReadableStream({
    start(c) { controller = c; }
  });
  stream[kHandle].attachConsumer(handle);
  return stream[kState].consumer;
}

function streamHeaders(stream, headers, kind) {
  const obj = toHeaderObject(headers);
  switch (kind) {
    case QUIC_STREAM_HEADERS_KIND_INFO:
      stream[kState].hints = obj;
      break;
    case QUIC_STREAM_HEADERS_KIND_INITIAL:
      stream[kState].headers = ObjectAssign(stream[kState].hints, obj);
      stream[kState].session[kMaybeStreamEvent](stream);
      break;
    case QUIC_STREAM_HEADERS_KIND_TRAILING:
      stream[kState].trailers.resolve(obj);
      break;
  }
}

function responseHints(stream, headers) {
  stream[kHandle].sendHeaders(
    QUIC_STREAM_HEADERS_KIND_INFO,
    mapToHeaders(headers),
    QUIC_STREAM_HEADERS_FLAGS_NONE);
}

module.exports = {
  Stream,
  createStream,
  destroyStream,
  isStream,
  setStreamSource,
};
