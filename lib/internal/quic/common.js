'use strict';

const {
  FunctionPrototypeCall,
  ObjectDefineProperties,
  PromisePrototypeThen,
  PromiseReject,
  PromiseResolve,
  ReflectConstruct,
  Symbol,
  Uint8Array,
} = primordials;

const {
  codes: {
    ERR_ILLEGAL_CONSTRUCTOR,
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_THIS,
  },
} = require('internal/errors');

const {
  Event,
} = require('internal/event_target');

const {
  ArrayBufferViewSource,
  BlobSource,
  StreamSource,
  StreamBaseSource,
} = internalBinding('quic');

const {
  createDeferredPromise,
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  isAnyArrayBuffer,
  isArrayBufferView,
  isPromise,
} = require('util/types');

const {
  Readable,
  Writable,
  pipeline,
} = require('stream');

const {
  isBlob,
  kHandle: kBlobHandle,
} = require('internal/blob');

const {
  inspect,
  TextEncoder,
} = require('util');

const {
  isReadableStream,
} = require('internal/webstreams/readablestream');

const {
  kEnumerableProperty,
} = require('internal/webstreams/util');

const {
  getPromiseDetails,
  kPending,
} = internalBinding('util');

const {
  isFileHandle,
  kHandle: kFileHandle,
} = require('internal/fs/promises');

const {
  symbols: {
    owner_symbol,
  },
} = require('internal/async_hooks');

const {
  onStreamRead,
  kHandle,
  kUpdateTimer,
  writeGeneric,
  writevGeneric,
} = require('internal/stream_base_commons');

const {
  ShutdownWrap,
} = internalBinding('stream_wrap');

const kAddSession = Symbol('kAddSession');
const kAddStream = Symbol('kAddStream');
const kBlocked = Symbol('kBlocked');
const kClientHello = Symbol('kClientHello');
const kClose = Symbol('kClose');
const kCreatedStream = Symbol('kCreatedStream');
const kData = Symbol('kData');
const kDestroy = Symbol('kDestroy');
const kHandshakeComplete = Symbol('kHandshakeComplete');
const kHeaders = Symbol('kHeaders');
const kOCSP = Symbol('kOCSP');
const kMaybeStreamEvent = Symbol('kMaybeStreamEvent');
const kResetStream = Symbol('kResetStream');
const kSessionTicket = Symbol('kSessionTicket');
const kSetSource = Symbol('kSetSource');
const kState = Symbol('kState');
const kType = Symbol('kType');

class DatagramEvent extends Event {
  constructor() { throw new ERR_ILLEGAL_CONSTRUCTOR(); }

  get datagram() {
    if (!isDatagramEvent(this))
      throw new ERR_INVALID_THIS('DatagramEvent');
    return this[kData].buffer;
  }

  get session() {
    if (!isDatagramEvent(this))
      throw new ERR_INVALID_THIS('DatagramEvent');
    return this[kData].session;
  }

  [kInspect](depth, options) {
    if (!isDatagramEvent(this))
      throw new ERR_INVALID_THIS('DatagramEvent');
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `${this[kType]} ${inspect({
      datagram: this[kData].datagram,
      session: this[kData].session,
    }, opts)}`;
  }
}

ObjectDefineProperties(DatagramEvent.prototype, {
  datagram: kEnumerableProperty,
  session: kEnumerableProperty,
});

function isDatagramEvent(value) {
  return typeof value?.[kData] === 'object' &&
         value?.[kType] === 'DatagramEvent';
}

function createDatagramEvent(buffer, session) {
  return ReflectConstruct(
    class extends Event {
      constructor() {
        super('datagram');
        this[kType] = 'DatagramEvent';
        this[kData] = {
          buffer,
          session,
        };
      }
    },
    [],
    DatagramEvent);
}

class SessionEvent extends Event {
  constructor() { throw new ERR_ILLEGAL_CONSTRUCTOR(); }

  get session() {
    if (!isSessionEvent(this))
      throw new ERR_INVALID_THIS('SessionEvent');
    return this[kData].session;
  }

  [kInspect](depth, options) {
    if (!isSessionEvent(this))
      throw new ERR_INVALID_THIS('SessionEvent');
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `${this[kType]} ${inspect({
      session: this[kData].session,
    }, opts)}`;
  }
}

ObjectDefineProperties(DatagramEvent.prototype, {
  session: kEnumerableProperty,
});

function isSessionEvent(value) {
  return typeof value?.[kData] === 'object' &&
         value?.[kType] === 'SessionEvent';
}

function createSessionEvent(session) {
  return ReflectConstruct(
    class extends Event {
      constructor() {
        super('session');
        this[kType] = 'SessionEvent';
        this[kData] = {
          session,
        };
      }
    },
    [],
    SessionEvent);
}

class StreamEvent extends Event {
  constructor() { throw new ERR_ILLEGAL_CONSTRUCTOR(); }

  get stream() {
    if (!isStreamEvent(this))
      throw new ERR_INVALID_THIS('StreamEvent');
    return this[kData].stream;
  }

  get respondWith() {
    if (!isStreamEvent(this))
      throw new ERR_INVALID_THIS('StreamEvent');
    return (response) => this[kData].stream.respondWith(response);
  }

  [kInspect](depth, options) {
    if (!isStreamEvent(this))
      throw new ERR_INVALID_THIS('StreamEvent');
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `${this[kType]} ${inspect({
      stream: this[kData].stream,
    }, opts)}`;
  }
}

ObjectDefineProperties(DatagramEvent.prototype, {
  stream: kEnumerableProperty,
  respondWith: kEnumerableProperty,
});

function isStreamEvent(value) {
  return typeof value?.[kData] === 'object' &&
         value?.[kType] === 'StreamEvent';
}

function createStreamEvent(stream) {
  return ReflectConstruct(
    class extends Event {
      constructor() {
        super('stream');
        this[kType] = 'StreamEvent';
        this[kData] = {
          stream,
        };
      }
    },
    [],
    StreamEvent);
}

function createLogStream(handle) {
  const readable = new Readable({
    read() {
      if (handle !== undefined)
        handle.readStart();
    },

    destroy() {
      handle[owner_symbol] = undefined;
      handle = undefined;
    },
  });
  readable[kUpdateTimer] = () => {};
  handle[owner_symbol] = readable;
  handle.onread = onStreamRead;
  return readable;
}

class StreamWritableSource extends Writable {
  constructor() {
    super();
    this[kHandle] = new StreamSource();
    this[kHandle][owner_symbol] = true;
  }

  _write(chunk, encoding, callback) {
    const self = this;
    function ondone(error) {
      if (error)
        self.destroy(error);
      callback(error);
    }

    return writeGeneric(this, chunk, encoding, ondone);
  }

  _writev(data, callback) {
    const self = this;
    function ondone(error) {
      if (error)
        self.destroy(error);
      callback(error);
    }

    return writevGeneric(this, data, ondone);
  }

  _final(callback) {
    const handle = this[kHandle];
    if (!handle) return callback();
    this[kHandle] = undefined;

    function ondone(status) {
      // TODO(@jasnell): Currently status is unused.
      callback();
    }

    const req = new ShutdownWrap();
    req.oncomplete = ondone;
    req.handle = handle;
    const err = handle.shutdown(req);
    if (err === 1)
      return FunctionPrototypeCall(ondone, req, [0]);
  }
}

// Used as the underlying source for a WritableStream
// TODO(@jasnell): Use the WritableStream StreamBase
// adapter here instead?
class WritableStreamSource {
  constructor() {
    this[kHandle] = new StreamSource();
    this[kHandle][owner_symbol] = this;
  }

  write(chunk) {
    const promise = createDeferredPromise();
    function ondone(error) {
      if (error) return promise.reject(error);
      promise.resolve();
    }
    // TODO(@jasnell): Support other types?
    if (!isArrayBufferView(chunk)) {
      promise.reject(
        new ERR_INVALID_ARG_TYPE(
          'chunk',
          [
            'TypedArray',
            'Buffer',
            'DataView',
          ],
          chunk));
    } else {
      writeGeneric(this, chunk, 'buffer', ondone);
    }
    return promise.promise;
  }

  close() {
    const handle = this[kHandle];
    if (!handle) return PromiseResolve();
    this[kHandle] = undefined;

    const promise = createDeferredPromise();

    function ondone(status) {
      // TODO(@jasnell): Currently status is unused.
      promise.resolve();
    }

    const req = new ShutdownWrap();
    req.oncomplete = ondone;
    req.handle = handle;
    const err = handle.shutdown(req);
    if (err === 1)
      promise.resolve();
    return promise.promise;
  }

  abort() {
    // Just defer to close, we don't need to do anything else here.
    return this.close();
  }
}

// Body here can be one of:
// 1. Undefined/null
// 2. String
// 3. ArrayBuffer
// 4. ArrayBufferView (TypedArray, Buffer, DataView)
// 5. Blob
// 6. stream.Readable
// 7. ReadableStream
// 8. FileHandle
// 9. A synchronous function returning 1-8
// 10. An asynchronous function resolving 1-8
//
// Regardless of what kind of thing body is, acquireBody
// always returns a promise that fulfills with the acceptable
// body value or rejects with an ERR_INVALID_ARG_TYPE.
function acquireBody(body) {
  if (typeof body === 'function') {
    try {
      body = FunctionPrototypeCall(body);
    } catch (error) {
      return PromiseReject(error);
    }
  }

  if (body == null)
    return PromiseResolve(undefined);

  // If body is a thenable, we're going to let it
  // fulfill then try acquireBody again on the result.
  // If the thenable rejects, go ahead and let that
  // bubble up to the caller for handling.
  if (typeof body.then === 'function') {
    return PromisePrototypeThen(
      isPromise(body) ? body : PromiseResolve(body),
      acquireBody);
  }

  if (typeof body === 'string') {
    const enc = new TextEncoder();
    return PromiseResolve(new ArrayBufferViewSource(enc.encode(body)));
  }

  if (isAnyArrayBuffer(body)) {
    return PromiseResolve(
      new ArrayBufferViewSource(
        new Uint8Array(body)));
  }

  if (isArrayBufferView(body))
    return PromiseResolve(new ArrayBufferViewSource(body));

  if (isBlob(body))
    return PromiseResolve(new BlobSource(body[kBlobHandle]));

  if (isFileHandle(body))
    return PromiseResolve(new StreamBaseSource(body[kFileHandle]));

  if (isReadableStream(body)) {
    const source = new WritableStreamSource();
    const writable = new Writable(source);
    source.writable = writable;
    // TODO(@jasnell): How to best surface this error?
    PromisePrototypeThen(
      body.pipeTo(writable),
      undefined,  // Do nothing on success
      (error) => {});  // What to do on error here?
    return PromiseResolve(source[kHandle]);
  }

  if (typeof body._readableState === 'object') {
    const promise = createDeferredPromise();
    const writable = new StreamWritableSource();
    pipeline(body, writable, (error) => {
      if (error) return promise.reject(error);
      promise.resolve();
    });
    // TODO(@jasnell): How to best surface this error?
    PromisePrototypeThen(
      promise.promise,
      undefined,  // Do nothing on success
      (error) => {});  // What to do on error here?
    return PromiseResolve(writable[kHandle]);
  }

  return PromiseReject(
    new ERR_INVALID_ARG_TYPE(
      'options.body',
      [
        'string',
        'ArrayBuffer',
        'TypedArray',
        'Buffer',
        'DataView',
        'Blob',
        'FileHandle',
        'ReadableStream',
        'stream.Readable',
        'Promise',
        'Function',
        'AsyncFunction',
      ],
      body));
}

function isPromisePending(promise) {
  if (promise === undefined) return false;
  const details = getPromiseDetails(promise);
  return details?.[0] === kPending;
}

function setPromiseHandled(promise) {
  PromisePrototypeThen(promise, undefined, () => {});
}

module.exports = {
  DatagramEvent,
  SessionEvent,
  StreamEvent,
  acquireBody,
  createDatagramEvent,
  createSessionEvent,
  createStreamEvent,
  createLogStream,
  isPromisePending,
  setPromiseHandled,
  kAddSession,
  kAddStream,
  kBlocked,
  kClientHello,
  kClose,
  kCreatedStream,
  kDestroy,
  kHandshakeComplete,
  kHeaders,
  kMaybeStreamEvent,
  kOCSP,
  kResetStream,
  kSessionTicket,
  kSetSource,
  kState,
  kType,
};
