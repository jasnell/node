'use strict';

/* eslint-disable no-use-before-define */

const {
  assertCrypto,
  customInspectSymbol: kInspect,
} = require('internal/util');

assertCrypto();

const {
  ArrayFrom,
  ArrayPrototypePush,
  BigInt64Array,
  Boolean,
  Error,
  FunctionPrototypeBind,
  FunctionPrototypeCall,
  Map,
  Number,
  ObjectSetPrototypeOf,
  Promise,
  PromiseAll,
  PromisePrototypeThen,
  PromisePrototypeCatch,
  PromisePrototypeFinally,
  PromiseReject,
  PromiseResolve,
  ReflectApply,
  SafeSet,
  Symbol,
  SymbolAsyncIterator,
  SymbolFor,
} = primordials;

const { Buffer } = require('buffer');
const { isArrayBufferView } = require('internal/util/types');
const {
  customInspect,
  getAllowUnauthorized,
  getSocketType,
  setTransportParams,
  setQuicSocketConfig,
  toggleListeners,
  validateNumber,
  validateTransportParams,
  validateQuicClientSessionOptions,
  validateQuicSocketOptions,
  validateQuicStreamOptions,
  validateQuicSocketListenOptions,
  validateCreateSecureContextOptions,
  validateQuicSocketConnectOptions,
  QuicStreamSharedState,
  QuicSocketSharedState,
  QuicSessionSharedState,
  QLogStream,
} = require('internal/quic/util');
const assert = require('internal/assert');
const { EventEmitter, once } = require('events');
const fs = require('fs');
const fsPromisesInternal = require('internal/fs/promises');
const { Duplex, Readable } = require('stream');
const {
  createSecureContext: _createSecureContext
} = require('tls');
const BlockList = require('internal/blocklist');
const {
  translatePeerCertificate
} = require('_tls_common');
const {
  defaultTriggerAsyncIdScope,
  symbols: {
    async_id_symbol,
    owner_symbol,
  },
} = require('internal/async_hooks');
const dgram = require('dgram');
const internalDgram = require('internal/dgram');
const {
  assertValidPseudoHeader,
  assertValidPseudoHeaderResponse,
  assertValidPseudoHeaderTrailer,
  mapToHeaders,
} = require('internal/http2/util');

const {
  constants: {
    UV_UDP_IPV6ONLY,
  }
} = internalBinding('udp_wrap');

const {
  writeGeneric,
  writevGeneric,
  onStreamRead,
  kAfterAsyncWrite,
  kMaybeDestroy,
  kUpdateTimer,
  kHandle,
  setStreamTimeout // eslint-disable-line no-unused-vars
} = require('internal/stream_base_commons');

const {
  ShutdownWrap,
  kReadBytesOrError,
  streamBaseState
} = internalBinding('stream_wrap');

const {
  codes: {
    ERR_ILLEGAL_CONSTRUCTOR,
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_STATE,
    ERR_OPERATION_FAILED,
    ERR_QUIC_FAILED_TO_CREATE_SESSION,
    ERR_QUIC_INVALID_REMOTE_TRANSPORT_PARAMS,
    ERR_QUIC_INVALID_TLS_SESSION_TICKET,
    ERR_QUIC_VERSION_NEGOTIATION,
    ERR_TLS_DH_PARAM_SIZE,
    ERR_UNKNOWN_ENCODING,
  },
  hideStackFrames,
  errnoException,
  exceptionWithHostPort
} = require('internal/errors');

const { FileHandle } = internalBinding('fs');
const { StreamPipe } = internalBinding('stream_pipe');
const { UV_EOF } = internalBinding('uv');

const {
  QuicSocket: QuicSocketHandle,
  JSQuicBufferConsumer,
  ArrayBufferViewSource,
  StreamSource,
  StreamBaseSource,
  initSecureContext,
  initSecureContextClient,
  createClientSession: _createClientSession,
  openStream: _openStream,
  setCallbacks,
  constants: {
    AF_INET6,
    NGTCP2_DEFAULT_MAX_PKTLEN,
    IDX_QUIC_SESSION_STATS_CREATED_AT,
    IDX_QUIC_SESSION_STATS_DESTROYED_AT,
    IDX_QUIC_SESSION_STATS_HANDSHAKE_START_AT,
    IDX_QUIC_SESSION_STATS_BYTES_RECEIVED,
    IDX_QUIC_SESSION_STATS_BYTES_SENT,
    IDX_QUIC_SESSION_STATS_BIDI_STREAM_COUNT,
    IDX_QUIC_SESSION_STATS_UNI_STREAM_COUNT,
    IDX_QUIC_SESSION_STATS_STREAMS_IN_COUNT,
    IDX_QUIC_SESSION_STATS_STREAMS_OUT_COUNT,
    IDX_QUIC_SESSION_STATS_KEYUPDATE_COUNT,
    IDX_QUIC_SESSION_STATS_LOSS_RETRANSMIT_COUNT,
    IDX_QUIC_SESSION_STATS_HANDSHAKE_COMPLETED_AT,
    IDX_QUIC_SESSION_STATS_ACK_DELAY_RETRANSMIT_COUNT,
    IDX_QUIC_SESSION_STATS_MAX_BYTES_IN_FLIGHT,
    IDX_QUIC_SESSION_STATS_BLOCK_COUNT,
    IDX_QUIC_SESSION_STATS_MIN_RTT,
    IDX_QUIC_SESSION_STATS_SMOOTHED_RTT,
    IDX_QUIC_SESSION_STATS_LATEST_RTT,
    IDX_QUIC_STREAM_STATS_CREATED_AT,
    IDX_QUIC_STREAM_STATS_DESTROYED_AT,
    IDX_QUIC_STREAM_STATS_BYTES_RECEIVED,
    IDX_QUIC_STREAM_STATS_BYTES_SENT,
    IDX_QUIC_STREAM_STATS_MAX_OFFSET,
    IDX_QUIC_STREAM_STATS_FINAL_SIZE,
    IDX_QUIC_STREAM_STATS_MAX_OFFSET_ACK,
    IDX_QUIC_STREAM_STATS_MAX_OFFSET_RECV,
    IDX_QUIC_SOCKET_STATS_CREATED_AT,
    IDX_QUIC_SOCKET_STATS_DESTROYED_AT,
    IDX_QUIC_SOCKET_STATS_BOUND_AT,
    IDX_QUIC_SOCKET_STATS_LISTEN_AT,
    IDX_QUIC_SOCKET_STATS_BYTES_RECEIVED,
    IDX_QUIC_SOCKET_STATS_BYTES_SENT,
    IDX_QUIC_SOCKET_STATS_PACKETS_RECEIVED,
    IDX_QUIC_SOCKET_STATS_PACKETS_IGNORED,
    IDX_QUIC_SOCKET_STATS_PACKETS_SENT,
    IDX_QUIC_SOCKET_STATS_SERVER_SESSIONS,
    IDX_QUIC_SOCKET_STATS_CLIENT_SESSIONS,
    IDX_QUIC_SOCKET_STATS_STATELESS_RESET_COUNT,
    IDX_QUIC_SOCKET_STATS_SERVER_BUSY_COUNT,
    ERR_FAILED_TO_CREATE_SESSION,
    ERR_INVALID_REMOTE_TRANSPORT_PARAMS,
    ERR_INVALID_TLS_SESSION_TICKET,
    NGTCP2_PATH_VALIDATION_RESULT_FAILURE,
    NGTCP2_NO_ERROR,
    QUIC_ERROR_APPLICATION,
    QUICSERVERSESSION_OPTION_REJECT_UNAUTHORIZED,
    QUICSERVERSESSION_OPTION_REQUEST_CERT,
    QUICCLIENTSESSION_OPTION_REQUEST_OCSP,
    QUICCLIENTSESSION_OPTION_VERIFY_HOSTNAME_IDENTITY,
    QUICSOCKET_OPTIONS_VALIDATE_ADDRESS,
    QUICSTREAM_HEADERS_KIND_NONE,
    QUICSTREAM_HEADERS_KIND_INFORMATIONAL,
    QUICSTREAM_HEADERS_KIND_INITIAL,
    QUICSTREAM_HEADERS_KIND_TRAILING,
    QUICSTREAM_HEADER_FLAGS_NONE,
    QUICSTREAM_HEADER_FLAGS_TERMINAL,
  }
} = internalBinding('quic');

const {
  Histogram,
  kDestroy: kDestroyHistogram
} = require('internal/histogram');

const {
  validateBoolean,
  validateInteger,
  validateObject,
} = require('internal/validators');

const emit = EventEmitter.prototype.emit;

const kAddSession = Symbol('kAddSession');
const kAddStream = Symbol('kAddStream');
const kAsyncCreate = Symbol('kAsyncCreateStream');
const kBind = Symbol('kBind');
const kBound = Symbol('kBound');
const kClose = Symbol('kClose');
const kClientHello = Symbol('kClientHello');
const kDestroy = Symbol('kDestroy');
const kHandleOcsp = Symbol('kHandleOcsp');
const kHandshake = Symbol('kHandshake');
const kHandshakeComplete = Symbol('kHandshakeComplete');
const kHandshakePost = Symbol('kHandshakePost');
const kHeaders = Symbol('kHeaders');
const kInternalState = Symbol('kInternalState');
const kInternalClientState = Symbol('kInternalClientState');
const kInternalServerState = Symbol('kInternalServerState');
const kIsReadOnly = Symbol('kIsReadOnly');
const kIsWriteOnly = Symbol('kIsWriteOnly');
const kListen = Symbol('kListen');
const kMaybeBind = Symbol('kMaybeBind');
const kOnFileOpened = Symbol('kOnFileOpened');
const kOnFileUnpipe = Symbol('kOnFileUnpipe');
const kOnPipedFileHandleRead = Symbol('kOnPipedFileHandleRead');
const kReady = Symbol('kReady');
const kRemoveFromSocket = Symbol('kRemoveFromSocket');
const kRemoveSession = Symbol('kRemove');
const kRemoveStream = Symbol('kRemoveStream');
const kServerBusy = Symbol('kServerBusy');
const kSetHandle = Symbol('kSetHandle');
const kSetQLogStream = Symbol('kSetQLogStream');
const kSetSocket = Symbol('kSetSocket');
const kStartFilePipe = Symbol('kStartFilePipe');
const kStreamClose = Symbol('kStreamClose');
const kStreamOptions = Symbol('kStreamOptions');
const kStreamReset = Symbol('kStreamReset');
const kSyncCreate = Symbol('kSyncCreateStream');
const kTrackWriteState = Symbol('kTrackWriteState');
const kUDPHandleForTesting = Symbol('kUDPHandleForTesting');
const kUsePreferredAddress = Symbol('kUsePreferredAddress');
const kVersionNegotiation = Symbol('kVersionNegotiation');
const kWriteGeneric = Symbol('kWriteGeneric');

const kRejections = SymbolFor('nodejs.rejection');

const kSocketUnbound = 0;
const kSocketPending = 1;
const kSocketBound = 2;
const kSocketDestroyed = 3;

let diagnosticPacketLossWarned = false;
let warnedVerifyHostnameIdentity = false;

let DOMException;

const lazyDOMException = hideStackFrames((message, name) => {
  if (DOMException === undefined)
    DOMException = internalBinding('messaging').DOMException;
  return new DOMException(message, name);
});

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

assert(process.versions.ngtcp2 !== undefined);

// Called by the C++ internals when the QuicSocket is closed with
// or without an error. The only thing left to do is destroy the
// QuicSocket instance.
function onSocketClose(err) {
  this[owner_symbol].destroy(err != null ? errnoException(err) : undefined);
}

// Called by the C++ internals when the server busy state of
// the QuicSocket has been changed.
function onSocketServerBusy() {
  this[owner_symbol][kServerBusy]();
}

// Called by the C++ internals when a new server QuicSession has been created.
function onSessionReady(handle) {
  const socket = this[owner_symbol];
  const session =
    new QuicServerSession(
      socket,
      handle,
      socket[kStreamOptions]);
  try {
    socket.emit('session', session);
  } catch (error) {
    socket[kRejections](error, 'session', session);
  }
}

// Called when the C++ QuicSession::Close() method has been called.
// Synchronously cleanup and destroy the JavaScript QuicSession.
function onSessionClose(code, family, silent, statelessReset) {
  this[owner_symbol][kDestroy](code, family, silent, statelessReset);
}

// This callback is invoked for server sessions at the start of the TLS
// handshake to provide ome basic information about the ALPN, SNI, and
// ciphers that are being requested. It is only called if the
// 'clientHelloHandler' option is specified on listen(). The [kClientHello]
// promise can resolve a new replacement SecureContext if necessary.
// If a new SecureContext is provided, it will be used to continue the
// TLS handshake. The TLS handshake is paused while the promise is
// pending. If the promise rejects, the session will be destroyed and
// the TLS handshake will be abandoned.
function onSessionClientHello(alpn, servername, ciphers) {
  PromisePrototypeThen(
    this[owner_symbol][kClientHello](alpn, servername, ciphers),
    (context) => {
      if (context !== undefined && !context?.context)
        throw new ERR_INVALID_ARG_TYPE('context', 'SecureContext', context);
      this.onClientHelloDone(context?.context);
    },
    (error) => this[owner_symbol].destroy(error)
  );
}

// This callback is only ever invoked for QuicServerSession instances,
// and is used to trigger OCSP request processing when needed. The
// kHandleOcsp async function returns a promise that resolves the
// response OCSP data, if any. The response must be either a string,
// TypedArray or DataView. Strings will be converted to a Buffer
// using utf8 encoding. When called, the TLS handshake will be
// paused while the [kHandleOcsp] promise is pending. The handshake
// will resume when onCertDone is called, or if there is an error
// the session will be destroyed and the TLS handshake will be
// abandoned.
function onSessionCert(servername) {
  PromisePrototypeThen(
    this[owner_symbol][kHandleOcsp](servername),
    (data) => {
      if (data !== undefined) {
        if (typeof data === 'string')
          data = Buffer.from(data);
        if (!isArrayBufferView(data)) {
          throw new ERR_INVALID_ARG_TYPE(
            'data',
            ['string', 'Buffer', 'TypedArray', 'DataView'],
            data);
        }
      }
      this.onCertDone(data);
    },
    (error) => this[owner_symbol].destroy(error)
  );
}

// This callback is only ever invoked for QuicClientSession instances,
// and is used to deliver the OCSP response as provided by the server.
// If the requestOCSP configuration option is false, this will never
// be called. If the [kHandleOcsp] promise rejects, the session will be
// destroyed.
function onSessionStatus(data) {
  PromisePrototypeCatch(
    this[owner_symbol][kHandleOcsp](data),
    (error) => this[owner_symbol].destroy(error)
  );
}

// Called by the C++ internals when the TLS handshake is completed.
function onSessionHandshake(
  servername,
  alpn,
  cipher,
  cipherVersion,
  maxPacketLength,
  verifyErrorReason,
  verifyErrorCode,
  earlyData) {
  this[owner_symbol][kHandshake](
    servername,
    alpn,
    cipher,
    cipherVersion,
    maxPacketLength,
    verifyErrorReason,
    verifyErrorCode,
    earlyData);
}

// Called by the C++ internals when TLS session ticket data is
// available. This is generally most useful on the client side
// where the session ticket needs to be persisted for session
// resumption and 0RTT.
function onSessionTicket(sessionTicket, transportParams) {
  if (this[owner_symbol]) {
    process.nextTick(FunctionPrototypeBind(
      emit,
      this[owner_symbol],
      'sessionTicket',
      sessionTicket,
      transportParams
    ));
  }
}

// Called by the C++ internals when path validation is completed.
// This is a purely informational event that is emitted only when
// there is a listener present for the pathValidation event.
function onSessionPathValidation(res, local, remote) {
  const session = this[owner_symbol];
  if (session) {
    process.nextTick(FunctionPrototypeBind(
      emit,
      session,
      'pathValidation',
      res === NGTCP2_PATH_VALIDATION_RESULT_FAILURE ? 'failure' : 'success',
      local,
      remote
    ));
  }
}

function onSessionUsePreferredAddress(address, port, family) {
  const session = this[owner_symbol];
  session[kUsePreferredAddress](
    address,
    port,
    family === AF_INET6 ? 'udp6' : 'udp4');
}

// Called by the C++ internals to emit a QLog record. This can
// be called before the QuicSession has been fully initialized,
// in which case we store a reference and defer emitting the
// qlog event until after we're initialized.
function onSessionQlog(handle) {
  const session = this[owner_symbol];
  const stream = new QLogStream(handle);
  if (session)
    session[kSetQLogStream](stream);
  else
    this.qlogStream = stream;
}

// Called by the C++ internals when a client QuicSession receives
// a version negotiation response from the server.
function onSessionVersionNegotiation(
  version,
  requestedVersions,
  supportedVersions) {
  if (this[owner_symbol]) {
    this[owner_symbol][kVersionNegotiation](
      version,
      requestedVersions,
      supportedVersions);
  }
}

// Called by the C++ internals to emit keylogging details for a
// QuicSession.
function onSessionKeylog(line) {
  if (this[owner_symbol])
    this[owner_symbol].emit('keylog', line);
}

// Called by the C++ internals when a new QuicStream has been created.
function onStreamReady(handle) {
  const session = this[owner_symbol];
  const stream = QuicStream[kSyncCreate](session, handle);
  process.nextTick(() => {
    try {
      session.emit('stream', stream);
    } catch (error) {
      stream.destroy(error);
    }
  });
}

// Called by the C++ internals when a stream is closed and
// needs to be destroyed on the JavaScript side.
function onStreamClose(id, appErrorCode) {
  this[owner_symbol][kStreamClose](id, appErrorCode);
}

// Called by the C++ internals when a stream has been reset
function onStreamReset(id, appErrorCode) {
  this[owner_symbol][kStreamReset](id, appErrorCode);
}

// Called when an error occurs in a QuicStream
function onStreamError(streamHandle, error) {
  streamHandle[owner_symbol].destroy(error);
}

// Called when a block of headers has been fully
// received for the stream. Not all QuicStreams
// will support headers. The headers argument
// here is an Array of name-value pairs.
function onStreamHeaders(id, headers, kind) {
  this[owner_symbol][kHeaders](id, headers, kind);
}

// When a stream is flow control blocked, causes a blocked event
// to be emitted. This is a purely informational event.
function onStreamBlocked() {
  process.nextTick(FunctionPrototypeBind(emit, this[owner_symbol], 'blocked'));
}

// Register the callbacks with the QUIC internal binding.
// The native layer will call these whenever it needs to
// pass data back to the JavaScript side. These must be
// synchronous functions.
setCallbacks({
  onSessionCert,
  onSessionClientHello,
  onSessionClose,
  onSessionHandshake,
  onSessionKeylog,
  onSessionPathValidation,
  onSessionQlog,
  onSessionReady,
  onSessionStatus,
  onSessionTicket,
  onSessionUsePreferredAddress,
  onSessionVersionNegotiation,
  onSocketClose,
  onSocketServerBusy,
  onStreamBlocked,
  onStreamClose,
  onStreamHeaders,
  onStreamError,
  onStreamReady,
  onStreamReset,
});

// Creates the SecureContext used by QuicSocket instances that are listening
// for new connections.
function createSecureContext(options, init_cb) {
  const sc_options = validateCreateSecureContextOptions(options);
  const { groups, earlyData } = sc_options;
  const sc = _createSecureContext(sc_options);
  init_cb(sc.context, groups, earlyData);
  return sc;
}

function onNewListener(event) {
  toggleListeners(this[kInternalState].state, event, true);
}

function onRemoveListener(event) {
  toggleListeners(this[kInternalState].state, event, false);
}

function getStats(obj, idx) {
  const stats = obj[kHandle]?.stats || obj[kInternalState].stats;
  // If stats is undefined at this point, it's just a bug
  assert(stats);
  return stats[idx];
}

function addressOrLocalhost(address, type) {
  return address || (type === AF_INET6 ? '::' : '0.0.0.0');
}

function deferredClosePromise(state) {
  const { promise, resolve, reject } = deferred();
  state.closePromise = promise;
  state.closePromiseResolve = resolve;
  state.closePromiseReject = reject;
  return PromisePrototypeFinally(promise, () => {
    state.closePromise = undefined;
    state.closePromiseResolve = undefined;
    state.closePromiseReject = undefined;
  });
}

async function resolvePreferredAddress(lookup, preferredAddress) {
  if (preferredAddress === undefined)
    return {};
  const {
    address,
    port,
    type = 'udp4'
  } = { ...preferredAddress };
  const [typeVal] = getSocketType(type);
  const {
    address: ip
  } = await lookup(address, typeVal === AF_INET6 ? 6 : 4);
  return { ip, port, type };
}

// QuicSocket wraps a UDP socket plus the associated TLS context and QUIC
// Protocol state. There may be *multiple* QUIC connections (QuicSession)
// associated with a single QuicSocket.
class QuicSocket extends EventEmitter {
  [kInternalState] = {
    alpn: undefined,
    bindPromise: undefined,
    blockList: undefined,
    client: undefined,
    closePromise: undefined,
    closePromiseResolve: undefined,
    closePromiseReject: undefined,
    defaultEncoding: undefined,
    highWaterMark: undefined,
    listenPending: false,
    listenPromise: undefined,
    lookup: undefined,
    ocspHandler: undefined,
    clientHelloHandler: undefined,
    server: undefined,
    serverSecureContext: undefined,
    sessions: new SafeSet(),
    state: kSocketUnbound,
    sharedState: undefined,
    stats: undefined,
    udpSocket: undefined,
    ipv6Only: undefined,
    port: undefined,
    type: undefined,
    fd: undefined,
  };

  constructor(options) {
    const {
      // The local address to bind to. This may be an IPv4, IPv6, or
      // hostname. If a host name is given, it will be resolved to
      // an IP address.
      address,

      // The local port to bind to.
      port,

      // The local UDP type (IPv4 or IPv6)
      type,

      // True if the UDP port should use IPv6 only without
      // dual-stack mode enabled.
      ipv6Only,

      // Default configuration for QuicClientSessions
      client,

      // The maximum number of connections
      maxConnections,

      // The maximum number of connections per host
      maxConnectionsPerHost,

      // The maximum number of stateless resets per host
      maxStatelessResetsPerHost,

      // The maximum number of seconds for retry token
      retryTokenTimeout,

      // The DNS lookup function
      lookup,

      // Default configuration for QuicServerSessions
      server,

      // True if address verification should be used.
      validateAddress,

      // Whether qlog should be enabled for sessions
      qlog,

      // Stateless reset token secret (16 byte buffer)
      statelessResetSecret,

      // When true, stateless resets will not be sent (default false)
      disableStatelessReset,
    } = validateQuicSocketOptions(options);
    super({ captureRejections: true });

    const state = this[kInternalState];
    state.client = client;
    state.server = server;
    state.lookup = lookup;
    state.address = addressOrLocalhost(address, type);
    state.ipv6Only = ipv6Only;
    state.port = port;
    state.type = type;
    state.udpSocket = dgram.createSocket(type === AF_INET6 ? 'udp6' : 'udp4');

    let socketOptions = 0;
    if (validateAddress)
      socketOptions |= (1 << QUICSOCKET_OPTIONS_VALIDATE_ADDRESS);

    setQuicSocketConfig({
      disableStatelessReset,
      maxConnections,
      maxConnectionsPerHost,
      maxStatelessResetsPerHost,
      retryTokenTimeout,
      socketOptions,
      qlog,
    });

    // kUDPHandleForTesting is only used in the Node.js test suite to
    // artificially test the socket. This code path should never be
    // used in user code.
    if (typeof options?.[kUDPHandleForTesting] === 'object') {
      state.udpSocket.bind(options[kUDPHandleForTesting]);
      state.state = kSocketBound;
      this[kBound]();
    }

    this[kSetHandle](
      new QuicSocketHandle(
        state.udpSocket[internalDgram.kStateSymbol].handle,
        statelessResetSecret));
  }

  [kRejections](err, eventname, ...args) {
    switch (eventname) {
      case 'session':
        const session = args[0];
        session.destroy(err);
        process.nextTick(() => {
          this.emit('sessionError', err, session);
        });
        return;
      default:
        // Fall through
    }
    this.destroy(err);
  }

  get [kStreamOptions]() {
    const state = this[kInternalState];
    return {
      highWaterMark: state.highWaterMark,
      defaultEncoding: state.defaultEncoding,
      ocspHandler: state.ocspHandler,
      clientHelloHandler: state.clientHelloHandler,
      context: state.serverSecureContext,
    };
  }

  [kSetHandle](handle) {
    this[kHandle] = handle;
    if (handle !== undefined) {
      handle[owner_symbol] = this;
      this[async_id_symbol] = handle.getAsyncId();
      this[kInternalState].sharedState =
        new QuicSocketSharedState(handle.state);
      this[kInternalState].blockList = new BlockList(handle.blockList);
    } else {
      this[kInternalState].sharedState = undefined;
      this[kInternalState].blockList = undefined;
    }
  }

  [kInspect](depth, options) {
    const state = this[kInternalState];
    return customInspect(this, {
      address: this.address,
      fd: this.fd,
      type: this[kInternalState].type === AF_INET6 ? 'udp6' : 'udp4',
      sessions: ArrayFrom(state.sessions),
      bound: this.bound,
      pending: this.pending,
      closing: this.closing,
      destroyed: this.destroyed,
      listening: this.listening,
      serverBusy: this.serverBusy,
      statelessResetDisabled: this.statelessResetDisabled,
    }, depth, options);
  }

  [kAddSession](session) {
    this[kInternalState].sessions.add(session);
  }

  [kRemoveSession](session) {
    const state = this[kInternalState];
    state.sessions.delete(session);
    if (this.closing && state.sessions.size === 0)
      this.destroy();
  }

  [kMaybeBind](options) {
    const state = this[kInternalState];
    if (state.bindPromise !== undefined)
      return state.bindPromise;

    return state.bindPromise = PromisePrototypeFinally(
      this[kBind](options),
      () => {
        state.bindPromise = undefined;
      }
    );
  }

  async [kBind](options) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');

    const state = this[kInternalState];
    if (state.state === kSocketBound)
      return;

    const { signal } = { ...options };
    if (signal != null && !('aborted' in signal))
      throw new ERR_INVALID_ARG_TYPE('options.signal', 'AbortSignal', signal);

    // If an AbotSignal was passed in, check to make sure it is not already
    // aborted before we continue on to do any work.
    if (signal?.aborted)
      throw new lazyDOMException('The operation was aborted', 'AbortError');

    state.state = kSocketPending;

    // TODO(@jasnell): The DNS lookup does not yet support cancelation
    // using the AbortSignal. Later when it does, pass the signal in.
    const {
      address: ip
    } = await state.lookup(state.address, state.type === AF_INET6 ? 6 : 4);

    // It's possible for the QuicSocket to have been destroyed while
    // we were waiting for the DNS lookup to complete. If so, reject
    // the Promise.
    if (this.destroyed) {
      state.state = kSocketUnbound;
      throw new ERR_INVALID_STATE('QuicSocket was destroyed');
    }

    // Check to see if the AbortSignal was triggered while we were waiting
    // for the DNS lookup to complete.
    if (signal?.aborted) {
      state.state = kSocketUnbound;
      throw new lazyDOMException('The operation was aborted', 'AbortError');
    }

    const udpHandle = state.udpSocket[internalDgram.kStateSymbol].handle;
    if (udpHandle == null) {
      state.state = kSocketUnbound;
      throw new ERR_OPERATION_FAILED('Acquiring the UDP socket handle failed');
    }

    try {
      const ret =
        udpHandle.bind(
          ip,
          state.port,
          state.ipv6Only ? UV_UDP_IPV6ONLY : 0);
      if (ret) {
        state.state = kSocketUnbound;
        throw exceptionWithHostPort(ret, 'bind', ip, state.port);
      }

      // On Windows, the fd will be meaningless, but we always record it.
      state.fd = udpHandle.fd;
      state.state = kSocketBound;

      process.nextTick(() => {
        // User code may have run before this so we need to check the
        // destroyed state. If it has been destroyed, do nothing.
        if (this.destroyed)
          return;
        try {
          this.emit('ready');
        } catch (error) {
          state.state = kSocketUnbound;
          this.destroy(error);
        }
      });
    } catch (error) {
      state.state = kSocketUnbound;
      this.destroy(error);
      throw error;
    }
  }

  // Currently only used for testing when the QuicSocket is bound immediately.
  [kBound]() {
    const state = this[kInternalState];
    if (state.state === kSocketBound)
      return;
    state.state = kSocketBound;

    // The ready event indicates that the QuicSocket is ready to be
    // used to either listen or connect. No QuicServerSession should
    // exist before this event, and all QuicClientSession will remain
    // in Initial states until ready is invoked.
    process.nextTick(() => {
      try {
        this.emit('ready');
      } catch (error) {
        this.destroy(error);
      }
    });
  }

  // Called by the C++ internals to notify when server busy status is toggled.
  [kServerBusy]() {
    const busy = this.serverBusy;
    process.nextTick(() => {
      try {
        this.emit('busy', busy);
      } catch (error) {
        this[kRejections](error, 'busy', busy);
      }
    });
  }

  listen(options) {
    const state = this[kInternalState];
    if (state.listenPromise !== undefined)
      return state.listenPromise;

    return state.listenPromise = PromisePrototypeFinally(
      this[kListen](options),
      () => {
        state.listenPromise = undefined;
      }
    );
  }

  async [kListen](options) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');
    if (this.listening)
      throw new ERR_INVALID_STATE('QuicSocket is already listening');

    options = {
      ...state.server,
      ...options,
    };

    // The ALPN protocol identifier is strictly required.
    const {
      alpn,
      lookup = state.lookup,
      defaultEncoding,
      highWaterMark,
      ocspHandler,
      clientHelloHandler,
      transportParams,
    } = validateQuicSocketListenOptions(options);

    state.serverSecureContext =
      createSecureContext({
        ...options,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
      }, initSecureContext);
    state.highWaterMark = highWaterMark;
    state.defaultEncoding = defaultEncoding;
    state.alpn = alpn;
    state.listenPending = true;
    state.ocspHandler = ocspHandler;
    state.clientHelloHandler = clientHelloHandler;

    await this[kMaybeBind]();

    // It's possible that the QuicSocket was destroyed or closed while
    // the bind was pending. Check for that and handle accordingly.
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket was destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');

    const {
      ip,
      port,
      type
    } = await resolvePreferredAddress(lookup, transportParams.preferredAddress);

    // It's possible that the QuicSocket was destroyed or closed while
    // the preferred address resolution was pending. Check for that and handle
    // accordingly.
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket was destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');

    const {
      rejectUnauthorized = !getAllowUnauthorized(),
      requestCert = false,
    } = transportParams;

    // Transport Parameters are passed to the C++ side using a shared array.
    // These are the transport parameters that will be used when a new
    // server QuicSession is established. They are transmitted to the client
    // as part of the server's initial TLS handshake. Once they are set, they
    // cannot be modified.
    setTransportParams(transportParams);

    // When the handle is told to listen, it will begin acting as a QUIC
    // server and will emit session events whenever a new QuicServerSession
    // is created.
    state.listenPending = false;
    this[kHandle].listen(
      state.serverSecureContext.context,
      ip,         // Preferred address ip,
      type,       // Preferred address type,
      port,       // Preferred address port,
      state.alpn,
      (rejectUnauthorized ? QUICSERVERSESSION_OPTION_REJECT_UNAUTHORIZED : 0) |
      (requestCert ? QUICSERVERSESSION_OPTION_REQUEST_CERT : 0));

    process.nextTick(() => {
      // It's remotely possible the QuicSocket is be destroyed or closed
      // while the nextTick is pending. If that happens, do nothing.
      if (this.destroyed || this.closing)
        return;
      try {
        this.emit('listening');
      } catch (error) {
        this.destroy(error);
      }
    });
  }

  async connect(options) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');

    options = {
      ...state.client,
      ...options
    };

    const {
      type,
      address,
      lookup = state.lookup
    } = validateQuicSocketConnectOptions(options);

    await this[kMaybeBind]();

    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket was destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');

    const {
      address: ip
    } = await lookup(addressOrLocalhost(address, type),
                     type === AF_INET6 ? 6 : 4);

    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket was destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');

    if (this.blockList.check(ip, type === AF_INET6 ? 'ipv6' : 'ipv4'))
      throw new ERR_OPERATION_FAILED(`${ip} failed BlockList check`);

    return new QuicClientSession(this, options, type, ip);
  }

  // Initiate a Graceful Close of the QuicSocket.
  // Existing QuicClientSession and QuicServerSession instances will be
  // permitted to close naturally and gracefully on their own.
  // The QuicSocket will be immediately closed and freed as soon as there
  // are no additional session instances remaining. If there are no
  // QuicClientSession or QuicServerSession instances, the QuicSocket
  // will be immediately closed.
  //
  // Returns a Promise that will be resolved once the QuicSocket is
  // destroyed.
  //
  // No additional QuicServerSession instances will be accepted from
  // remote peers, and calls to connect() to create QuicClientSession
  // instances will fail. The QuicSocket will be otherwise usable in
  // every other way.
  //
  // Once initiated, a graceful close cannot be canceled. The graceful
  // close can be interupted, however, by abruptly destroying the
  // QuicSocket using the destroy() method.
  //
  // If close() is called before the QuicSocket has been bound (before
  // either connect() or listen() have been called, or the QuicSocket
  // is still in the pending state, the QuicSocket is destroyed
  // immediately.
  close() {
    return this[kInternalState].closePromise || this[kClose]();
  }

  [kClose]() {
    if (this.destroyed) {
      return PromiseReject(
        new ERR_INVALID_STATE('QuicSocket is already destroyed'));
    }
    const state = this[kInternalState];
    const promise = deferredClosePromise(state);

    // Tell the underlying QuicSocket C++ object to stop
    // listening for new QuicServerSession connections.
    // New initial connection packets for currently unknown
    // DCID's will be ignored.
    if (this[kHandle])
      state.sharedState.serverListening = false;

    // If the QuicSocket is otherwise not bound to the local
    // port, or there are not active sessions, destroy the
    // QuicSocket immediately and we're done.
    if (state.state !== kSocketBound || state.sessions.size === 0) {
      this.destroy();
      return promise;
    }

    // Otherwise, loop through each of the known sessions and close them.
    const reqs = [promise];
    for (const session of state.sessions) {
      ArrayPrototypePush(reqs,
                         PromisePrototypeCatch(session.close(),
                                               (error) => this.destroy(error)));
    }
    return PromiseAll(reqs);
  }

  // Initiate an abrupt close and destruction of the QuicSocket.
  // Existing QuicClientSession and QuicServerSession instances will be
  // immediately closed. If error is specified, it will be forwarded
  // to each of the session instances.
  //
  // When the session instances are closed, an attempt to send a final
  // CONNECTION_CLOSE will be made.
  //
  // The JavaScript QuicSocket object will be marked destroyed and will
  // become unusable. As soon as all pending outbound UDP packets are
  // flushed from the QuicSocket's queue, the QuicSocket C++ instance
  // will be destroyed and freed from memory.
  destroy(error) {
    const state = this[kInternalState];
    // If the QuicSocket is already destroyed, do nothing
    if (state.state === kSocketDestroyed)
      return;

    // Mark the QuicSocket as being destroyed.
    state.state = kSocketDestroyed;
    this[kHandle].stats[IDX_QUIC_SOCKET_STATS_DESTROYED_AT] =
      process.hrtime.bigint();
    state.stats = new BigInt64Array(this[kHandle].stats);

    // Immediately close any sessions that may be remaining.
    // If the udp socket is in a state where it is able to do so,
    // a final attempt to send CONNECTION_CLOSE frames for each
    // closed session will be made.
    for (const session of state.sessions)
      session.destroy(error);

    this[kHandle].ondone = () => {
      state.udpSocket.close((err) => {
        if (err) error = err;
        if (error && typeof state.closePromiseReject === 'function')
          state.closePromiseReject(error);
        else if (typeof state.closePromiseResolve === 'function')
          state.closePromiseResolve();
        this[kDestroy](error);
      });
    };
    this[kHandle].waitForPendingCallbacks();
  }

  [kDestroy](error) {
    const state = this[kInternalState];
    state.udpSocket = undefined;
    this[kHandle] = undefined;

    if (error) {
      if (typeof state.closePromiseReject === 'function')
        state.closePromiseReject(error);
      process.nextTick(FunctionPrototypeBind(emit, this, 'error', error));
    } else if (typeof state.closePromiseResolve === 'function') {
      state.closePromiseResolve();
    }
    process.nextTick(FunctionPrototypeBind(emit, this, 'close'));
  }

  setTTL(ttl) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.setTTL(ttl);
    return this;
  }

  setMulticastTTL(ttl) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.setMulticastTTL(ttl);
    return this;
  }

  setBroadcast(on = true) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.setBroadcast(on);
    return this;
  }

  setMulticastLoopback(on = true) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.setMulticastLoopback(on);
    return this;
  }

  setMulticastInterface(iface) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.setMulticastInterface(iface);
    return this;
  }

  addMembership(address, iface) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.addMembership(address, iface);
    return this;
  }

  dropMembership(address, iface) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.dropMembership(address, iface);
    return this;
  }

  ref() {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.ref();
    return this;
  }

  unref() {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    state.udpSocket.unref();
    return this;
  }

  get blockList() {
    return this[kInternalState]?.blockList;
  }

  get address() {
    const state = this[kInternalState];
    if (state.state !== kSocketDestroyed) {
      try {
        return state.udpSocket.address();
      } catch (err) {
        if (err.code === 'EBADF') {
          // If there is an EBADF error, the socket is not bound.
          // Return empty object. Else, rethrow the error because
          // something else bad happened.
          return {};
        }
        throw err;
      }
    }
    return {};
  }

  // On Windows, this always returns undefined.
  get fd() {
    return this[kInternalState].fd >= 0 ?
      this[kInternalState].fd : undefined;
  }

  get serverSecureContext() {
    return this[kInternalState].serverSecureContext;
  }

  // True if the QuicSocket has been bound to a local UDP port
  get bound() {
    return this[kInternalState].state === kSocketBound;
  }

  // True if graceful close has been initiated by calling close()
  get closing() {
    return this[kInternalState].closePromise !== undefined;
  }

  // True if the QuicSocket has been destroyed and is no longer usable
  get destroyed() {
    return this[kInternalState].state === kSocketDestroyed;
  }

  // True if listen() has been called successfully
  get listening() {
    return Boolean(this[kInternalState].sharedState?.serverListening);
  }

  // True if the QuicSocket is in the process of binding to a local
  // UDP port.
  get pending() {
    return this[kInternalState].state === kSocketPending;
  }

  // Marking a server as busy will cause all new
  // connection attempts to fail with a SERVER_BUSY CONNECTION_CLOSE.
  set serverBusy(on) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    validateBoolean(on, 'on');
    if (state.sharedState.serverBusy !== on) {
      state.sharedState.serverBusy = on;
      this[kServerBusy]();
    }
  }

  get serverBusy() {
    return Boolean(this[kInternalState].sharedState?.serverBusy);
  }

  set statelessResetDisabled(on) {
    const state = this[kInternalState];
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    validateBoolean(on, 'on');
    if (state.sharedState.statelessResetDisabled !== on)
      state.sharedState.statelessResetDisabled = on;
  }

  get statelessResetDisabled() {
    return Boolean(this[kInternalState].sharedState?.statelessResetDisabled);
  }

  get duration() {
    const end = getStats(this, IDX_QUIC_SOCKET_STATS_DESTROYED_AT) ||
                process.hrtime.bigint();
    return Number(end - getStats(this, IDX_QUIC_SOCKET_STATS_CREATED_AT));
  }

  get boundDuration() {
    const end = getStats(this, IDX_QUIC_SOCKET_STATS_DESTROYED_AT) ||
                process.hrtime.bigint();
    return Number(end - getStats(this, IDX_QUIC_SOCKET_STATS_BOUND_AT));
  }

  get listenDuration() {
    const end = getStats(this, IDX_QUIC_SOCKET_STATS_DESTROYED_AT) ||
                process.hrtime.bigint();
    return Number(end - getStats(this, IDX_QUIC_SOCKET_STATS_LISTEN_AT));
  }

  get bytesReceived() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_BYTES_RECEIVED));
  }

  get bytesSent() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_BYTES_SENT));
  }

  get packetsReceived() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_PACKETS_RECEIVED));
  }

  get packetsSent() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_PACKETS_SENT));
  }

  get packetsIgnored() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_PACKETS_IGNORED));
  }

  get serverSessions() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_SERVER_SESSIONS));
  }

  get clientSessions() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_CLIENT_SESSIONS));
  }

  get statelessResetCount() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_STATELESS_RESET_COUNT));
  }

  get serverBusyCount() {
    return Number(getStats(this, IDX_QUIC_SOCKET_STATS_SERVER_BUSY_COUNT));
  }

  // Diagnostic packet loss is a testing mechanism that allows simulating
  // pseudo-random packet loss for rx or tx. The value specified for each
  // option is a number between 0 and 1 that identifies the possibility of
  // packet loss in the given direction.
  setDiagnosticPacketLoss(options) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    const {
      rx = 0.0,
      tx = 0.0
    } = { ...options };
    validateNumber(
      rx,
      'options.rx',
      /* min */ 0.0,
      /* max */ 1.0);
    validateNumber(
      tx,
      'options.tx',
      /* min */ 0.0,
      /* max */ 1.0);
    if ((rx > 0.0 || tx > 0.0) && !diagnosticPacketLossWarned) {
      diagnosticPacketLossWarned = true;
      process.emitWarning(
        'QuicSocket diagnostic packet loss is enabled. Received or ' +
        'transmitted packets will be randomly ignored to simulate ' +
        'network packet loss.');
    }
    this[kHandle].setDiagnosticPacketLoss(rx, tx);
  }
}

class QuicSession extends EventEmitter {
  [kInternalState] = {
    alpn: undefined,
    cipher: undefined,
    cipherVersion: undefined,
    clientHelloHandler: undefined,
    closeCode: NGTCP2_NO_ERROR,
    closeFamily: QUIC_ERROR_APPLICATION,
    closePromise: undefined,
    closePromiseResolve: undefined,
    closePromiseReject: undefined,
    destroyed: false,
    earlyData: false,
    handshakeComplete: false,
    handshakeCompletePromise: undefined,
    handshakeCompletePromiseResolve: undefined,
    handshakeCompletePromiseReject: undefined,
    idleTimeout: false,
    maxPacketLength: NGTCP2_DEFAULT_MAX_PKTLEN,
    ocspHandler: undefined,
    servername: undefined,
    socket: undefined,
    silentClose: false,
    statelessReset: false,
    stats: undefined,
    streams: new Map(),
    verifyErrorReason: undefined,
    verifyErrorCode: undefined,
    handshakeAckHistogram: undefined,
    handshakeContinuationHistogram: undefined,
    highWaterMark: undefined,
    defaultEncoding: undefined,
    state: undefined,
    qlogStream: undefined,
  };

  constructor(socket, options) {
    const {
      alpn,
      servername,
      highWaterMark,
      defaultEncoding,
      ocspHandler,
      clientHelloHandler,
    } = options;
    super({ captureRejections: true });
    this.on('newListener', onNewListener);
    this.on('removeListener', onRemoveListener);
    const state = this[kInternalState];
    state.socket = socket;
    state.servername = servername;
    state.alpn = alpn;
    state.highWaterMark = highWaterMark;
    state.defaultEncoding = defaultEncoding;
    state.ocspHandler = ocspHandler;
    state.clientHelloHandler = clientHelloHandler;
    socket[kAddSession](this);
  }

  [kRejections](err, eventname, ...args) {
    this.destroy(err);
  }

  // Used to get the configured options for peer initiated QuicStream
  // instances.
  get [kStreamOptions]() {
    const state = this[kInternalState];
    return {
      highWaterMark: state.highWaterMark,
      defaultEncoding: state.defaultEncoding,
    };
  }

  [kSetQLogStream](stream) {
    const state = this[kInternalState];
    state.qlogStream = stream;
    process.nextTick(() => {
      try {
        this.emit('qlog', state.qlogStream);
      } catch (error) {
        this.destroy(error);
      } finally {
        // The qlog event will only ever be emitted once.
        // Release the references to the listeners.
        this.removeAllListeners('qlog');
      }
    });
  }

  [kHandshakeComplete]() {
    const state = this[kInternalState];
    if (state.handshakeComplete)
      return PromiseResolve();

    if (state.handshakeCompletePromise !== undefined)
      return state.handshakeCompletePromise;

    state.handshakeCompletePromise = PromisePrototypeFinally(
      new Promise((resolve, reject) => {
        state.handshakeCompletePromiseResolve = resolve;
        state.handshakeCompletePromiseReject = reject;
      }),
      () => {
        state.handshakeCompletePromise = undefined;
        state.handshakeCompletePromiseReject = undefined;
        state.handshakeCompletePromiseResolve = undefined;
      }
    );

    return state.handshakeCompletePromise;
  }

  // Sets the internal handle for the QuicSession instance. For
  // server QuicSessions, this is called immediately as the
  // handle is created before the QuicServerSession JS object.
  // For client QuicSession instances, the connect() method
  // must first perform DNS resolution on the provided address
  // before the underlying QuicSession handle can be created.
  [kSetHandle](handle) {
    const state = this[kInternalState];
    this[kHandle] = handle;
    if (handle !== undefined) {
      handle[owner_symbol] = this;
      state.state = new QuicSessionSharedState(handle.state);
      state.handshakeAckHistogram = new Histogram(handle.ack);
      state.handshakeContinuationHistogram = new Histogram(handle.rate);
      state.state.ocspEnabled = state.ocspHandler !== undefined;
      state.state.clientHelloEnabled = state.clientHelloHandler !== undefined;
      if (handle.qlogStream !== undefined) {
        this[kSetQLogStream](handle.qlogStream);
        handle.qlogStream = undefined;
      }
    } else {
      if (state.handshakeAckHistogram)
        state.handshakeAckHistogram[kDestroyHistogram]();
      if (state.handshakeContinuationHistogram)
        state.handshakeContinuationHistogram[kDestroyHistogram]();
    }
  }

  // Called when a client QuicSession instance receives a version
  // negotiation packet from the server peer. The client QuicSession
  // is destroyed immediately. This is not called at all for server
  // QuicSessions.
  [kVersionNegotiation](version, requestedVersions, supportedVersions) {
    const err =
      new ERR_QUIC_VERSION_NEGOTIATION(
        version,
        requestedVersions,
        supportedVersions);
    err.detail = {
      version,
      requestedVersions,
      supportedVersions,
    };
    this.destroy(err);
  }

  // Closes the specified stream with the given code. The
  // QuicStream object will be destroyed.
  [kStreamClose](id, code) {
    const stream = this[kInternalState].streams.get(id);
    if (stream === undefined)
      return;
    stream[kDestroy](code);
  }

  [kStreamReset](id, code) {
    const stream = this[kInternalState].streams.get(id);
    if (stream === undefined)
      return;

    stream[kStreamReset](code);
  }

  // Delivers a block of headers to the appropriate QuicStream
  // instance. This will only be called if the ALPN selected
  // is known to support headers.
  [kHeaders](id, headers, kind) {
    const stream = this[kInternalState].streams.get(id);
    if (stream === undefined)
      return;

    stream[kHeaders](headers, kind);
  }

  [kInspect](depth, options) {
    const state = this[kInternalState];
    return customInspect(this, {
      alpn: state.alpn,
      cipher: this.cipher,
      closing: this.closing,
      closeCode: this.closeCode,
      destroyed: this.destroyed,
      earlyData: state.earlyData,
      maxStreams: this.maxStreams,
      servername: this.servername,
      streams: state.streams.size,
    }, depth, options);
  }

  [kSetSocket](socket, natRebinding = false) {
    this[kInternalState].socket = socket;
    if (socket !== undefined)
      this[kHandle].setSocket(socket[kHandle], natRebinding);
  }

  // Called at the completion of the TLS handshake for the local peer
  [kHandshake](
    servername,
    alpn,
    cipher,
    cipherVersion,
    maxPacketLength,
    verifyErrorReason,
    verifyErrorCode,
    earlyData) {
    const state = this[kInternalState];
    state.handshakeComplete = true;
    state.servername = servername;
    state.alpn = alpn;
    state.cipher = cipher;
    state.cipherVersion = cipherVersion;
    state.maxPacketLength = maxPacketLength;
    state.verifyErrorReason = verifyErrorReason;
    state.verifyErrorCode = verifyErrorCode;
    state.earlyData = earlyData;

    if (!this[kHandshakePost]()) {
      if (typeof state.handshakeCompletePromiseReject === 'function') {
        state.handshakeCompletePromiseReject(
          new ERR_OPERATION_FAILED('Handshake failed'));
      }
      return;
    }

    if (typeof state.handshakeCompletePromiseResolve === 'function')
      state.handshakeCompletePromiseResolve();

    process.nextTick(() => {
      try {
        this.emit('secure', servername, alpn, this.cipher);
      } catch (error) {
        this.destroy(error);
      } finally {
        this.removeAllListeners('secure');
      }
    });
  }

  // Non-op for the default case. QuicClientSession
  // overrides this with some client-side specific
  // checks
  [kHandshakePost]() {
    return true;
  }

  [kRemoveStream](stream) {
    this[kInternalState].streams.delete(stream.id);
    this[kMaybeDestroy]();
  }

  [kAddStream](id, stream) {
    this[kInternalState].streams.set(id, stream);
  }

  // Called when a client QuicSession has opted to use the
  // server provided preferred address. This is a purely
  // informationational notification. It is not called on
  // server QuicSession instances.
  [kUsePreferredAddress](address, port, type) {
    process.nextTick(() => {
      try {
        this.emit('usePreferredAddress', address, port, type);
      } catch (error) {
        this.destroy(error);
      } finally {
        // usePreferredAddress will only ever be emitted once.
        // Release the references to the listeners.
        this.removeAllListeners('usePreferredAddress');
      }
    });
  }

  close() {
    return this[kInternalState].closePromise || this[kClose]();
  }

  [kClose]() {
    if (this.destroyed) {
      return PromiseReject(
        new ERR_INVALID_STATE('QuicSession is already destroyed'));
    }
    const promise = deferredClosePromise(this[kInternalState]);
    if (!this[kMaybeDestroy]()) {
      this[kHandle].gracefulClose();
    }
    return promise;
  }

  get closing() {
    return this[kInternalState].closePromise !== undefined;
  }

  // The QuicSession will be destroyed if close() has been
  // called and there are no remaining streams
  [kMaybeDestroy]() {
    const state = this[kInternalState];
    if (this.closing && state.streams.size === 0) {
      this.destroy();
      return true;
    }
    return false;
  }

  // Causes the QuicSession to be immediately destroyed, but with
  // additional metadata set.
  [kDestroy](code, family, silent, statelessReset) {
    const state = this[kInternalState];
    state.closeCode = code;
    state.closeFamily = family;
    state.silentClose = silent;
    state.statelessReset = statelessReset;
    this.destroy();
  }

  // Destroying synchronously shuts down and frees the
  // QuicSession immediately, even if there are still open
  // streams.
  //
  // Unless we're in the middle of a silent close, a
  // CONNECTION_CLOSE packet will be sent to the connected
  // peer and the session will be immediately destroyed.
  //
  // If destroy is called with an error argument, the
  // 'error' event is emitted on next tick.
  //
  // Once destroyed, and after the 'error' event (if any),
  // the 'close' event is emitted on next tick.
  destroy(error) {
    const state = this[kInternalState];
    // Destroy can only be called once. Multiple calls will be ignored
    if (state.destroyed)
      return;
    state.destroyed = true;

    state.idleTimeout = Boolean(this[kInternalState].state?.idleTimeout);

    // Destroy any remaining streams immediately.
    for (const stream of state.streams.values())
      stream.destroy(error);

    this.removeListener('newListener', onNewListener);
    this.removeListener('removeListener', onRemoveListener);

    const handle = this[kHandle];
    this[kHandle] = undefined;
    if (handle !== undefined) {
      // Copy the stats for use after destruction
      handle.stats[IDX_QUIC_SESSION_STATS_DESTROYED_AT] =
        process.hrtime.bigint();
      state.stats = new BigInt64Array(handle.stats);

      // Destroy the underlying QuicSession handle
      handle.destroy(state.closeCode, state.closeFamily);
    }

    // Remove the QuicSession JavaScript object from the
    // associated QuicSocket.
    state.socket[kRemoveSession](this);
    state.socket = undefined;

    // If we are destroying with an error, schedule the
    // error to be emitted on process.nextTick.
    if (error) {
      if (typeof state.closePromiseReject === 'function')
        state.closePromiseReject(error);
      process.nextTick(FunctionPrototypeBind(emit, this, 'error', error));
    } else if (typeof state.closePromiseResolve === 'function')
      state.closePromiseResolve();

    if (typeof state.handshakeCompletePromiseReject === 'function') {
      state.handshakeCompletePromiseReject(
        new ERR_OPERATION_FAILED('Handshake failed'));
    }

    process.nextTick(FunctionPrototypeBind(emit, this, 'close'));
  }

  // For server QuicSession instances, true if earlyData is
  // enabled. For client QuicSessions, true only if session
  // resumption is used and early data was accepted during
  // the TLS handshake. The value is set only after the
  // TLS handshake is completed (immeditely before the
  // secure event is emitted)
  get usingEarlyData() {
    return this[kInternalState].earlyData;
  }

  get maxStreams() {
    let bidi = 0;
    let uni = 0;
    if (this[kHandle]) {
      bidi = this[kInternalState].state.maxStreamsBidi;
      uni = this[kInternalState].state.maxStreamsUni;
    }
    return { bidi, uni };
  }

  get qlog() {
    return this[kInternalState].qlogStream;
  }

  get address() {
    return this[kInternalState].socket?.address || {};
  }

  get maxDataLeft() {
    return Number(this[kHandle] ? this[kInternalState].state.maxDataLeft : 0);
  }

  get bytesInFlight() {
    return Number(this[kHandle] ? this[kInternalState].state.bytesInFlight : 0);
  }

  get blockCount() {
    return Number(
      this[kHandle]?.stats[IDX_QUIC_SESSION_STATS_BLOCK_COUNT] || 0);
  }

  get authenticated() {
    // Specifically check for null. Undefined means the check has not
    // been performed yet, another other value other than null means
    // there was an error
    return this[kInternalState].verifyErrorReason == null;
  }

  get authenticationError() {
    if (this.authenticated)
      return undefined;
    const state = this[kInternalState];
    // eslint-disable-next-line no-restricted-syntax
    const err = new Error(state.verifyErrorReason);
    const code = 'ERR_QUIC_VERIFY_' + state.verifyErrorCode;
    err.name = `Error [${code}]`;
    err.code = code;
    return err;
  }

  get remoteAddress() {
    const out = {};
    if (this[kHandle])
      this[kHandle].getRemoteAddress(out);
    return out;
  }

  get handshakeComplete() {
    return this[kInternalState].handshakeComplete;
  }

  get handshakeConfirmed() {
    return this[kHandle] ?
      this[kInternalState].state.handshakeConfirmed :
      false;
  }

  get idleTimeout() {
    return this[kInternalState].idleTimeout;
  }

  get alpn() {
    return this[kInternalState].alpn;
  }

  get cipher() {
    if (!this.handshakeComplete)
      return {};
    const state = this[kInternalState];
    return {
      name: state.cipher,
      version: state.cipherVersion,
    };
  }

  getCertificate() {
    return this[kHandle] ?
      translatePeerCertificate(this[kHandle].getCertificate() || {}) : {};
  }

  getPeerCertificate(detailed = false) {
    return this[kHandle] ?
      translatePeerCertificate(
        this[kHandle].getPeerCertificate(detailed) || {}) : {};
  }

  get servername() {
    return this[kInternalState].servername;
  }

  get destroyed() {
    return this[kInternalState].destroyed;
  }

  get closeCode() {
    const state = this[kInternalState];
    return {
      code: state.closeCode,
      family: state.closeFamily,
      silent: state.silentClose,
    };
  }

  get socket() {
    return this[kInternalState].socket;
  }

  get statelessReset() {
    return this[kInternalState].statelessReset;
  }

  async createStream(options) {
    if (this.destroyed) {
      throw new ERR_INVALID_STATE(
        `${this.constructor.name} is already destroyed`);
    }
    if (this.closing) {
      throw new ERR_INVALID_STATE(
        `${this.constructor.name} is closing`);
    }

    if (options !== undefined)
      validateObject(options, 'options');

    const {
      unidirectional = false,
      source
    } = { ...options };

    if (typeof unidirectional !== 'boolean') {
      throw new ERR_INVALID_ARG_TYPE(
        'options.unidirectional',
        'boolean',
        unidirectional);
    }

    return await QuicStream[kAsyncCreate](this, {
      unidirectional,
      source,
    });
  }

  get duration() {
    const end = getStats(this, IDX_QUIC_SESSION_STATS_DESTROYED_AT) ||
                process.hrtime.bigint();
    return Number(end - getStats(this, IDX_QUIC_SESSION_STATS_CREATED_AT));
  }

  get handshakeDuration() {
    const end =
      this.handshakeComplete ?
        getStats(this, IDX_QUIC_SESSION_STATS_HANDSHAKE_COMPLETED_AT) :
        process.hrtime.bigint();
    return Number(
      end - getStats(this, IDX_QUIC_SESSION_STATS_HANDSHAKE_START_AT));
  }

  get bytesReceived() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_BYTES_RECEIVED));
  }

  get bytesSent() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_BYTES_SENT));
  }

  get bidiStreamCount() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_BIDI_STREAM_COUNT));
  }

  get uniStreamCount() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_UNI_STREAM_COUNT));
  }

  get maxInFlightBytes() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_MAX_BYTES_IN_FLIGHT));
  }

  get lossRetransmitCount() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_LOSS_RETRANSMIT_COUNT));
  }

  get ackDelayRetransmitCount() {
    return Number(
      getStats(this, IDX_QUIC_SESSION_STATS_ACK_DELAY_RETRANSMIT_COUNT));
  }

  get peerInitiatedStreamCount() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_STREAMS_IN_COUNT));
  }

  get selfInitiatedStreamCount() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_STREAMS_OUT_COUNT));
  }

  get keyUpdateCount() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_KEYUPDATE_COUNT));
  }

  get minRTT() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_MIN_RTT));
  }

  get latestRTT() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_LATEST_RTT));
  }

  get smoothedRTT() {
    return Number(getStats(this, IDX_QUIC_SESSION_STATS_SMOOTHED_RTT));
  }

  updateKey() {
    const state = this[kInternalState];
    // Initiates a key update for the connection.
    if (this.destroyed) {
      throw new ERR_INVALID_STATE(
        `${this.constructor.name} is already destroyed`);
    }
    if (this.closing) {
      throw new ERR_INVALID_STATE(
        `${this.constructor.name} is closing`);
    }
    if (!state.handshakeConfirmed)
      throw new ERR_INVALID_STATE('Handshake is not yet confirmed');
    return this[kHandle].updateKey();
  }

  get handshakeAckHistogram() {
    return this[kInternalState].handshakeAckHistogram;
  }

  get handshakeContinuationHistogram() {
    return this[kInternalState].handshakeContinuationHistogram;
  }

  [kRemoveFromSocket]() {
    return this[kHandle].removeFromSocket();
  }
}
class QuicServerSession extends QuicSession {
  [kInternalServerState] = {
    context: undefined
  };

  constructor(socket, handle, options) {
    const {
      highWaterMark,
      defaultEncoding,
      ocspHandler,
      clientHelloHandler,
      context,
    } = options;
    super(socket, {
      highWaterMark,
      defaultEncoding,
      ocspHandler,
      clientHelloHandler
    });
    this[kInternalServerState].context = context;
    this[kSetHandle](handle);
  }

  // Called only when a clientHello event handler is registered.
  // Allows user code an opportunity to interject into the start
  // of the TLS handshake.
  async [kClientHello](alpn, servername, ciphers) {
    const internalState = this[kInternalState];
    return internalState.clientHelloHandler?.(alpn, servername, ciphers);
  }

  async [kHandleOcsp](servername) {
    const internalState = this[kInternalState];
    const { context } = this[kInternalServerState];
    if (!internalState.ocspHandler || !context) return undefined;
    // eslint-disable-next-line no-return-await
    return await internalState.ocspHandler('request', {
      servername,
      certificate: context.context.getCertificate(),
      issuer: context.context.getIssuer()
    });
  }

  get allowEarlyData() { return false; }
}

class QuicClientSession extends QuicSession {
  [kInternalClientState] = {
    allowEarlyData: false,
    handshakeStarted: false,
    minDHSize: undefined,
    secureContext: undefined,
  };

  constructor(socket, options, type, ip) {
    const sc_options = {
      ...options,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    };
    const {
      autoStart,
      alpn,
      dcid,
      minDHSize,
      ocspHandler,
      port,
      preferredAddressPolicy,
      remoteTransportParams,
      servername,
      sessionTicket,
      verifyHostnameIdentity,
      qlog,
      highWaterMark,
      defaultEncoding,
    } = validateQuicClientSessionOptions(options);

    if (!verifyHostnameIdentity && !warnedVerifyHostnameIdentity) {
      warnedVerifyHostnameIdentity = true;
      process.emitWarning(
        'QUIC hostname identity verification is disabled. This violates QUIC ' +
        'specification requirements and reduces security. Hostname identity ' +
        'verification should only be disabled for debugging purposes.'
      );
    }

    super(socket, {
      servername,
      alpn,
      highWaterMark,
      defaultEncoding,
      ocspHandler
    });
    const state = this[kInternalClientState];
    state.handshakeStarted = autoStart;
    state.minDHSize = minDHSize;

    state.secureContext =
      createSecureContext(
        sc_options,
        initSecureContextClient);

    const transportParams = validateTransportParams(options);

    state.allowEarlyData =
      remoteTransportParams !== undefined &&
      sessionTicket !== undefined;

    setTransportParams(transportParams);

    const handle =
      _createClientSession(
        this.socket[kHandle],
        type,
        ip,
        port,
        state.secureContext.context,
        this.servername || ip,
        remoteTransportParams,
        sessionTicket,
        dcid,
        preferredAddressPolicy,
        this.alpn,
        (verifyHostnameIdentity ?
          QUICCLIENTSESSION_OPTION_VERIFY_HOSTNAME_IDENTITY : 0) |
        (ocspHandler !== undefined ?
          QUICCLIENTSESSION_OPTION_REQUEST_OCSP : 0),
        qlog,
        autoStart);

    // If handle is a number, creating the session failed.
    if (typeof handle === 'number') {
      switch (handle) {
        case ERR_FAILED_TO_CREATE_SESSION:
          throw new ERR_QUIC_FAILED_TO_CREATE_SESSION();
        case ERR_INVALID_REMOTE_TRANSPORT_PARAMS:
          throw new ERR_QUIC_INVALID_REMOTE_TRANSPORT_PARAMS();
        case ERR_INVALID_TLS_SESSION_TICKET:
          throw new ERR_QUIC_INVALID_TLS_SESSION_TICKET();
        default:
          throw new ERR_OPERATION_FAILED(`Unspecified reason [${handle}]`);
      }
    }

    this[kSetHandle](handle);
  }

  [kHandshakePost]() {
    const { type, size } = this.ephemeralKeyInfo;
    if (type === 'DH' && size < this[kInternalClientState].minDHSize) {
      this.destroy(new ERR_TLS_DH_PARAM_SIZE(size));
      return false;
    }
    return true;
  }

  async [kHandleOcsp](data) {
    const internalState = this[kInternalState];
    // eslint-disable-next-line no-return-await
    return await internalState.ocspHandler?.('response', { data });
  }

  get allowEarlyData() {
    return this[kInternalClientState].allowEarlyData;
  }

  get handshakeStarted() {
    return this[kInternalClientState].handshakeStarted;
  }

  startHandshake() {
    const state = this[kInternalClientState];
    if (this.destroyed) {
      throw new ERR_INVALID_STATE(
        `${this.constructor.name} is already destroyed`);
    }
    if (state.handshakeStarted)
      return;
    state.handshakeStarted = true;
    this[kHandle].startHandshake();
  }

  get ephemeralKeyInfo() {
    return this[kHandle] !== undefined ?
      this[kHandle].getEphemeralKeyInfo() :
      {};
  }

  async setSocket(socket, natRebinding = false) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicClientSession is already destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicClientSession is closing');
    if (!(socket instanceof QuicSocket))
      throw new ERR_INVALID_ARG_TYPE('socket', 'QuicSocket', socket);
    if (socket.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket is already destroyed');
    if (socket.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');
    if (typeof natRebinding !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('natRebinding', 'boolean', true);

    await socket[kMaybeBind]();

    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicClientSession was destroyed');
    if (this.closing)
      throw new ERR_INVALID_STATE('QuicClientSession is closing');
    if (socket.destroyed)
      throw new ERR_INVALID_STATE('QuicSocket was destroyed');
    if (socket.closing)
      throw new ERR_INVALID_STATE('QuicSocket is closing');

    if (this.socket) {
      this.socket[kRemoveSession](this);
      this[kSetSocket](undefined);
    }
    socket[kAddSession](this);
    this[kSetSocket](socket, natRebinding);
  }
}

async function acquireSource(data, options) {
  if (data === undefined) return data;

  if (typeof data.then === 'function')
    return await acquireSource(await data, options);

  if (typeof data === 'string') {
    const { encoding = 'utf8' } = { ...options };
    if (!Buffer.isEncoding(encoding))
      throw new ERR_UNKNOWN_ENCODING(encoding);
    return new ArrayBufferViewSource(Buffer.from(data, encoding));
  }

  if (isArrayBufferView(data))
    return new ArrayBufferViewSource(data);

  // TODO(@jasnell): Support other types

  throw new ERR_INVALID_ARG_TYPE(
    'source',
    [
      'promise<string>',
      'promise<Buffer>',
      'promise<TypedArray>',
      'promise<DataView>',
      'string',
      'Buffer',
      'TypedArray',
      'DataView',
    ],
    source);
}

function QuicStreamReadableEmit(chunks, ended) {
  for (const chunk of chunks)
    this.push(chunk);
  if (ended) {
    this.push(null);
  }
}

class QuicStreamReadable extends Readable {
  static [kSyncCreate](stream, options) {
    const readable = new Readable(options);
    ObjectSetPrototypeOf(readable, QuicStreamReadable.prototype);
    readable[kHandle] = new JSQuicBufferConsumer();
    readable[kHandle].emit = QuicStreamReadableEmit.bind(readable);
    return readable;
  }
  constructor() { throw new ERR_ILLEGAL_CONSTRUCTOR(); }
  _read(size) {}

  _destroy(err, cb) {
    this[kHandle] = undefined;
    cb(err);
  }
}

class QuicStream extends EventEmitter {
  // The synchronous factory function is used directly for inbound,
  // peer-initiated streams where the handle has already been created.
  // In those cases, the source will be undefined. It is used indirectly
  // by kAsyncCreateStream when the createStream() API is called, in
  // which case a source may be provided. We do not perform type checking
  // here since this is an internal-only function.
  static [kSyncCreate](session, handle, source) {
    const stream = new EventEmitter({ captureRejections: true });
    ObjectSetPrototypeOf(stream, QuicStream.prototype);
    // We define all of the fields for the internal state at once
    // here as a performance optimization. This keeps the internal
    // shape from changing and causing functions to deopt as a result.
    stream[kInternalState] = {
      closed: false,
      closePromise: undefined,
      closePromiseReject: undefined,
      closePromiseResolve: undefined,
      consumer: undefined,
      dataRateHistogram: undefined,
      dataSizeHistogram: undefined,
      dataAckHistogram: undefined,
      id: undefined,
      resetCode: undefined,
      session: session,
      sharedState: undefined,
      source: source,
      stats: undefined,
    };
    stream[kSetHandle](handle);
    return stream;
  }

  static async [kAsyncCreate](session, options) {
    const {
      unidirectional = false,
      source,
    } = options;

    const ret = await PromiseAll([
      session[kHandshakeComplete](),
      acquireSource(source, options)
    ]);

    return QuicStream[kSyncCreate](
      session,
      _openStream(session[kHandle], ret[1], unidirectional),
      ret[1]);
  }

  // Instances of QuicStream cannot be created directly using the
  // new keyword. Use the kAsyncCreateStream and kSyncCreateStream
  // factory functions instead.
  constructor() { throw new ERR_ILLEGAL_CONSTRUCTOR(); }

  [kSetHandle](handle) {
    const state = this[kInternalState];
    const current = this[kHandle];
    this[kHandle] = handle;
    if (handle !== undefined) {
      handle[owner_symbol] = this;
      this[async_id_symbol] = handle.getAsyncId();
      state.id = handle.id();
      state.dataRateHistogram = new Histogram(handle.rate);
      state.dataSizeHistogram = new Histogram(handle.size);
      state.dataAckHistogram = new Histogram(handle.ack);
      state.sharedState = new QuicStreamSharedState(handle.state);
      state.session[kAddStream](state.id, this);
    } else {
      if (current !== undefined) {
        current.stats[IDX_QUIC_STREAM_STATS_DESTROYED_AT] =
          process.hrtime.bigint();
        state.stats = new BigInt64Array(current.stats);
      }
      state.sharedState = undefined;
      if (state.dataRateHistogram)
        state.dataRateHistogram[kDestroyHistogram]();
      if (state.dataSizeHistogram)
        state.dataSizeHistogram[kDestroyHistogram]();
      if (state.dataAckHistogram)
        state.dataAckHistogram[kDestroyHistogram]();
    }
  }

  [kInspect](depth, options) {
    return customInspect(this, {
      id: this[kInternalState].id,
      detached: this.detached,
      unidirectional: this.unidirectional,
      serverInitiated: this.serverInitiated,
    }, depth, options);
  }

  // A QuicStream is write-only if it is unidirectional and
  // locally initiated.
  get [kIsWriteOnly]() {
    if (!this.unidirectional)
      return false;
    return this.serverInitiated ?
        this.session instanceof QuicServerSession :
        this.session instanceof QuicClientSession;
  }

  // A QuicStream is read-only if it is unidirectional and
  // remotely initiated.
  get [kIsReadOnly]() {
    if (!this.unidirectional)
      return false;
    return this.serverInitiated ?
      this.session() instanceof QuicClientSession :
      this.session() instanceof QuicServerSession;
  }

  [kDestroy](code) {
    this[kSetHandle]();
    const state = this[kInternalState];
    state.source = undefined;

    // TODO(@jasnell): Do something with code!
    if (typeof state.closePromiseResolve === 'function')
      state.closePromiseResolve();

    process.nextTick(FunctionPrototypeBind(emit, this, 'close'));
  }

  destroy(error) {
    // If the stream is still open, signal immediate close (reset +
    // stop sending) and free all resources immediately. Any buffered
    // inbound or outbound data is released and the JavaScript stream
    // is detached from the handle.
  }

  [kStreamReset](code) {
    this[kInternalState].resetCode = code;
    // TODO(@jasnell): What to do with the consumer?
  }

  [kHeaders](headers, kind) {
    // TODO(@jasnell): Convert the headers into a proper object
    let name;
    switch (kind) {
      case QUICSTREAM_HEADERS_KIND_NONE:
        // Fall through
      case QUICSTREAM_HEADERS_KIND_INITIAL:
        name = 'initialHeaders';
        break;
      case QUICSTREAM_HEADERS_KIND_INFORMATIONAL:
        name = 'informationalHeaders';
        break;
      case QUICSTREAM_HEADERS_KIND_TRAILING:
        name = 'trailingHeaders';
        break;
      default:
        assert.fail('Invalid headers kind');
    }
    process.nextTick(FunctionPrototypeBind(emit, this, name, headers));
  }

  // Triggers a graceful close. Once called, send() cannot be called
  // if it hasn't been already. Returns a promise that is resolved once
  // the stream closes naturally.
  close() {
    return this[kInternalState].closePromise || this[kClose]();
  }

  [kClose]() {
    if (this.destroyed) {
      return PromiseReject(
        new ERR_INVALID_STATE('QuicStream is already destroyed'));
    }
    return deferredClosePromise(this[kInternalState]);
  }

  // Send data from the given source. The source may be a
  // string, TypedArray, JSON-serializable JavaScript object,
  // FileHandle, stream.Readable, generator object yielding
  // strings or TypedArrays, async generator object yielding
  // strings or TypedArrays, or a Promise resolving any of
  // the same.
  // If a source has already been attached, or if the stream
  // has been detached, or is incapable of sending (because it
  // is read only), an error will be thrown.
  async send(source, options) {
    if (this.detached)
      throw new ERR_INVALID_STATE('The QuicStream has been detached');

    if (this[kIsReadOnly])
      throw new ERR_INVALID_STATE('The QuicStream is read-only');

    const state = this[kInternalState];
    if (state.source !== undefined) {
      throw new ERR_INVALID_STATE(
        'The QuicStream already has a source attached');
    }

    if (state.closePromise)
      throw new ERR_INVALID_STATE('The QuicStream is closing');

    state.source = await acquireSource(source, options);
    this[kHandle].attachSource(state.source);

    // TODO(@jasnell): Should this return a Promise that resolves when the
    // the source has been completely consumed? Right now it resolves when
    // the source has been attached.
  }

  // Return a stream.Readable consumer for this QuicStream
  readable(options) {
    if (this.detached)
      throw new ERR_INVALID_STATE('The QuicStream has been detached');

    if (this[kIsWriteOnly])
      throw new ERR_INVALID_STATE('The QuicStream is write-only');

    const state = this[kInternalState];
    if (state.consumer !== undefined) {
      throw new ERR_INVALID_STATE(
        'The QuicStream already as a consumer attached');
    }

    if (options !== undefined)
      validateObject(options, 'options');
    state.consumer = QuicStreamReadable[kSyncCreate](this, options);
    this[kHandle].attachConsumer(state.consumer[kHandle]);
    return state.consumer;
  }

  // Return a promise that resolves the received data as a string.
  async text(options) {
    const readable = this.readable();
    const { encoding = 'utf8'} = { ...options };
    if (!Buffer.isEncoding(encoding))
      throw new ERR_UNKNOWN_ENCODING(encoding);
    readable.setEncoding(encoding);
    let result = '';
    for await (const chunk of readable)
      result += chunk;
    return result;
  }

  async [SymbolAsyncIterator]() {
    return this.readable()[SymbolAsyncIterator]();
  }

  sendInformationalHeaders(headers = {}) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicStream is already destroyed');

    if (this.detached)
      throw new ERR_INVALID_STATE('Unable to submit headers');

    validateObject(headers, 'headers');

    // TODO(@jasnell): The validators here are specific to the QUIC
    // protocol. In the case below, these are the http/3 validators
    // (which are identical to the rules for http/2). We need to
    // find a way for this to be easily abstracted based on the
    // selected alpn.

    let validator;
    if (this.session instanceof QuicServerSession) {
      validator =
        !this.serverInitiated ?
          assertValidPseudoHeaderResponse :
          assertValidPseudoHeader;
    } else {  // QuicClientSession
      validator =
        !this.serverInitiated ?
          assertValidPseudoHeader :
          assertValidPseudoHeaderResponse;
    }

    return this[kHandle].submitInformationalHeaders(
      mapToHeaders(headers, validator));
  }

  sendInitialHeaders(headers = {}, options = {}) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicStream is already destroyed');

    if (this.detached)
      throw new ERR_INVALID_STATE('Unable to submit headers');

    const { terminal } = { ...options };

    if (terminal !== undefined)
      validateBoolean(terminal, 'options.terminal');
    validateObject(headers, 'headers');

    // TODO(@jasnell): The validators here are specific to the QUIC
    // protocol. In the case below, these are the http/3 validators
    // (which are identical to the rules for http/2). We need to
    // find a way for this to be easily abstracted based on the
    // selected alpn.

    let validator;
    if (this.session instanceof QuicServerSession) {
      validator =
        !this.serverInitiated ?
          assertValidPseudoHeaderResponse :
          assertValidPseudoHeader;
    } else {  // QuicClientSession
      validator =
        !this.serverInitiated ?
          assertValidPseudoHeader :
          assertValidPseudoHeaderResponse;
    }

    return this[kHandle].submitHeaders(
      mapToHeaders(headers, validator),
      terminal ?
        QUICSTREAM_HEADER_FLAGS_TERMINAL :
        QUICSTREAM_HEADER_FLAGS_NONE);
  }

  sendTrailingHeaders(headers = {}) {
    if (this.destroyed)
      throw new ERR_INVALID_STATE('QuicStream is already destroyed');

    if (this.detached)
      throw new ERR_INVALID_STATE('Unable to submit headers');

    validateObject(headers, 'headers');

    // TODO(@jasnell): The validators here are specific to the QUIC
    // protocol. In the case below, these are the http/3 validators
    // (which are identical to the rules for http/2). We need to
    // find a way for this to be easily abstracted based on the
    // selected alpn.

    return this[kHandle].submitTrailers(
      mapToHeaders(headers, assertValidPseudoHeaderTrailer));
  }

  get detached() {
    return this[kHandle] === undefined;
  }

  get serverInitiated() {
    return Boolean(this[kInternalState].id & 0b01);
  }

  get unidirectional() {
    return Boolean(this[kInternalState].id & 0b10);
  }

  get resetCode() {
    const state = this[kInternalState];
    return (state.resetCode !== undefined) ? state.resetCode | 0 : undefined;
  }

  get id() {
    return this[kInternalState].id;
  }

  get session() {
    return this[kInternalState].session;
  }

  get dataRateHistogram() {
    return this[kInternalState].dataRateHistogram;
  }

  get dataSizeHistogram() {
    return this[kInternalState].dataSizeHistogram;
  }

  get dataAckHistogram() {
    return this[kInternalState].dataAckHistogram;
  }

  get duration() {
    const end = getStats(this, IDX_QUIC_STREAM_STATS_DESTROYED_AT) ||
                process.hrtime.bigint();
    return Number(end - getStats(this, IDX_QUIC_STREAM_STATS_CREATED_AT));
  }

  get bytesReceived() {
    return Number(getStats(this, IDX_QUIC_STREAM_STATS_BYTES_RECEIVED));
  }

  get bytesSent() {
    return Number(getStats(this, IDX_QUIC_STREAM_STATS_BYTES_SENT));
  }

  get maxExtendedOffset() {
    return Number(getStats(this, IDX_QUIC_STREAM_STATS_MAX_OFFSET));
  }

  get finalSize() {
    return Number(getStats(this, IDX_QUIC_STREAM_STATS_FINAL_SIZE));
  }

  get maxAcknowledgedOffset() {
    return Number(getStats(this, IDX_QUIC_STREAM_STATS_MAX_OFFSET_ACK));
  }

  get maxReceivedOffset() {
    return Number(getStats(this, IDX_QUIC_STREAM_STATS_MAX_OFFSET_RECV));
  }
}

//class QuicStream extends Duplex {

  // [kClose]() {
  //   const state = this[kInternalState];

  //   if (this.destroyed) {
  //     return PromiseReject(
  //       new ERR_INVALID_STATE('QuicStream is already destroyed'));
  //   }

  //   const promise = deferredClosePromise(state);
  //   if (this.readable) {
  //     this.push(null);
  //     this.read();
  //   }

  //   if (this.writable) {
  //     this.end();
  //   }

  //   // TODO(@jasnell): Investigate later if a Promise version
  //   // of finished() can work here instead.
  //   return promise;
  // }

  // close() {
  //   return this[kInternalState].closePromise || this[kClose]();
  // }

  // _destroy(error, callback) {
  //   const state = this[kInternalState];
  //   const handle = this[kHandle];
  //   this[kSetHandle]();
  //   if (handle !== undefined)
  //     handle.destroy();
  //   state.session[kRemoveStream](this);

  //   if (error && typeof state.closePromiseReject === 'function')
  //     state.closePromiseReject(error);
  //   else if (typeof state.closePromiseResolve === 'function')
  //     state.closePromiseResolve();

  //   // TODO(@jasnell): Investigate how we can eliminate the nextTick here
  //   process.nextTick(() => callback(error));
  // }

  // [kDestroy](code) {
  //   // TODO(@jasnell): If code is non-zero, and stream is not otherwise
  //   // naturally shutdown, then we should destroy with an error.

  //   // Put the QuicStream into detached mode before calling destroy
  //   this[kSetHandle]();
  //   this.destroy();
  // }

  // _final(cb) {
  //   if (!this.detached) {
  //     const state = this[kInternalState];
  //     if (state.sharedState?.finSent)
  //       return cb();
  //     const handle = this[kHandle];
  //     const req = new ShutdownWrap();
  //     req.oncomplete = () => {
  //       req.handle = undefined;
  //       cb();
  //     };
  //     req.handle = handle;
  //     if (handle.shutdown(req) === 1)
  //       return req.oncomplete();
  //     return;
  //   }
  //   return cb();
  // }

  // sendFile(path, options = {}) {
  //   if (this.detached)
  //     throw new ERR_INVALID_STATE('Unable to send file');
  //   fs.open(path, 'r',
  //           FunctionPrototypeBind(QuicStream[kOnFileOpened], this, options));
  // }

  // static [kOnFileOpened](options, err, fd) {
  //   const onError = options.onError;
  //   if (err) {
  //     if (onError) {
  //       this.close();
  //       onError(err);
  //     } else {
  //       this.destroy(err);
  //     }
  //     return;
  //   }

  //   if (this.destroyed || this.closed) {
  //     fs.close(fd, assert.ifError);
  //     return;
  //   }

  //   this.sendFD(fd, options, true);
  // }

  // sendFD(fd, { offset = -1, length = -1 } = {}, ownsFd = false) {
  //   if (this.destroyed || this[kInternalState].closed)
  //     return;

  //   if (this.detached)
  //     throw new ERR_INVALID_STATE('Unable to send file descriptor');

  //   validateInteger(offset, 'options.offset', /* min */ -1);
  //   validateInteger(length, 'options.length', /* min */ -1);

  //   if (fd instanceof fsPromisesInternal.FileHandle)
  //     fd = fd.fd;
  //   else if (typeof fd !== 'number')
  //     throw new ERR_INVALID_ARG_TYPE('fd', ['number', 'FileHandle'], fd);

  //   this[kUpdateTimer]();
  //   this.ownsFd = ownsFd;

  //   defaultTriggerAsyncIdScope(this[async_id_symbol],
  //                              QuicStream[kStartFilePipe],
  //                              this, fd, offset, length);
  // }

  // static [kStartFilePipe](stream, fd, offset, length) {
  //   const handle = new FileHandle(fd, offset, length);
  //   handle.onread = QuicStream[kOnPipedFileHandleRead];
  //   handle.stream = stream;

  //   const pipe = new StreamPipe(handle, stream[kHandle]);
  //   pipe.onunpipe = QuicStream[kOnFileUnpipe];
  //   pipe.start();

  //   // Exact length of the file doesn't matter here, since the
  //   // stream is closing anyway - just use 1 to signify that
  //   // a write does exist
  //   stream[kTrackWriteState](stream, 1);
  // }

  // static [kOnFileUnpipe]() {  // Called on the StreamPipe instance.
  //   const stream = this.sink[owner_symbol];
  //   if (stream.ownsFd)
  //     PromisePrototypeCatch(this.source.close(),
  //                           FunctionPrototypeBind(stream.destroy, stream));
  //   else
  //     this.source.releaseFD();
  //   stream.end();
  // }

  // static [kOnPipedFileHandleRead]() {
  //   const err = streamBaseState[kReadBytesOrError];
  //   if (err < 0 && err !== UV_EOF) {
  //     this.stream.destroy(errnoException(err, 'sendFD'));
  //   }
  // }

//}

function createSocket(options) {
  return new QuicSocket(options);
}

module.exports = {
  createSocket,
  kUDPHandleForTesting,
  kRemoveFromSocket,
};

/* eslint-enable no-use-before-define */

// A single QuicSocket may act as both a Server and a Client.
// There are two kinds of sessions:
//   * QuicServerSession
//   * QuicClientSession
//
// It is important to understand that QUIC sessions are
// independent of the QuicSocket. A default configuration
// for QuicServerSession and QuicClientSessions may be
// set when the QuicSocket is created, but the actual
// configuration for a particular QuicSession instance is
// not set until the session itself is created.
//
// QuicSockets and QuicSession instances have distinct
// configuration options that apply independently:
//
// QuicSocket Options:
//   * `lookup` {Function} A function used to resolve DNS names.
//   * `type` {string} Either `'udp4'` or `'udp6'`, defaults to
//     `'udp4'`.
//   * `port` {number} The local IP port the QuicSocket will
//     bind to.
//   * `address` {string} The local IP address or hostname that
//     the QuicSocket will bind to. If a hostname is given, the
//     `lookup` function will be invoked to resolve an IP address.
//   * `ipv6Only`
//
// Keep in mind that while all QUIC network traffic is encrypted
// using TLS 1.3, every QuicSession maintains it's own SecureContext
// that is completely independent of the QuicSocket. Every
// QuicServerSession and QuicClientSession could, in theory,
// use a completely different TLS 1.3 configuration. To keep it
// simple, however, we use the same SecureContext for all QuicServerSession
// instances, but that may be something we want to revisit later.
//
// Every QuicSession has two sets of configuration parameters:
//   * Options
//   * Transport Parameters
//
// Options establish implementation specific operation parameters,
// such as the default highwatermark for new QuicStreams. Transport
// Parameters are QUIC specific and are passed to the peer as part
// of the TLS handshake.
//
// Every QuicSession may have separate options and transport
// parameters, even within the same QuicSocket, so the configuration
// must be established when the session is created.
//
// When creating a QuicSocket, it is possible to set a default
// configuration for both QuicServerSession and QuicClientSession
// options.
//
// const soc = createSocket({
//   type: 'udp4',
//   port: 0,
//   server: {
//     // QuicServerSession configuration defaults
//   },
//   client: {
//     // QuicClientSession configuration defaults
//   }
// });
//
// When calling listen() on the created QuicSocket, the server
// specific configuration that will be used for all new
// QuicServerSession instances will be given, with the values
// provided to createSocket() using the server option used
// as a default.
//
// When calling connect(), the client specific configuration
// will be given, with the values provided to the createSocket()
// using the client option used as a default.


// Some lifecycle documentation for the various objects:
//
// QuicSocket
//   Close
//     * Close all existing Sessions
//     * Do not allow any new Sessions (inbound or outbound)
//     * Destroy once there are no more sessions

//   Destroy
//     * Destroy all remaining sessions
//     * Destroy and free the QuicSocket handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicClientSession
//   Close
//     * Allow existing Streams to complete normally
//     * Do not allow any new Streams (inbound or outbound)
//     * Destroy once there are no more streams

//   Destroy
//     * Send CONNECTION_CLOSE
//     * Destroy all remaining Streams
//     * Remove Session from Parent Socket
//     * Destroy and free the QuicSession handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicServerSession
//   Close
//     * Allow existing Streams to complete normally
//     * Do not allow any new Streams (inbound or outbound)
//     * Destroy once there are no more streams
//   Destroy
//     * Send CONNECTION_CLOSE
//     * Destroy all remaining Streams
//     * Remove Session from Parent Socket
//     * Destroy and free the QuicSession handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicStream
//   Destroy
//     * Remove Stream From Parent Session
//     * Destroy and free the QuicStream handle immediately
//     * If Error, emit Error event
//     * Emit Close event

// QuicSocket States:
//   Initial                 -- Created
//   Pending                 -- Pending binding to local UDP port
//   Bound                   -- Bound to local UDP port
//   Closed                  -- Unbound from local UDP port
//   Destroyed               -- QuicSocket is no longer usable
//   Destroyed-With-Error    -- An error has been encountered, socket is no
//                              longer usable
//
// QuicSession States:
//   Initial                 -- Created, QuicSocket state undetermined,
//                              no internal QuicSession Handle assigned.
//   Ready
//     QuicSocket Ready        -- QuicSocket in Bound state.
//     Handle Assigned         -- Internal QuicSession Handle assigned.
//   TLS Handshake Started   --
//   TLS Handshake Completed --
//   TLS Handshake Confirmed --
//   Closed                  -- Graceful Close Initiated
//   Destroyed               -- QuicSession is no longer usable
//   Destroyed-With-Error    -- An error has been encountered, session is no
//                              longer usable
//
// QuicStream States:
//   Initial Writable/Corked -- Created, QuicSession in Initial State
//   Open Writable/Uncorked  -- QuicSession in Ready State
//   Closed                  -- Graceful Close Initiated
//   Destroyed               -- QuicStream is no longer usable
//   Destroyed-With-Error    -- An error has been encountered, stream is no
//                              longer usable
