'use strict';

const {
  ObjectSetPrototypeOf,
  Symbol,
} = primordials;

const {
  ConfigObject,
  OptionsObject,
  RandomConnectionIDStrategy,
  NGTCP2_CC_ALGO_CUBIC,
  NGTCP2_CC_ALGO_RENO,
  NGTCP2_PREFERRED_ADDRESS_IGNORE,
  NGTCP2_PREFERRED_ADDRESS_USE,
  NGTCP2_MAX_CIDLEN,
  HTTP3_ALPN,

  IDX_STATS_ENDPOINT_CREATED_AT,
  IDX_STATS_ENDPOINT_BOUND_AT,
  IDX_STATS_ENDPOINT_LISTEN_AT,
  IDX_STATS_ENDPOINT_DESTROYED_AT,
  IDX_STATS_ENDPOINT_BYTES_RECEIVED,
  IDX_STATS_ENDPOINT_BYTES_SENT,
  IDX_STATS_ENDPOINT_PACKETS_RECEIVED,
  IDX_STATS_ENDPOINT_PACKETS_IGNORED,
  IDX_STATS_ENDPOINT_PACKETS_SENT,
  IDX_STATS_ENDPOINT_SERVER_SESSIONS,
  IDX_STATS_ENDPOINT_CLIENT_SESSIONS,
  IDX_STATS_ENDPOINT_STATELESS_RESET_COUNT,
  IDX_STATS_ENDPOINT_SERVER_BUSY_COUNT,

  IDX_STATS_SESSION_CREATED_AT,
  IDX_STATS_SESSION_HANDSHAKE_COMPLETED_AT,
  IDX_STATS_SESSION_HANDSHAKE_CONFIRMED_AT,
  IDX_STATS_SESSION_SENT_AT,
  IDX_STATS_SESSION_RECEIVED_AT,
  IDX_STATS_SESSION_CLOSING_AT,
  IDX_STATS_SESSION_DESTROYED_AT,
  IDX_STATS_SESSION_BYTES_RECEIVED,
  IDX_STATS_SESSION_BYTES_SENT,
  IDX_STATS_SESSION_BIDI_STREAM_COUNT,
  IDX_STATS_SESSION_UNI_STREAM_COUNT,
  IDX_STATS_SESSION_STREAMS_IN_COUNT,
  IDX_STATS_SESSION_STREAMS_OUT_COUNT,
  IDX_STATS_SESSION_KEYUPDATE_COUNT,
  IDX_STATS_SESSION_LOSS_RETRANSMIT_COUNT,
  IDX_STATS_SESSION_MAX_BYTES_IN_FLIGHT,
  IDX_STATS_SESSION_BLOCK_COUNT,
  IDX_STATS_SESSION_BYTES_IN_FLIGHT,
  IDX_STATS_SESSION_CWND,
  IDX_STATS_SESSION_DELIVERY_RATE_SEC,
  IDX_STATS_SESSION_INITIAL_RTT,
  IDX_STATS_SESSION_LATEST_RTT,
  IDX_STATS_SESSION_MAX_UDP_PAYLOAD_SIZE,
  IDX_STATS_SESSION_MIN_RTT,
  IDX_STATS_SESSION_PTO_COUNT,
  IDX_STATS_SESSION_RTTVAR,
  IDX_STATS_SESSION_SMOOTHED_RTT,
  IDX_STATS_SESSION_SSTHRESH,
  IDX_STATS_SESSION_RECEIVE_RATE,
  IDX_STATS_SESSION_SEND_RATE,

  IDX_STATE_ENDPOINT_LISTENING,
  IDX_STATE_ENDPOINT_BUSY,
  IDX_STATE_ENDPOINT_STATELESS_RESET_DISABLED,
  IDX_STATE_ENDPOINT_WAITING_FOR_CALLBACKS,
  IDX_STATE_ENDPOINT_PENDING_CALLBACKS,

  IDX_STATE_SESSION_CLIENT_HELLO_ENABLED,
  IDX_STATE_SESSION_DATAGRAM_ENABLED,
  IDX_STATE_SESSION_KEYLOG_ENABLED,
  IDX_STATE_SESSION_OCSP_ENABLED,
  IDX_STATE_SESSION_PATH_VALIDATED_ENABLED,
  IDX_STATE_SESSION_USE_PREFERRED_ADDRESS_ENABLED,
  IDX_STATE_SESSION_CLOSING,
  IDX_STATE_SESSION_CLOSING_TIMER_ENABLED,
  IDX_STATE_SESSION_CONNECTION_CLOSE_SCOPE,
  IDX_STATE_SESSION_DESTROYED,
  IDX_STATE_SESSION_GRACEFUL_CLOSING,
  IDX_STATE_SESSION_HANDSHAKE_CONFIRMED,
  IDX_STATE_SESSION_IDLE_TIMEOUT,
  IDX_STATE_SESSION_MAX_DATA_LEFT,
  IDX_STATE_SESSION_MAX_STREAMS_BIDI,
  IDX_STATE_SESSION_MAX_STREAMS_UNI,
  IDX_STATE_SESSION_SILENT_CLOSE,
  IDX_STATE_SESSION_STATELESS_RESET,
} = internalBinding('quic');

const {
  Buffer,
} = require('buffer');

const {
  JSTransferable,
  kClone,
  kDeserialize
} = require('internal/worker/js_transferable');

const {
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
  validateBigIntOrSafeInteger,
  validateBoolean,
  validateInt32,
  validateNumber,
  validateObject,
  validateString,
  validateUint32,
} = require('internal/validators');

const {
  isArrayBufferView,
  isAnyArrayBuffer
} = require('internal/util/types');

const {
  createSecureContext
} = require('_tls_common');

const {
  codes: {
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_ARG_TYPE,
    ERR_OUT_OF_RANGE,
  },
} = require('internal/errors');

const {
  endianness
} = require('os');
const kLittleEndian = endianness() === 'LE';

const kClose = Symbol('kClose');
const kDestroy = Symbol('kDestroy');
const kHandle = Symbol('kHandle');
const kOptions = Symbol('kOptions');
const kMaybeBind = Symbol('kMaybeBind');
const kSetTransportParams = Symbol('kSetTransportParams');
const kSetSecureOptions = Symbol('kSetSecureOptions');
const kSetPreferredAddress = Symbol('kSetPreferredAddress');
const kSetSessionResume = Symbol('kSetSessionResume');
const kState = Symbol('kState');

const kRandomConnectionIdStrategy = new RandomConnectionIDStrategy();

class EndpointConfig extends JSTransferable {
  constructor(options = {}) {
    super();
    validateObject(options, 'config');
    let { address = '127.0.0.1' } = options;
    const {
      port = 0,
      family = 'ipv4',
      retryTokenExpiration,
      maxWindowOverride,
      maxStreamWindowOverride,
      maxConnectionsPerHost,
      maxConnectionsTotal,
      maxStatelessResets,
      addressLRUSize,
      retryLimit,
      maxPayloadSize,
      unacknowledgedPacketThreshold,
      qlog,
      validateAddress,
      disableStatelessReset,
      rxPacketLoss,
      txPacketLoss,
      ccAlgorithm,
      udp,
    } = options;

    if (!isSocketAddress(address)) {
      if (typeof address !== 'string') {
        throw new ERR_INVALID_ARG_TYPE('options.address', [
          'string',
          'net.SocketAddress'
        ], address);
      }
      address = new SocketAddress({ address, port, family });
    }

    if (retryTokenExpiration !== undefined) {
      validateBigIntOrSafeInteger(
        retryTokenExpiration,
        'config.retryTokenExpiration');
    }

    if (maxWindowOverride !== undefined) {
      validateBigIntOrSafeInteger(
        maxWindowOverride,
        'config.maxWindowOverride');
    }

    if (maxStreamWindowOverride !== undefined) {
      validateBigIntOrSafeInteger(
        maxStreamWindowOverride,
        'config.maxStreamWindowOverride');
    }

    if (maxConnectionsPerHost !== undefined) {
      validateBigIntOrSafeInteger(
        maxConnectionsPerHost,
        'config.maxConnectionsPerHost');
    }

    if (maxConnectionsTotal !== undefined) {
      validateBigIntOrSafeInteger(
        maxConnectionsTotal,
        'config.maxConnectionsTotal');
    }

    if (maxStatelessResets !== undefined) {
      validateBigIntOrSafeInteger(
        maxStatelessResets,
        'config.maxStatelessResets');
    }

    if (addressLRUSize !== undefined) {
      validateBigIntOrSafeInteger(
        addressLRUSize,
        'config.addressLRUSize');
    }

    if (retryLimit !== undefined) {
      validateBigIntOrSafeInteger(
        retryLimit,
        'config.retryLimit');
    }

    if (maxPayloadSize !== undefined) {
      validateBigIntOrSafeInteger(
        maxPayloadSize,
        'config.mayPayloadSize');
    }

    if (unacknowledgedPacketThreshold !== undefined) {
      validateBigIntOrSafeInteger(
        unacknowledgedPacketThreshold,
        'config.unacknowledgedPacketThreshold');
    }

    if (qlog !== undefined)
      validateBoolean(qlog, 'config.qlog');

    if (validateAddress !== undefined)
      validateBoolean(validateAddress, 'config.validateAddress');

    if (disableStatelessReset !== undefined)
      validateBoolean(disableStatelessReset, 'config.disableStatelessReset');

    if (rxPacketLoss !== undefined) {
      validateNumber(rxPacketLoss, 'config.rxPacketLoss');
      if (rxPacketLoss < 0.0 || rxPacketLoss > 1.0) {
        throw new ERR_OUT_OF_RANGE(
          'config.rxPacketLoss',
          'between 0.0 and 1.0');
      }
    }

    if (txPacketLoss !== undefined) {
      validateNumber(txPacketLoss, 'config.txPacketLoss');
      if (txPacketLoss < 0.0 || txPacketLoss > 1.0) {
        throw new ERR_OUT_OF_RANGE(
          'config.txPacketLoss',
          'between 0.0 and 1.0');
      }
    }

    let ccAlgo;
    if (ccAlgorithm !== undefined) {
      validateString(ccAlgorithm, 'config.ccAlgorithm');
      switch (ccAlgorithm) {
        case 'cubic': ccAlgo = NGTCP2_CC_ALGO_CUBIC; break;
        case 'reno': ccAlgo = NGTCP2_CC_ALGO_RENO; break;
        default:
          throw new ERR_INVALID_ARG_VALUE(
            'config.ccAlgorithm',
            ccAlgorithm,
            'be either `cubic` or `reno`');
      }
    }

    if (udp !== undefined)
      validateObject(udp, 'options.udp');

    const {
      ipv6Only = false,
      receiveBufferSize = 0,
      sendBufferSize = 0,
      ttl = 0,
    } = udp || {};
    validateBoolean(ipv6Only, 'config.udp.ipv6Only');
    if (receiveBufferSize !== undefined)
      validateUint32(receiveBufferSize, 'config.udp.receiveBufferSize');
    if (sendBufferSize !== undefined)
      validateUint32(sendBufferSize, 'config.udp.sendBufferSize');
    if (ttl !== undefined)
      validateInt32(ttl, 'config.udp.ttl', 0, 255);

    this[kOptions] = {
      address,
      retryTokenExpiration,
      maxWindowOverride,
      maxStreamWindowOverride,
      maxConnectionsPerHost,
      maxConnectionsTotal,
      maxStatelessResets,
      addressLRUSize,
      retryLimit,
      maxPayloadSize,
      unacknowledgedPacketThreshold,
      qlog,
      validateAddress,
      disableStatelessReset,
      rxPacketLoss,
      txPacketLoss,
      ccAlgorithm,
      ipv6Only,
      receiveBufferSize,
      sendBufferSize,
      ttl,
    };

    this[kHandle] = new ConfigObject(
      address[kSocketAddressHandle],
      {
        retryTokenExpiration,
        maxWindowOverride,
        maxStreamWindowOverride,
        maxConnectionsPerHost,
        maxConnectionsTotal,
        maxStatelessResets,
        addressLRUSize,
        retryLimit,
        maxPayloadSize,
        unacknowledgedPacketThreshold,
        qlog,
        validateAddress,
        disableStatelessReset,
        rxPacketLoss,
        txPacketLoss,
        ccAlgorithm: ccAlgo,
        ipv6Only,
        receiveBufferSize,
        sendBufferSize,
        ttl,
      });
  }

  generateResetTokenSecret() {
    this[kHandle].generateResetTokenSecret();
  }

  setResetTokenSet(secret, encoding = 'hex') {
    if (typeof secret === 'string') {
      validateString('encoding');
      switch (encoding) {
        case 'hex':
          // Fall through
        case 'base64':
          // Fall through
        case 'base64url':
          secret = Buffer.from(secret, encoding);
          break;
        default:
          throw new ERR_INVALID_ARG_VALUE(
            'encoding',
            encoding,
            'be `hex`, `base64`, or `base64url');
      }
    }
    else if (!isAnyArrayBuffer(secret) && !isArrayBufferView(secret)) {
      throw new ERR_INVALID_ARG_TYPE('secret', [
        'string',
        'ArrayBuffer',
        'Buffer',
        'TypedArray',
        'DataView'
      ], secret);
    }
    if (secret.byteLength != 16) {
      throw new ERR_INVALID_ARG_VALUE(
        'secret',
        secret.byteLength,
        'be exactly 16 bytes long');
    }
    this[kHandle].setResetTokenSecret(secret);
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `EndpointConfig ${inspect(this[kOptions], opts)}`;
  }

  [kClone]() {
    const handle = this[kHandle];
    const options = this[kOptions];
    return {
      data: { handle, options },
      deserializeInfo: 'internal/quic/util:InternalConfig'
    };
  }

  [kDeserialize]({ handle, options }) {
    this[kHandle] = handle;
    this[kOptions] = options;
  }
}

class InternalConfig extends JSTransferable {}
InternalConfig.prototype.constructor = EndpointConfig.prototype.constructor;
ObjectSetPrototypeOf(InternalConfig.prototype, EndpointConfig.prototype);

class SessionOptions extends JSTransferable {
  constructor(options = {}) {
    super();
    validateObject(options, 'options');
    const {
      alpn = HTTP3_ALPN,
      hostname,
      context = createSecureContext(),
      preferredAddressStrategy,
      transportParams,
      secure,
    } = options;
    let { dcid } = options;

    validateString(alpn, 'options.alpn');

    if (hostname !== undefined)
      validateString(hostname, 'options.hostname');

    if (context == null ||
        typeof context !== 'object' ||
        typeof context.context !== 'object') {
      throw new ERR_INVALID_ARG_TYPE(
        'options.context',
        'SecureContext',
        context);
    }

    if (dcid !== undefined) {
      if (typeof dcid === 'string')
        dcid = Buffer.from(dcid, 'hex');
      else if (!isArrayBufferView(dcid) && !isAnyArrayBuffer(dcid)) {
        throw new ERR_INVALID_ARG_TYPE(
          'options.dcid',
          [
            'string',
            'ArrayBuffer',
            'Buffer',
            'TypedArray',
            'DataView'
          ],
          dcid);
      }

      if (dcid.byteLength > NGTCP2_MAX_CIDLEN) {
        throw new ERR_INVALID_ARG_VALUE(
          'options.dcid',
          dcid.byteLength,
          `be between 0 and ${NGTCP2_MAX_CIDLEN} bytes in length`);
      }
    }

    let pas;
    if (preferredAddressStrategy !== undefined) {
      validateString(
        preferredAddressStrategy,
        'options.preferredAddressStrategy');
      switch (preferredAddressStrategy) {
        case 'use':
          pas = NGTCP2_PREFERRED_ADDRESS_USE;
          break;
        case 'ignore':
          pas = NGTCP2_PREFERRED_ADDRESS_IGNORE;
          break;
        default:
          throw new ERR_INVALID_ARG_VALUE(
            'options.preferredAddressStrategy',
            preferredAddressStrategy,
            'be either `use` or `ignore`.');
      }
    }

    this[kOptions] = {
      alpn,
      hostname,
      context,
      dcid,
      preferredAddressStrategy,
    };

    this[kHandle] = new OptionsObject(
      alpn,
      context.context,
      hostname,
      dcid,
      pas,
      kRandomConnectionIdStrategy);

    this[kSetTransportParams](transportParams);
    this[kSetSecureOptions](secure);
  }

  [kSetSessionResume]() {
    // TODO(@jasnell): Implement
  }

  [kSetPreferredAddress](addr, name, family) {
    if (!isSocketAddress(addr)) {
      validateObject(addr, name);
      const {
        address,
        port
      } = addr;
      addr = new SocketAddress({ address, port, family });
    }
    if (addr.family !== family) {
      throw new ERR_INVALID_ARG_VALUE(
        `${name}.family`,
        addr.family,
        `must be ${family}`);
    }
    this[kHandle].setPreferredAddress(addr[kSocketAddressHandle]);
  }

  [kSetTransportParams](params) {
    if (params === undefined) return;
    validateObject(params);
    const {
      initialMaxStreamDataBidiLocal,
      initialMaxStreamDataBidiRemote,
      initialMaxStreamDataUni,
      initialMaxData,
      initialMaxStreamsBidi,
      initialMaxStreamsUni,
      maxIdleTimeout,
      activeConnectionIdLimit,
      ackDelayExponent,
      maxAckDelay,
      maxDatagramFrameSize,
      disableActiveMigration,
      preferredAddress: {
        ipv4,
        ipv6
      } = {},
    } = params;

    if (initialMaxStreamDataBidiLocal !== undefined) {
      validateBigIntOrSafeInteger(
        initialMaxStreamDataBidiLocal,
        'options.transportParams.initialMaxStreamDataBidiLocal');
    }

    if (initialMaxStreamDataBidiRemote !== undefined) {
      validateBigIntOrSafeInteger(
        initialMaxStreamDataBidiRemote,
        'options.transportParams.initialMaxStreamDataBidiRemote');
    }

    if (initialMaxStreamDataUni !== undefined) {
      validateBigIntOrSafeInteger(
        initialMaxStreamDataUni,
        'options.transportParams.initialMaxStreamDataUni');
    }

    if (initialMaxData !== undefined) {
      validateBigIntOrSafeInteger(
        initialMaxData,
        'options.transportParams.initialMaxData');
    }

    if (initialMaxStreamsBidi !== undefined) {
      validateBigIntOrSafeInteger(
        initialMaxStreamsBidi,
        'options.transportParams.initialMaxStreamsBidi');
    }

    if (initialMaxStreamsUni !== undefined) {
      validateBigIntOrSafeInteger(
        initialMaxStreamsUni,
        'options.transportParams.initialMaxStreamsUni');
    }

    if (maxIdleTimeout !== undefined) {
      validateBigIntOrSafeInteger(
        maxIdleTimeout,
        'options.transportParams.maxIdleTimeout');
    }

    if (activeConnectionIdLimit !== undefined) {
      validateBigIntOrSafeInteger(
        activeConnectionIdLimit,
        'options.transportParams.activeConnectionIdLimit');
    }

    if (ackDelayExponent !== undefined) {
      validateBigIntOrSafeInteger(
        ackDelayExponent,
        'options.transportParams.ackDelayExponent');
    }

    if (maxAckDelay !== undefined) {
      validateBigIntOrSafeInteger(
        maxAckDelay,
        'options.transportParams.maxAckDelay');
    }

    if (maxDatagramFrameSize !== undefined) {
      validateBigIntOrSafeInteger(
        maxDatagramFrameSize,
        'options.transportParams.maxDatagramFrameSize');
    }

    if (disableActiveMigration !== undefined) {
      validateBoolean(
        disableActiveMigration,
        'options.transportParams.disableActiveMigration');
    }

    if (ipv4 !== undefined) {
      this[kSetPreferredAddress](
        ipv4,
        'options.transportParams.preferredAddress.ipv4',
        'ipv4');
    }
    if (ipv6 !== undefined) {
      this[kSetPreferredAddress](
        ipv6,
        'options.transportParams.preferredAddress.ipv6',
        'ipv6');
    }

    this[kOptions].transportParams = {
      initialMaxStreamDataBidiLocal,
      initialMaxStreamDataBidiRemote,
      initialMaxStreamDataUni,
      initialMaxData,
      initialMaxStreamsBidi,
      initialMaxStreamsUni,
      maxIdleTimeout,
      activeConnectionIdLimit,
      ackDelayExponent,
      maxAckDelay,
      maxDatagramFrameSize,
      disableActiveMigration,
      preferredAddress: {
        ipv4,
        ipv6,
      },
    };

    this[kHandle].setTransportParams(this[kOptions].transportParams);
  }

  [kSetSecureOptions](options) {
    if (options === undefined) return;
    validateObject(options, 'options');
    const {
      rejectUnauthorized,
      enableTLSTrace,
      requestPeerCertificate,
      requestOCSP,
      verifyHostnameIdentity
    } = options;

    if (rejectUnauthorized !== undefined) {
      validateBoolean(
        rejectUnauthorized,
        'options.secure.rejectUnauthorized');
    }

    if (enableTLSTrace !== undefined) {
      validateBoolean(
        enableTLSTrace,
        'options.secure.enableTLSTrace');
    }

    if (requestPeerCertificate !== undefined) {
      validateBoolean(
        requestPeerCertificate,
        'options.secure.requestPeerCertificate');
    }

    if (requestOCSP !== undefined) {
      validateBoolean(
        requestOCSP,
        'options.secure.requestOCSP');
    }

    if (verifyHostnameIdentity !== undefined) {
      validateBoolean(
        verifyHostnameIdentity,
        'options.secure.verifyHostnameIdentity');
    }

    this[kOptions].secure = {
      rejectUnauthorized,
      enableTLSTrace,
      requestPeerCertificate,
      requestOCSP,
      verifyHostnameIdentity
    };

    this[kHandle].setTLSOptions(this[kOptions].secure);
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `SessionOptions ${inspect(this[kOptions], opts)}`;
  }

  [kClone]() {
    const handle = this[kHandle];
    const options = this[kOptions];
    return {
      data: { handle, options },
      deserializeInfo: 'internal/quic/util:InternalOptions'
    };
  }

  [kDeserialize]({ handle, options }) {
    this[kHandle] = handle;
    this[kOptions] = options;
  }
}

class InternalOptions extends JSTransferable {}
InternalOptions.prototype.constructor = SessionOptions.prototype.constructor;
ObjectSetPrototypeOf(InternalOptions.prototype, SessionOptions.prototype);

class EndpointInternalState {
  constructor(state) {
    this[kHandle] = new DataView(state);
  }

  set listening(on) {
    this[kHandle].setUint8(IDX_STATE_ENDPOINT_LISTENING, on ? 1 : 0);
  }

  get listening() {
    return !!this[kHandle].getUint8(IDX_STATE_ENDPOINT_LISTENING);
  }

  set busy(on) {
    this[kHandle].setUint8(IDX_STATE_ENDPOINT_BUSY, on ? 1 : 0);
  }

  get busy() {
    return !!this[kHandle].getUint8(IDX_STATE_ENDPOINT_BUSY);
  }

  set statelessResetDisabled(on = true) {
    this[kHandle].setUint8(
      IDX_STATE_ENDPOINT_STATELESS_RESET_DISABLED,
      on ? 1 : 0);
  }

  get statelessResetDisabled() {
    return !!this[kHandle].getUint8(
      IDX_STATE_ENDPOINT_STATELESS_RESET_DISABLED);
  }

  get waitingForCallbacks() {
    return !!this[kHandle].getUint8(IDX_STATE_ENDPOINT_WAITING_FOR_CALLBACKS);
  }

  get pendingCallbacks() {
    return this[kHandle].getBigUint64(
      IDX_STATE_ENDPOINT_PENDING_CALLBACKS,
      kLittleEndian);
  }
}

class EndpointStatistics {
  constructor() {
    throw new TypeError('Illegal constructor');
  }

  [kClose]() {
    // Closes off the connection to the internal data
    // by copying the current values into a new buffer.
    this[kHandle][IDX_STATS_ENDPOINT_DESTROYED_AT] = process.hrtime.bigint();
    this[kHandle] = new BigUint64Array(this[kHandle]);
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `EndpointStatistics ${inspect({
      bytesReceived: this.bytesReceived,
      bytesSent: this.bytesSent,
      packetsIgnored: this.packetsIgnored,
      packetsReceived: this.packetsReceived,
      packetsSent: this.packetsSent,
      serverSessions: this.serverSessions,
      clientSessions: this.clientSessions,
      statelessResetCount: this.statelessResetCount,
      serverBusyCount: this.serverBusyCount,
      startTime: this.startTime,
      boundTime: this.boundTime,
      listenTime: this.listenTime,
      duration: this.duration,
    }, opts)}`;
  }

  get bytesReceived() {
    return this[kHandle][IDX_STATS_ENDPOINT_BYTES_RECEIVED];
  }

  get bytesSent() {
    return this[kHandle][IDX_STATS_ENDPOINT_BYTES_SENT];
  }

  get packetsReceived() {
    return this[kHandle][IDX_STATS_ENDPOINT_PACKETS_RECEIVED];
  }

  get packetsIgnored() {
    return this[kHandle][IDX_STATS_ENDPOINT_PACKETS_IGNORED];
  }

  get packetsSent() {
    return this[kHandle][IDX_STATS_ENDPOINT_PACKETS_SENT];
  }

  get serverSessions() {
    return this[kHandle][IDX_STATS_ENDPOINT_SERVER_SESSIONS];
  }

  get clientSessions() {
    return this[kHandle][IDX_STATS_ENDPOINT_CLIENT_SESSIONS];
  }

  get statelessResetCount() {
    return this[kHandle][IDX_STATS_ENDPOINT_STATELESS_RESET_COUNT];
  }

  get serverBusyCount() {
    return this[kHandle][IDX_STATS_ENDPOINT_SERVER_BUSY_COUNT];
  }

  get startTime() {
    // TODO(@jasnell): Adjust to time origin
    return this[kHandle][IDX_STATS_ENDPOINT_CREATED_AT];
  }

  get duration() {
    const end = this[kHandle][IDX_STATS_ENDPOINT_DESTROYED_AT] ||
                process.hrtime.bigint();
    return end - this.startTime;
  }

  get boundTime() {
    return this[kHandle][IDX_STATS_ENDPOINT_BOUND_AT];
  }

  get listenTime() {
    return this[kHandle][IDX_STATS_ENDPOINT_LISTEN_AT];
  }
}

function internalEndpointStats(stats) {
  this[kHandle] = stats;
}

class SessionInternalState {
  constructor(state) {
    this[kHandle] = new DataView(state);
  }

  get clientHelloEnabled() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_CLIENT_HELLO_ENABLED);
  }

  set clientHelloEnabled(on = true) {
    this[kHandle].setUint8(IDX_STATE_SESSION_CLIENT_HELLO_ENABLED, on ? 1 : 0);
  }

  get datagramEnabled() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_DATAGRAM_ENABLED);
  }

  set datagramEnabled(on = true) {
    this[kHandle].setUint8(IDX_STATE_SESSION_DATAGRAM_ENABLED, on ? 1 : 0);
  }

  get keylogEnabled() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_KEYLOG_ENABLED);
  }

  set keylogEnabled(on = true) {
    this[kHandle].setUint8(IDX_STATE_SESSION_KEYLOG_ENABLED, on ? 1 : 0);
  }

  get ocspEnabled() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_OCSP_ENABLED);
  }

  set ocspEnabled(on = true) {
    this[kHandle].setUint8(IDX_STATE_SESSION_OCSP_ENABLED, on ? 1 : 0);
  }

  get pathValidatedEnabled() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_PATH_VALIDATED_ENABLED);
  }

  set pathValidatedEnabled(on = true) {
    this[kHandle].setUint8(
      IDX_STATE_SESSION_PATH_VALIDATED_ENABLED, on ? 1 : 0);
  }

  get usePreferredAddressEnabled() {
    return !!this[kHandle].getUint8(
      IDX_STATE_SESSION_USE_PREFERRED_ADDRESS_ENABLED);
  }

  set usePreferredAddressEnabled(on = true) {
    this[kHandle].setUint8(
      IDX_STATE_SESSION_USE_PREFERRED_ADDRESS_ENABLED, on ? 1 : 0)
  }

  get closing() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_CLOSING);
  }

  get closingTimerEnabled() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_CLOSING_TIMER_ENABLED);
  }

  get connectionCloseScope() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_CONNECTION_CLOSE_SCOPE);
  }

  get destroyed() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_DESTROYED);
  }

  get gracefulClosing() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_GRACEFUL_CLOSING);
  }

  get handshakeConfirmed() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_HANDSHAKE_CONFIRMED);
  }

  get idleTimeout() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_IDLE_TIMEOUT);
  }

  get maxDataLeft() {
    return this[kHandle].getBigUint64(
      IDX_STATE_SESSION_MAX_DATA_LEFT,
      kLittleEndian);
  }

  get maxBidirectionalStreams() {
    return this[kHandle].getBigUint64(
      IDX_STATE_SESSION_MAX_STREAMS_BIDI,
      kLittleEndian);
  }

  get maxUnidirectionalStreams() {
    return this[kHandle].getBigUint64(
      IDX_STATE_SESSION_MAX_STREAMS_UNI,
      kLittleEndian);
  }

  get silentClose() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_SILENT_CLOSE);
  }

  get statelessReset() {
    return !!this[kHandle].getUint8(IDX_STATE_SESSION_STATELESS_RESET);
  }
}

class SessionStatistics {
  constructor() {
    throw new TypeError('Illegal constructor');
  }

  [kClose]() {
    // Closes off the connection to the internal data
    // by copying the current values into a new buffer.
    this[kHandle][IDX_STATS_SESSION_DESTROYED_AT] = process.hrtime.bigint();
    this[kHandle] = new BigUint64Array(this[kHandle]);
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `EndpointStatistics ${inspect({
      startTime: this.startTime,
      duration: this.duration,
      bytesReceived: this.bytesReceived,
      bytesSent: this.bytesSent,
      bidirectionalStreamCount: this.bidirectionalStreamCount,
      unidirectionalStreamCount: this.unidirectionalStreamCount,
      inboundStreamCount: this.inboundStreamCount,
      outboundStreamCount: this.outboundStreamCount,
      keyUpdateCount: this.keyUpdateCount,
      lossRetransmitCount: this.lossRetransmitCount,
      maxBytesInFlight: this.maxBytesInFlight,
      blockedStreamCount: this.blockedStreamCount,
      bytesInFlight: this.bytesInFlight,
      cwnd: this.cwnd,
      perSecondDeliveryRate: this.perSecondDeliveryRate,
      initialRTT: this.initialRTT,
      latestRTT: this.latestRTT,
      minRTT: this.minRTT,
      maxUdpPayloadSize: this.maxUdpPayloadSize,
      ptoCount: this.ptoCount,
      rttvar: this.rttvar,
      smootedRTT: this.smootedRTT,
      ssthresh: this.ssthresh,
      receiveRate: this.receiveRate,
      sendRate: this.sendRate,
      handshakeCompletedTime: this.handshakeCompletedTime,
      handshakeConfirmedTime: this.handshakeConfirmedTime,
      lastSentTime: this.lastSentTime,
      lastReceivedTime: this.lastReceivedTime,
      closingTime: this.closingTime,
    }, opts)}`;
  }

  get bytesReceived() {
    return this[kHandle][IDX_STATS_SESSION_BYTES_RECEIVED];
  }

  get bytesSent() {
    return this[kHandle][IDX_STATS_SESSION_BYTES_SENT];
  }

  get bidirectionalStreamCount() {
    return this[kHandle][IDX_STATS_SESSION_BIDI_STREAM_COUNT];
  }

  get unidirectionalStreamCount() {
    return this[kHandle][IDX_STATS_SESSION_UNI_STREAM_COUNT];
  }

  get inboundStreamCount() {
    return this[kHandle][IDX_STATS_SESSION_STREAMS_IN_COUNT];
  }

  get outboundStreamCount() {
    return this[kHandle][IDX_STATS_SESSION_STREAMS_OUT_COUNT];
  }

  get keyUpdateCount() {
    return this[kHandle][IDX_STATS_SESSION_KEYUPDATE_COUNT];
  }

  get lossRetransmitCount() {
    return this[kHandle][IDX_STATS_SESSION_LOSS_RETRANSMIT_COUNT];
  }

  get maxBytesInFlight() {
    return this[kHandle][IDX_STATS_SESSION_MAX_BYTES_IN_FLIGHT];
  }

  get blockedStreamCount() {
    return this[kHandle][IDX_STATS_SESSION_BLOCK_COUNT];
  }

  get bytesInFlight() {
    return this[kHandle][IDX_STATS_SESSION_BYTES_IN_FLIGHT];
  }

  get cwnd() {
    return this[kHandle][IDX_STATS_SESSION_CWND];
  }

  get perSecondDeliveryRate() {
    return this[kHandle][IDX_STATS_SESSION_DELIVERY_RATE_SEC];
  }

  get initialRTT() {
    return this[kHandle][IDX_STATS_SESSION_INITIAL_RTT];
  }

  get latestRTT() {
    return this[kHandle][IDX_STATS_SESSION_LATEST_RTT];
  }

  get maxUdpPayloadSize() {
    return this[kHandle][IDX_STATS_SESSION_MAX_UDP_PAYLOAD_SIZE];
  }

  get minRTT() {
    return this[kHandle][IDX_STATS_SESSION_MIN_RTT];
  }

  get ptoCount() {
    return this[kHandle][IDX_STATS_SESSION_PTO_COUNT];
  }

  get rttvar() {
    return this[kHandle][IDX_STATS_SESSION_RTTVAR];
  }

  get smootedRTT() {
    return this[kHandle][IDX_STATS_SESSION_SMOOTHED_RTT];
  }

  get ssthresh() {
    return this[kHandle][IDX_STATS_SESSION_SSTHRESH];
  }

  get receiveRate() {
    return this[kHandle][IDX_STATS_SESSION_RECEIVE_RATE];
  }

  get sendRate() {
    return this[kHandle][IDX_STATS_SESSION_SEND_RATE];
  }

  get startTime() {
    // TODO(@jasnell): Adjust to time origin
    return this[kHandle][IDX_STATS_SESSION_CREATED_AT];
  }

  get duration() {
    const end = this[kHandle][IDX_STATS_SESSION_DESTROYED_AT] ||
                process.hrtime.bigint();
    return end - this.startTime;
  }

  get handshakeCompletedTime() {
    return this[kHandle][IDX_STATS_SESSION_HANDSHAKE_COMPLETED_AT];
  }

  get handshakeConfirmedTime() {
    return this[kHandle][IDX_STATS_SESSION_HANDSHAKE_CONFIRMED_AT];
  }

  get lastSentTime() {
    return this[kHandle][IDX_STATS_SESSION_SENT_AT];
  }

  get lastReceivedTime() {
    return this[kHandle][IDX_STATS_SESSION_RECEIVED_AT];
  }

  get closingTime() {
    return this[kHandle][IDX_STATS_SESSION_CLOSING_AT];
  }
}

function internalSessionStats(stats) {
  this[kHandle] = stats;
}

module.exports = {
  EndpointConfig,
  EndpointInternalState,
  EndpointStatistics,
  SessionOptions,
  SessionInternalState,
  SessionStatistics,
  internalEndpointStats,
  internalSessionStats,

  kClose,
  kDestroy,
  kHandle,
  kOptions,
  kMaybeBind,
  kSetTransportParams,
  kSetSecureOptions,
  kSetPreferredAddress,
  kSetSessionResume,
  kState,
};
