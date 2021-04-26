'use strict';

const {
  Symbol,
} = primordials;

const { Buffer } = require('buffer');

const {
  ConfigObject,
  OptionsObject,
  RandomConnectionIDStrategy,
  createClientSecureContext,
  createServerSecureContext,
  HTTP3_ALPN,
  NGTCP2_CC_ALGO_CUBIC,
  NGTCP2_CC_ALGO_RENO,
  NGTCP2_MAX_CIDLEN,
  NGTCP2_PREFERRED_ADDRESS_USE,
  NGTCP2_PREFERRED_ADDRESS_IGNORE,
} = internalBinding('quic');

// If the HTTP3_ALPN is undefined, the Node.js binary
// was built without QUIC support, in which case we
// don't want to export anything here.
if (HTTP3_ALPN === undefined)
  return;

const {
  SocketAddress,
  kHandle: kSocketAddressHandle,
} = require('internal/socketaddress');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  isArrayBufferView,
  isAnyArrayBuffer,
} = require('internal/util/types');

const {
  configSecureContext,
} = require('internal/tls');

const {
  inspect,
} = require('util');

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_OUT_OF_RANGE,
  },
  AbortError,
} = require('internal/errors');

const {
  validateAbortSignal,
  validateBigIntOrSafeInteger,
  validateBoolean,
  validateInt32,
  validateNumber,
  validateObject,
  validatePort,
  validateString,
  validateUint32,
} = require('internal/validators');

const {
  AbortSignal,
} = require('internal/abort_controller');

const kHandle = Symbol('kHandle');
const kType = Symbol('kType');
const kSide = Symbol('kSide');
const kOptions = Symbol('kOptions');
const kSecureContext = Symbol('kSecureContext');
const kGetPreferredAddress = Symbol('kGetPreferredAddress');
const kGetTransportParams = Symbol('kGetTransportParams');
const kGetSecureOptions = Symbol('kGetSecureOptions');

const kResetTokenSecretLen = 16;

const kRandomConnectionIdStrategy = new RandomConnectionIDStrategy();

/**
 *
 * @typedef { import('../socketaddress').SocketAddressOrOptions
 * } SocketAddressOrOptions
 *
 * @typedef {Object} UDPOptions
 * @property {boolean} [ipv6Only]
 * @property {number} [receiveBufferSize]
 * @property {number} [sendBufferSize]
 * @property {number} [ttl]
 *
 * @typedef {Object} EndpointConfigOptions
 * @property {SocketAddressOrOptions} [address]
 * @property {number|bigint} [retryTokenExpiration]
 * @property {number|bigint} [tokenExpiration]
 * @property {number|bigint} [maxWindowOverride]
 * @property {number|bigint} [maxStreamWindowOverride]
 * @property {number|bigint} [maxConnectionsPerHost]
 * @property {number|bigint} [maxConnectionsTotal]
 * @property {number|bigint} [maxStatelessResets]
 * @property {number|bigint} [addressLRUSize]
 * @property {number|bigint} [retryLimit]
 * @property {number|bigint} [maxPayloadSize]
 * @property {number|bigint} [unacknowledgedPacketThreshold]
 * @property {boolean} [qlog]
 * @property {boolean} [validateAddress]
 * @property {boolean} [disableStatelessReset]
 * @property {number} [rxPacketLoss]
 * @property {number} [txPacketLoss]
 * @property {string} [ccAlgorithm]
 * @property {UDPOptions} [udp]
 * @property {ArrayBuffer|TypedArray|DataView} [resetTokenSecret]
 *
 * @typedef {Object} PreferredAddress
 * @property {SocketAddressOrOptions} [ipv4]
 * @property {SocketAddressOrOptions} [ipv6]
 *
 * @typedef {Object} TransportParams
 * @property {number|bigint} [initialMaxStreamDataBidiLocal]
 * @property {number|bigint} [initialMaxStreamDataBidiRemote]
 * @property {number|bigint} [initialMaxStreamDataUni]
 * @property {number|bigint} [initialMaxData]
 * @property {number|bigint} [initialMaxStreamsBidi]
 * @property {number|bigint} [initialMaxStreamsUni]
 * @property {number|bigint} [maxIdleTimeout]
 * @property {number|bigint} [activeConnectionIdLimit]
 * @property {number|bigint} [ackDelayExponent]
 * @property {number|bigint} [maxAckDelay]
 * @property {number|bigint} [maxDatagramFrameSize]
 * @property {boolean} [disableActiveMigration]
 * @property {PreferredAddress} [preferredAddress]
 *
 * @typedef {Object} SecureOptions
 * @property {*} [ca]
 * @property {*} [cert]
 * @property {*} [sigalgs]
 * @property {*} [ciphers]
 * @property {*} [clientCertEngine]
 * @property {*} [crl]
 * @property {*} [dhparam]
 * @property {*} [ecdhCurve]
 * @property {*} [key]
 * @property {Object} [privateKey]
 * @property {string} [privateKey.engine]
 * @property {string} [privateKey.identifier]
 * @property {*} [passphrase]
 * @property {*} [pfx]
 * @property {*} [secureOptions]
 * @property {*} [sessionIdContext]
 * @property {*} [ticketKeys]
 * @property {*} [sessionTimeout]
 * @property {boolean} [enableTLSTrace]
 * @property {number} [handshakeTimeout]
 * @property {number} [minDHSize]
 * @property {Function} [pskCallback]
 * @property {boolean} [rejectUnauthorized]
 * @property {boolean} [requestOCSP]
 * @property {boolean} [requestPeerCertificate]
 * @property {boolean} [verifyHostnameIdentity]
 *
 * @typedef {Object} SessionConfigOptions
 * @property {string} [alpn] - The protocol identifier
 * @property {string} [hostname] - The SNI hostname
 * @property {string} [preferredAddressStrategy] - One of 'use' or 'ignore'
 * @property {TransportParams} [transportParams]
 * @property {SecureOptions} [secure]
 * @property {AbortSignal} [signal]
 * @typedef {EndpointConfig|EndpointConfigOptions} EndpointConfigOrOptions
 * @typedef {SessionConfig|SessionConfigOptions} SessionConfigOrOptions
 *
 * @typedef {import('../blob.js').Blob} Blob
 * @typedef {import('stream').Readable} Readable
 * @typedef {ArrayBuffer|TypedArray|DataView|Blob|Readable|string} StreamPayload
 * @typedef {Object} StreamOptionsInit
 * @property {boolean} [unidirectional]
 * @property {Object|Map<string,string>} [headers]
 * @property {Object|Map<string,string>} [trailers]
 * @property {StreamPayload|Promise<StreamPayload>} [body]
 * @property {string} [encoding]
 *
 * @typedef {Object} ResponseOptionsInit
 * @property {Object|Map<string,string>} [headers]
 * @property {Object|Map<string,string>} [trailers]
 * @property {StreamPayload|Promise<StreamPayload>} [body]
 * @property {string} [encoding]
 */
class EndpointConfig {
  [kType] = 'endpoint-config';

  /**
   * @param {*} val
   * @returns {boolean}
   */
  static isEndpointConfig(val) {
    return val?.[kType] === 'endpoint-config';
  }

  /**
   * @param {EndpointConfigOptions} options
   */
  constructor(options = {}) {
    validateObject(options, 'options');
    let { address = new SocketAddress({ address: '127.0.0.1' }) } = options;
    const {
      retryTokenExpiration,
      tokenExpiration,
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
      resetTokenSecret,
    } = options;

    if (!SocketAddress.isSocketAddress(address)) {
      if (address == null || typeof address !== 'object') {
        throw new ERR_INVALID_ARG_TYPE(
          'options.address',
          ['SocketAddress', 'Object'],
          address);
      }
      const {
        address: _address = '127.0.0.1',
        port = 0,
        family = 'ipv4',
      } = address;
      validateString(_address, 'options.address.address');
      validatePort(port, 'options.address.port');
      validateString(family, 'options.address.family');
      address = new SocketAddress({ address: _address, port, family });
    }

    if (retryTokenExpiration !== undefined) {
      validateBigIntOrSafeInteger(
        retryTokenExpiration,
        'options.retryTokenExpiration');
    }

    if (tokenExpiration !== undefined) {
      validateBigIntOrSafeInteger(
        tokenExpiration,
        'options.tokenExpiration');
    }

    if (maxWindowOverride !== undefined) {
      validateBigIntOrSafeInteger(
        maxWindowOverride,
        'options.maxWindowOverride');
    }

    if (maxStreamWindowOverride !== undefined) {
      validateBigIntOrSafeInteger(
        maxStreamWindowOverride,
        'options.maxStreamWindowOverride');
    }

    if (maxConnectionsPerHost !== undefined) {
      validateBigIntOrSafeInteger(
        maxConnectionsPerHost,
        'options.maxConnectionsPerHost');
    }

    if (maxConnectionsTotal !== undefined) {
      validateBigIntOrSafeInteger(
        maxConnectionsTotal,
        'options.maxConnectionsTotal');
    }

    if (maxStatelessResets !== undefined) {
      validateBigIntOrSafeInteger(
        maxStatelessResets,
        'options.maxStatelessResets');
    }

    if (addressLRUSize !== undefined) {
      validateBigIntOrSafeInteger(
        addressLRUSize,
        'options.addressLRUSize');
    }

    if (retryLimit !== undefined) {
      validateBigIntOrSafeInteger(
        retryLimit,
        'options.retryLimit');
    }

    if (maxPayloadSize !== undefined) {
      validateBigIntOrSafeInteger(
        maxPayloadSize,
        'options.mayPayloadSize');
    }

    if (unacknowledgedPacketThreshold !== undefined) {
      validateBigIntOrSafeInteger(
        unacknowledgedPacketThreshold,
        'options.unacknowledgedPacketThreshold');
    }

    if (qlog !== undefined)
      validateBoolean(qlog, 'options.qlog');

    if (validateAddress !== undefined)
      validateBoolean(validateAddress, 'options.validateAddress');

    if (disableStatelessReset !== undefined)
      validateBoolean(disableStatelessReset, 'options.disableStatelessReset');

    if (rxPacketLoss !== undefined) {
      validateNumber(rxPacketLoss, 'options.rxPacketLoss');
      if (rxPacketLoss < 0.0 || rxPacketLoss > 1.0) {
        throw new ERR_OUT_OF_RANGE(
          'options.rxPacketLoss',
          'between 0.0 and 1.0');
      }
    }

    if (txPacketLoss !== undefined) {
      validateNumber(txPacketLoss, 'options.txPacketLoss');
      if (txPacketLoss < 0.0 || txPacketLoss > 1.0) {
        throw new ERR_OUT_OF_RANGE(
          'config.txPacketLoss',
          'between 0.0 and 1.0');
      }
    }

    let ccAlgo;
    if (ccAlgorithm !== undefined) {
      validateString(ccAlgorithm, 'options.ccAlgorithm');
      switch (ccAlgorithm) {
        case 'cubic': ccAlgo = NGTCP2_CC_ALGO_CUBIC; break;
        case 'reno': ccAlgo = NGTCP2_CC_ALGO_RENO; break;
        default:
          throw new ERR_INVALID_ARG_VALUE(
            'options.ccAlgorithm',
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
    validateBoolean(ipv6Only, 'options.udp.ipv6Only');
    if (receiveBufferSize !== undefined)
      validateUint32(receiveBufferSize, 'options.udp.receiveBufferSize');
    if (sendBufferSize !== undefined)
      validateUint32(sendBufferSize, 'options.udp.sendBufferSize');
    if (ttl !== undefined)
      validateInt32(ttl, 'options.udp.ttl', 0, 255);

    if (resetTokenSecret !== undefined) {
      if (!isAnyArrayBuffer(resetTokenSecret) &&
          !isArrayBufferView(resetTokenSecret)) {
        throw new ERR_INVALID_ARG_TYPE('options.resetTokenSecret', [
          'ArrayBuffer',
          'Buffer',
          'TypedArray',
          'DataView',
        ], resetTokenSecret);
      }
      if (resetTokenSecret.byteLength !== kResetTokenSecretLen) {
        throw new ERR_INVALID_ARG_VALUE(
          'options.resetTokenSecret',
          resetTokenSecret.byteLength,
          `be exactly ${kResetTokenSecretLen} bytes long`);
      }
    }

    this[kOptions] = {
      address,
      retryTokenExpiration,
      tokenExpiration,
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
      resetTokenSecret: resetTokenSecret || '(generated)',
    };

    this[kHandle] = new ConfigObject(
      address[kSocketAddressHandle],
      {
        retryTokenExpiration,
        tokenExpiration,
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

    if (resetTokenSecret !== undefined) {
      this[kHandle].setResetTokenSecret(resetTokenSecret);
    } else {
      this[kHandle].generateResetTokenSecret();
    }
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
}

class SessionConfig {
  [kType] = 'session-config';

  /**
   * @param {*} val
   * @returns
   */
  static isSessionConfig(val) {
    return val?.[kType] === 'session-config';
  }

  /**
   * @param {string} side - One of either 'client' or 'server'
   * @param {SessionConfigOptions} [options]
   */
  constructor(side, options = {}) {
    validateString(side, 'side');
    validateObject(options, 'options');
    const {
      alpn = HTTP3_ALPN,
      hostname,
      preferredAddressStrategy,
      transportParams,
      secure,
      signal,
    } = options;
    let { dcid } = options;

    switch (side) {
      case 'client':
        this[kSide] = 'client';
        break;
      case 'server':
        this[kSide] = 'server';
        break;
      default:
        throw new ERR_INVALID_ARG_VALUE(
          'side',
          side,
          'be either `client` or `server`.');
    }

    validateString(alpn, 'options.alpn');

    if (hostname !== undefined)
      validateString(hostname, 'options.hostname');

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
            'DataView',
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

    if (signal !== undefined) {
      validateAbortSignal(signal, 'options.signal');
      if (signal.aborted)
        throw new AbortError();
    }

    this[kOptions] = {
      alpn,
      hostname,
      dcid,
      preferredAddressStrategy,
      signal,
    };

    this[kGetSecureOptions](secure);

    this[kSecureContext] = side === 'server' ?
      createServerSecureContext() :
      createClientSecureContext();
    configSecureContext(this[kSecureContext]);

    this[kHandle] = new OptionsObject(
      alpn,
      hostname,
      dcid,
      pas,
      kRandomConnectionIdStrategy,
      this[kOptions].secure,
      ...this[kGetTransportParams](transportParams));
  }

  /** @type {string} */
  get side() { return this[kSide]; }

  [kGetPreferredAddress](addr, name, family) {
    if (!SocketAddress.isSocketAddress(addr)) {
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
    return addr[kSocketAddressHandle];
  }

  [kGetTransportParams](params) {
    if (params === undefined) return [, , , ];
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

    const ipv4PreferredAddress = ipv4 !== undefined ?
      this[kGetPreferredAddress](
        ipv4,
        'options.transportParams.preferredAddress.ipv4',
        'ipv4') : undefined;
    const ipv6PreferredAddress = ipv6 !== undefined ?
      this[kGetPreferredAddress](
        ipv6,
        'options.transportParams.preferredAddress.ipv6',
        'ipv6') : undefined;

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

    return [
      this[kOptions].transportParams,
      ipv4PreferredAddress,
      ipv6PreferredAddress,
    ];
  }

  [kGetSecureOptions](options) {
    if (options === undefined) return;
    validateObject(options, 'options');
    const {
      // Secure context options
      ca,
      cert,
      sigalgs,
      ciphers,
      clientCertEngine,
      crl,
      dhparam,
      ecdhCurve,
      key,
      privateKey: {
        engine: privateKeyEngine,
        identifier: privateKeyIdentifier,
      } = {},
      passphrase,
      pfx,
      secureOptions,
      sessionIdContext = 'node.js quic server',
      ticketKeys,
      sessionTimeout,

      enableTLSTrace,
      handshakeTimeout,
      minDHSize,
      pskCallback,
      rejectUnauthorized,
      requestOCSP,
      requestPeerCertificate,
      verifyHostnameIdentity
    } = options;

    if (enableTLSTrace !== undefined) {
      validateBoolean(
        enableTLSTrace,
        'options.secure.enableTLSTrace');
    }

    if (handshakeTimeout !== undefined)
      validateUint32(handshakeTimeout, 'options.secure.handshakeTimeout', true);

    if (minDHSize !== undefined)
      validateUint32(minDHSize, 'options.secure.minDHSize', true);

    if (pskCallback !== undefined && typeof pskCallback !== 'function') {
      throw new ERR_INVALID_ARG_TYPE(
        'options.secure.pskCallback',
        'function',
        pskCallback);
    }

    if (rejectUnauthorized !== undefined) {
      validateBoolean(
        rejectUnauthorized,
        'options.secure.rejectUnauthorized');
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
      ca,
      cert,
      sigalgs,
      ciphers,
      clientCertEngine,
      crl,
      dhparam,
      ecdhCurve,
      key,
      privateKeyEngine,
      privateKeyIdentifier,
      passphrase,
      pfx,
      secureOptions,
      sessionIdContext,
      ticketKeys,
      sessionTimeout,
      enableTLSTrace,
      handshakeTimeout,
      minDHSize,
      pskCallback,
      rejectUnauthorized,
      requestOCSP,
      requestPeerCertificate,
      verifyHostnameIdentity,
    };

    return this[kOptions].secure;
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `SessionConfig ${inspect(this[kOptions], opts)}`;
  }

  /** @type {AbortSignal} */
  get signal() {
    return this[kOptions].signal;
  }
}

class StreamOptions {
  [kType] = 'stream-options';

  /**
   * @param {*} val
   * @returns
   */
  static isStreamOptions(val) {
    return val?.[kType] === 'stream-options';
  }

  /**
   * @param {StreamOptionsInit} [options]
   */
  constructor(options = {}) {
    validateObject(options, 'options');
    const {
      unidirectional = false,
      headers,
      trailers,
      body,
      encoding,
    } = options;

    this[kOptions] = {
      unidirectional,
      headers,
      trailers,
      body,
      encoding,
    };
  }

  get unidirectional() {
    return this[kOptions].unidirectional;
  }

  get headers() {
    return this[kOptions].headers;
  }

  get body() {
    return this[kOptions].body;
  }

  get encoding() {
    return this[kOptions].encoding;
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `StreamOptions ${inspect(this[kOptions], opts)}`;
  }
}

class ResponseOptions {
  [kType] = 'response-options';

  /**
   * @param {*} val
   * @returns
   */
  static isResponseOptions(val) {
    return val?.[kType] === 'response-options';
  }

  /**
   * @param {ResponseOptionsInit} [options]
   */
  constructor(options = {}) {
    validateObject(options, 'options');
    const {
      headers,
      trailers,
      body,
      encoding,
    } = options;

    this[kOptions] = {
      headers,
      trailers,
      body,
      encoding,
    };
  }

  get headers() {
    return this[kOptions].headers;
  }

  get body() {
    return this[kOptions].body;
  }

  get encoding() {
    return this[kOptions].encoding;
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `ResponseOptions ${inspect(this[kOptions], opts)}`;
  }
}

/**
 * @param {ArrayBuffer|TypedArray|DataView} sessionTicket
 * @param {ArrayBuffer|TypedArray|DataView} transportParams
 * @returns {void}
 */
function validateResumeOptions(sessionTicket, transportParams) {
  // Silently ignore the options if either is not provided
  if (sessionTicket === undefined || transportParams === undefined)
    return;

  if (!isAnyArrayBuffer(sessionTicket) && !isArrayBufferView(sessionTicket)) {
    throw new ERR_INVALID_ARG_TYPE(
      'resume.sessionTicket', [
        'ArrayBuffer',
        'TypedArray',
        'DataView',
        'Buffer',
      ],
      sessionTicket);
  }

  if (!isAnyArrayBuffer(transportParams) &&
      !isArrayBufferView(transportParams)) {
    throw new ERR_INVALID_ARG_TYPE(
      'resume.transportParams', [
        'ArrayBuffer',
        'TypedArray',
        'DataView',
        'Buffer',
      ],
      transportParams);
  }
}

module.exports = {
  EndpointConfig,
  SessionConfig,
  StreamOptions,
  ResponseOptions,
  validateResumeOptions,
  kSecureContext,
  kHandle,
  // Exported for testing purposes only
  kOptions,
};
