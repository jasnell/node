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

const {
  isSocketAddress,
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
} = require('internal/errors');

const {
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
  lookup
} = require('dns/promises');

const kHandle = Symbol('kHandle');
const kType = Symbol('kType');
const kOptions = Symbol('kOptions');
const kCreateClientContext = Symbol('kCreateClientContext');
const kCreateServerContext = Symbol('kCreateServerContext');
const kSetSessionResume = Symbol('kSetSessionResume');
const kSetPreferredAddress = Symbol('kSetPreferredAddress');
const kSetTransportParams = Symbol('kSetTransportParams');
const kSetSecureOptions = Symbol('kSetSecureOptions');

const kResetTokenSecretLen = 16;

const kRandomConnectionIdStrategy = new RandomConnectionIDStrategy();

async function defaultLookup(name, family) {
  let address = name;
  switch (family) {
    case 'ipv4':
      ({ address } = await lookup(name, 4));
      break;
    case 'ipv6':
      ({ address } = await lookup(name, 6));
      break;
  }
  return address;
}

// Immutable configuration options for a QUIC Endpoint
class EndpointConfig {
  [kType] = 'endpoint-config';

  static isEndpointConfig(val) {
    return val?.[kType] === 'endpoint-config';
  }

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

    if (!isSocketAddress(address)) {
      if (address == null || typeof address !== 'object') {
        throw new ERR_INVALID_ARG_TYPE(
          'options.address',
          ['SocketAddress', 'Object']);
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

// Immutable configuration options for a QUIC Session
class SessionConfig {
  [kType] = 'session-config';

  static isSessionConfig(val) {
    return val?.[kType] === 'session-config';
  }

  constructor(options = {}) {
    validateObject(options, 'options');
    const {
      alpn = HTTP3_ALPN,
      hostname,
      preferredAddressStrategy,
      transportParams,
      secure,
      // Callback function invoked when a new server
      // session is created on a listening endpoint.
      onSession = (session) => {},
      onLookup = defaultLookup,
    } = options;
    let { dcid } = options;

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

    if (onSession !== undefined && typeof onSession !== 'function') {
      throw new ERR_INVALID_ARG_TYPE(
        'options.onSession',
        'function',
        onSession);
    }

    if (onLookup !== undefined && typeof onLookup !== 'function') {
      throw new ERR_INVALID_ARG_TYPE(
        'options.onLookup',
        'function',
        onLookup);
    }

    this[kOptions] = {
      alpn,
      hostname,
      dcid,
      preferredAddressStrategy,
      onSession,
      onLookup,
    };

    this[kHandle] = new OptionsObject(
      alpn,
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

    this[kHandle].setTLSOptions(this[kOptions].secure);
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

  [kCreateClientContext]() {
    return configSecureContext(
      createClientSecureContext(),
      this[kOptions].secure);
  }

  [kCreateServerContext]() {
    return configSecureContext(
      createServerSecureContext(),
      this[kOptions].secure);
  }

  get onSession() {
    return this[kOptions]?.onSession;
  }

  get onLookup() {
    return this[kOptions]?.onLookup;
  }
}

module.exports = {
  EndpointConfig,
  SessionConfig,
  kCreateClientContext,
  kCreateServerContext,
  kHandle,
};
