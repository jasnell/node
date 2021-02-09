'use strict';

const {
  ObjectSetPrototypeOf,
  Symbol
} = primordials;

require('net').BlockList;

const {
  ConfigObject,
  OptionsObject,
  createEndpoint: _createEndpoint,
  AF_INET,
  AF_INET6,
  NGTCP2_CC_ALGO_CUBIC,
  NGTCP2_CC_ALGO_RENO,
  NGTCP2_PREFERRED_ADDRESS_IGNORE,
  NGTCP2_PREFERRED_ADDRESS_USE,
  NGTCP2_MAX_CIDLEN,
  HTTP3_ALPN,
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
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  inspect,
} = require('util');

const {
  validateBigIntOrSafeInteger,
  validateBoolean,
  validateNumber,
  validateObject,
  validatePort,
  validateString,
} = require('internal/validators');

const {
  isArrayBufferView,
  isAnyArrayBuffer
} = require('internal/util/types');

const {
  createSecureContext
} = require('_tls_common');

const {
  createSocket
} = require('dgram');

const {
  kStateSymbol: kDgramStateSymbol,
} = require('internal/dgram');

const {
  codes: {
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_ARG_TYPE,
    ERR_OUT_OF_RANGE,
  },
} = require('internal/errors');

const kHandle = Symbol('kHandle');
const kOptions = Symbol('kOptions');
const kSetTransportParams = Symbol('kSetTransportParams');
const kSetSecureOptions = Symbol('kSetSecureOptions');
const kSetPreferredAddress = Symbol('kSetPreferredAddress');
const kSetSessionResume = Symbol('kSetSessionResume');
const kUdp = Symbol('kUdp');

class EndpointConfig extends JSTransferable {
  constructor(options = {}) {
    super();
    validateObject(options, 'config');
    const {
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
    } = options;

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

    this[kOptions] = {
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
    };

    this[kHandle] = new ConfigObject({
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
      deserializeInfo: 'internal/quic/quic:InternalConfig'
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
      pas);

    this[kSetTransportParams](transportParams);
    this[kSetSecureOptions](secure);
  }

  [kSetSessionResume]() {
    // TODO(@jasnell): Implement
  }

  [kSetPreferredAddress](addr, name, family) {
    validateObject(addr, name);
    const {
      address = '',
      port = 0,
    } = addr;
    validateString(address, `${name}.address`);
    validatePort(port, `${name}.port`, { allowZero: true });
    if (!this[kHandle].setPreferredAddress(family, address, port)) {
      throw new ERR_INVALID_ARG_VALUE(`${name}.address`, address);
    }
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
        AF_INET);
    }
    if (ipv6 !== undefined) {
      this[kSetPreferredAddress](
        ipv6,
        'options.transportParams.preferredAddress.ipv6',
        AF_INET6);
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
      deserializeInfo: 'internal/quic/quic:InternalOptions'
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

class Endpoint {
  constructor() {
    throw new TypeError('Illegal constructor');
  }

  listen(options = new SessionOptions()) {
    validateObject(options, 'options');
    if (!(options instanceof SessionOptions))
      options = new SessionOptions(options);

    this[kHandle].startListen(options[kHandle]);
    return this;
  }

  ref() {
    this[kUdp].ref();
    return this;
  }

  unref() {
    this[kUdp].unref();
    return this;
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

class InternalEndpoint {
  constructor(config, udpWrap) {
    this[kHandle] = _createEndpoint(config[kHandle], udpWrap);
    this[kUdp] = udpWrap;
  }
}

InternalEndpoint.prototype.constructor = Endpoint.prototype.constructor;
ObjectSetPrototypeOf(InternalEndpoint.prototype, Endpoint.prototype);

function createEndpoint(config = new EndpointConfig(), udp) {
  validateObject(config, 'config');
  if (!(config instanceof EndpointConfig))
    config = new EndpointConfig(config);

  if (udp === undefined)
    udp = createSocket('udp4');
  else if (typeof udp === 'string')
    udp = createSocket(udp);

  if (udp[kDgramStateSymbol] != null &&
      typeof udp[kDgramStateSymbol] !== 'object') {
    throw new ERR_INVALID_ARG_TYPE('udp', 'dgram.Socket', udp);
  }

  return new InternalEndpoint(config, udp[kDgramStateSymbol].handle);
}

module.exports = {
  EndpointConfig,
  SessionOptions,
  createEndpoint,
};
