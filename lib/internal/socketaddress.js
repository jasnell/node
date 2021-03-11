'use strict';

const {
  ObjectSetPrototypeOf,
  Symbol
} = primordials;

const {
  SocketAddress: SocketAddressHandle,
  AF_INET,
  AF_INET6,
  kLabelMask,
} = internalBinding('block_list');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  inspect,
} = require('internal/util/inspect');

const kHandle = Symbol('kHandle');
const kDetail = Symbol('kDetail');

const {
  JSTransferable,
  kClone,
  kDeserialize,
} = require('internal/worker/js_transferable');

const {
  codes: {
    ERR_INVALID_ARG_VALUE,
    ERR_OUT_OF_RANGE,
  },
} = require('internal/errors');

const {
  validateObject,
  validatePort,
  validateString,
  validateUint32,
} = require('internal/validators');

function isSocketAddress(value) {
  return value?.[kDetail] !== undefined;
}

class SocketAddress extends JSTransferable {
  constructor(options = {}) {
    validateObject(options, 'options');
    const {
      family = 'ipv4',
      address = (family === 'ipv4' ? '0.0.0.0' : '::0'),
      port = 0,
      flowlabel,
    } = options;
    validateString(family, 'options.family', family);
    let type;
    switch (family.toLowerCase()) {
      case 'ipv4': type = AF_INET; break;
      case 'ipv6': type = AF_INET6; break;
      default:
        throw new ERR_INVALID_ARG_VALUE('options.family', family);
    }
    validateString(address, 'options.address', address);
    validatePort(port, 'options.port', { allowZero: true });
    if (flowlabel !== undefined && type === AF_INET6) {
      validateUint32(flowlabel, 'options.flowlabel');
      if (flowlabel > kLabelMask) {
        throw new ERR_OUT_OF_RANGE(
          'options.flowlabel',
          `<= ${kLabelMask}`,
          flowlabel);
      }
    }
    super();
    this[kHandle] = new SocketAddressHandle(type, address, port, flowlabel);
    this[kDetail] = this[kHandle].detail({
      family: undefined,
      host: undefined,
      port: 0,
      flowlabel: undefined,
    });
  }

  get address() {
    return this[kDetail]?.host;
  }

  get family() {
    return this[kDetail]?.family;
  }

  get port() {
    return this[kDetail]?.port;
  }

  get flowlabel() {
    return this[kDetail]?.flowlabel;
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `SocketAddress ${inspect({
      address: this.address,
      port: this.port,
      family: this.family,
      flowlabel: this.flowlabel,
    }, opts)}`;
  }

  [kClone]() {
    const handle = this[kHandle];
    return {
      data: { handle },
      deserializeInfo: 'internal/socketaddress:InternalSocketAddress'
    };
  }

  [kDeserialize]({ handle }) {
    this[kHandle] = handle;
    this[kDetail] = this[kHandle].detail({
      family: undefined,
      host: undefined,
      port: 0,
      flowlabel: undefined,
    });
  }
}

class InternalSocketAddress extends JSTransferable {
  constructor(handle) {
    super();
    if (handle !== undefined) {
      this[kHandle] = handle;
      this[kDetail] = this[kHandle].detail({
        family: undefined,
        host: undefined,
        port: 0,
        flowlabel: undefined,
      });
    }
  }
}

InternalSocketAddress.prototype.constructor =
  SocketAddress.prototype.constructor;
ObjectSetPrototypeOf(InternalSocketAddress.prototype, SocketAddress.prototype);

module.exports = {
  SocketAddress,
  InternalSocketAddress,
  isSocketAddress,
  kHandle,
};
