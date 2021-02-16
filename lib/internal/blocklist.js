'use strict';

const {
  Boolean,
  ObjectSetPrototypeOf,
  Symbol
} = primordials;

const {
  BlockList: BlockListHandle,
  SocketAddress: SocketAddressHandle,
  AF_INET,
  AF_INET6,
  kLabelMask,
} = internalBinding('block_list');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');
const { inspect } = require('internal/util/inspect');

const kHandle = Symbol('kHandle');
const kDetail = Symbol('kDetail');
const { owner_symbol } = internalBinding('symbols');

const {
  JSTransferable,
  kClone,
  kDeserialize,
} = require('internal/worker/js_transferable');

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_OUT_OF_RANGE,
  }
} = require('internal/errors');

const {
  validateInt32,
  validateObject,
  validatePort,
  validateString,
  validateUint32,
} = require('internal/validators');

function isSocketAddress(value) {
  return value?.[kDetail] !== undefined;
}

function isBlockList(value) {
  return value?.[kHandle] && !isSocketAddress(value);
}

function getSocketAddress(addr, family) {
  family = family.toLowerCase();
  if (family !== 'ipv4' && family !== 'ipv6')
    throw new ERR_INVALID_ARG_VALUE('family', family);
  const type = family === 'ipv4' ? AF_INET : AF_INET6;
  if (addr === '') {
    switch (type) {
      case AF_INET: addr = '0.0.0.0'; break;
      case AF_INET6: addr = '::'; break;
    }
  }
  return new SocketAddressHandle(type, addr, 0, 0);
}

class BlockList extends JSTransferable {
  constructor(parent) {
    if (parent !== undefined && !isBlockList(parent))
      throw new ERR_INVALID_ARG_TYPE('parent', 'BlockList', parent);
    super();
    this[kHandle] = new BlockListHandle(parent?.[kHandle]);
    this[kHandle][owner_symbol] = this;
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `BlockList ${inspect({
      rules: this.rules
    }, opts)}`;
  }

  addAddress(address, family = 'ipv4') {
    if (typeof address === 'string') {
      validateString(family, 'family');
      address = getSocketAddress(address, family);
    } else if (!isSocketAddress(address)) {
      throw new ERR_INVALID_ARG_TYPE(
        'address',
        [
          'string',
          'net.SocketAddress'
        ],
        address);
    } else {
      address = address[kHandle];
    }
    this[kHandle].addAddress(address);
  }

  addRange(start, end, family = 'ipv4') {
    let ip;
    if (typeof start === 'string') {
      ip = start;
      validateString(family, 'family');
      start = getSocketAddress(start, family);
    } else if (!isSocketAddress(start)) {
      throw new ERR_INVALID_ARG_TYPE(
        'start',
        [
          'string',
          'net.SocketAddress'
        ],
        start);
    } else {
      ip = start.address;
      start = start[kHandle];
    }
    if (typeof end === 'string') {
      validateString(family, 'family');
      end = getSocketAddress(end, family);
    } else if (!isSocketAddress(end)) {
      throw new ERR_INVALID_ARG_TYPE(
        'end',
        [
          'string',
          'net.SocketAddress'
        ],
        end);
    } else {
      end = end[kHandle];
    }

    const ret = this[kHandle].addRange(start, end);
    if (ret === false)
      throw new ERR_INVALID_ARG_VALUE('start', ip, 'must come before end');
  }

  addSubnet(network, prefix, family = 'ipv4') {
    if (typeof network === 'string') {
      validateString(family, 'family');
      network = getSocketAddress(network, family);
    } else if (!isSocketAddress(network)) {
      throw new ERR_INVALID_ARG_TYPE(
        'network',
        [
          'string',
          'net.SocketAddress'
        ],
        network);
    } else {
      network = network[kHandle];
    }

    switch (network?.family || family.toLowerCase()) {
      case 'ipv4':
        validateInt32(prefix, 'prefix', 0, 32);
        break;
      case 'ipv6':
        validateInt32(prefix, 'prefix', 0, 128);
        break;
      default:
        throw new ERR_INVALID_ARG_VALUE('family', family);
    }
    this[kHandle].addSubnet(network, prefix);
  }

  check(address, family = 'ipv4') {
    if (typeof address === 'string') {
      validateString(family, 'family');
      try {
        address = getSocketAddress(address, family);
      } catch {
        // We ignore address validation errors and just
        // return false always.
        return false;
      }
    } else if (!isSocketAddress(address)) {
      throw new ERR_INVALID_ARG_TYPE(
        'address',
        [
          'string',
          'net.SocketAddress',
        ],
        address
      );
    } else {
      address = address[kHandle];
    }
    return Boolean(this[kHandle].check(address));
  }

  get rules() {
    return this[kHandle].getRules();
  }

  [kClone]() {
    const handle = this[kHandle];
    return {
      data: { handle },
      deserializeInfo: 'internal/blocklist:InternalBlockList'
    };
  }

  [kDeserialize]({ handle }) {
    this[kHandle] = handle;
    this[kHandle][owner_symbol] = this;
  }
}

class InternalBlockList extends JSTransferable {
  constructor(handle) {
    super();
    this[kHandle] = handle;
  }
}

InternalBlockList.prototype.constructor = BlockList.prototype.constructor;
ObjectSetPrototypeOf(InternalBlockList.prototype, BlockList.prototype);

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
      deserializeInfo: 'internal/blocklist:InternalSocketAddress'
    };
  }

  [kDeserialize]({ handle }) {
    this[kHandle] = handle;
    this[kHandle][owner_symbol] = this;
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
    this[kHandle] = handle;
    this[kDetail] = this[kHandle].detail({
      family: undefined,
      host: undefined,
      port: 0,
      flowlabel: undefined,
    });
  }
}

InternalSocketAddress.prototype.constructor =
  SocketAddress.prototype.constructor;
ObjectSetPrototypeOf(InternalSocketAddress.prototype, SocketAddress.prototype);

module.exports = {
  BlockList,
  SocketAddress,
  InternalBlockList,
  InternalSocketAddress,
  isSocketAddress,
  isBlockList,
  kHandle,
};
