'use strict';

const {
  Symbol
} = primordials;

const {
  Http3OptionsObject
} = internalBinding('quic');

if (Http3OptionsObject === undefined)
  return;

const {
  validateBigIntOrSafeInteger,
  validateObject,
} = require('internal/validators');

const {
  kType,
} = require('internal/quic/common');

const {
  inspect,
} = require('util');

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  codes: {
    ERR_INVALID_THIS,
  },
} = require('internal/errors');

const kHandle = Symbol('kHandle');
const kOptions = Symbol('kOptions');

/**
 * @typedef {{
 *   maxHeaderLength? : bigint | number,
 *   maxHeaderPairs? : bigint | number,
 *   maxFieldSectionSize? : bigint | number,
 *   maxPushes? : bigint | number,
 *   qpackBlockedStreams? : bigint | number,
 *   qpackMaxTableCapacity? : bigint | number,
 * }} Http3OptionsInit
 */

class Http3Options {
  [kType] = 'Http3Options';

  /**
   * @param {*} value
   * @returns {boolean}
   */
  static isHttp3Options(value) {
    return typeof value?.[kHandle] === 'object';
  }

  /**
   * @param {Http3OptionsInit} [options]
   */
  constructor(options = {}) {
    validateObject(options, 'options');
    const {
      maxHeaderLength,
      maxHeaderPairs,
      maxFieldSectionSize,
      maxPushes,
      qpackBlockedStreams,
      qpackMaxTableCapacity,
    } = options;

    if (maxHeaderLength !== undefined) {
      validateBigIntOrSafeInteger(
        maxHeaderLength,
        'options.maxHeaderLength');
    }

    if (maxHeaderPairs !== undefined) {
      validateBigIntOrSafeInteger(
        maxHeaderPairs,
        'options.maxHeaderPairs');
    }

    if (maxFieldSectionSize !== undefined) {
      validateBigIntOrSafeInteger(
        maxFieldSectionSize,
        'options.maxFieldSectionSize');
    }

    if (maxPushes !== undefined)
      validateBigIntOrSafeInteger(maxPushes, 'options.maxPushes');

    if (qpackBlockedStreams !== undefined) {
      validateBigIntOrSafeInteger(
        qpackBlockedStreams,
        'options.qpackBlockedStreams');
    }

    if (qpackMaxTableCapacity !== undefined) {
      validateBigIntOrSafeInteger(
        qpackMaxTableCapacity,
        'options.qpackMaxTableCapacity');
    }

    this[kOptions] = {
      maxHeaderLength,
      maxHeaderPairs,
      maxFieldSectionSize,
      maxPushes,
      qpackBlockedStreams,
      qpackMaxTableCapacity,
    };

    this[kHandle] = new Http3OptionsObject(this[kOptions]);
  }

  [kInspect](depth, options) {
    if (!Http3Options.isHttp3Options(this))
      throw new ERR_INVALID_THIS('Http3Options');
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1
    };

    return `${this[kType]} ${inspect(this[kOptions], opts)}`;
  }
}

module.exports = {
  Http3Options,
  kHandle,
};
