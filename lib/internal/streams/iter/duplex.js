'use strict';

// New Streams API - Duplex Channel
//
// Creates a pair of connected channels where data written to one
// channel's writer appears in the other channel's readable.

const {
  SymbolAsyncDispose,
} = primordials;

const {
  push,
} = require('internal/streams/iter/push');
const {
  validateObject,
} = require('internal/validators');

/**
 * Create a pair of connected duplex channels for bidirectional communication.
 * @param {{ highWaterMark?: number, backpressure?: string, signal?: AbortSignal,
 *           a?: object, b?: object }} [options]
 * @returns {[DuplexChannel, DuplexChannel]}
 */
function duplex(options = { __proto__: null }) {
  validateObject(options, 'options');
  const { highWaterMark, backpressure, signal, a, b } = options;
  if (a !== undefined) {
    validateObject(a, 'options.a');
  }
  if (b !== undefined) {
    validateObject(b, 'options.b');
  }

  // Channel A writes to B's readable (A->B direction)
  const { writer: aWriter, readable: bReadable } = push({
    highWaterMark: a?.highWaterMark ?? highWaterMark,
    backpressure: a?.backpressure ?? backpressure,
    signal,
  });

  // Channel B writes to A's readable (B->A direction)
  const { writer: bWriter, readable: aReadable } = push({
    highWaterMark: b?.highWaterMark ?? highWaterMark,
    backpressure: b?.backpressure ?? backpressure,
    signal,
  });

  let aWriterRef = aWriter;
  let bWriterRef = bWriter;

  const channelA = {
    __proto__: null,
    get writer() { return aWriter; },
    readable: aReadable,
    async close() {
      if (aWriterRef === null) return;
      const writer = aWriterRef;
      aWriterRef = null;
      if (writer.endSync() < 0) {
        await writer.end();
      }
    },
    [SymbolAsyncDispose]() {
      return this.close();
    },
  };

  const channelB = {
    __proto__: null,
    get writer() { return bWriter; },
    readable: bReadable,
    async close() {
      if (bWriterRef === null) return;
      const writer = bWriterRef;
      bWriterRef = null;
      if (writer.endSync() < 0) {
        await writer.end();
      }
    },
    [SymbolAsyncDispose]() {
      return this.close();
    },
  };

  return [channelA, channelB];
}

module.exports = {
  duplex,
};
