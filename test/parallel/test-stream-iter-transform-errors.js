// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  from,
  pull,
  bytes,
  decompressGzip,
  decompressBrotli,
  decompressZstd,
} = require('stream/iter');

// =============================================================================
// Decompression of corrupt data
// =============================================================================

async function testCorruptGzipData() {
  const corrupt = new Uint8Array([0x1F, 0x8B, 0xFF, 0xFF, 0xFF]);
  await assert.rejects(
    async () => await bytes(pull(from(corrupt), decompressGzip())),
    (err) => err != null,
  );
}

async function testCorruptBrotliData() {
  const corrupt = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]);
  await assert.rejects(
    async () => await bytes(pull(from(corrupt), decompressBrotli())),
    (err) => err != null,
  );
}

async function testCorruptZstdData() {
  // Completely invalid data (not even valid magic bytes)
  const corrupt = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
  await assert.rejects(
    async () => await bytes(pull(from(corrupt), decompressZstd())),
    (err) => err != null,
  );
}

// =============================================================================
// Run all tests
// =============================================================================

(async () => {
  await testCorruptGzipData();
  await testCorruptBrotliData();
  await testCorruptZstdData();
})().then(common.mustCall());
