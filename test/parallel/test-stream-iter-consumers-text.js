// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  from,
  fromSync,
  text,
  textSync,
} = require('stream/iter');

// =============================================================================
// textSync / text
// =============================================================================

async function testTextSyncBasic() {
  const source = fromSync('hello text');
  const data = textSync(source);
  assert.strictEqual(data, 'hello text');
}

async function testTextAsync() {
  const source = from('hello async text');
  const data = await text(source);
  assert.strictEqual(data, 'hello async text');
}

async function testTextEncoding() {
  // Default encoding is utf-8
  const source = from('café');
  const data = await text(source);
  assert.strictEqual(data, 'café');
}

// =============================================================================
// Text encoding tests
// =============================================================================

async function testTextNonUtf8Encoding() {
  // Latin-1 encoding
  const latin1Bytes = new Uint8Array([0xE9, 0xE8, 0xEA]); // é, è, ê in latin1
  const result = await text(from(latin1Bytes), { encoding: 'iso-8859-1' });
  assert.strictEqual(result, 'éèê');
}

async function testTextSyncNonUtf8Encoding() {
  const latin1Bytes = new Uint8Array([0xE9, 0xE8, 0xEA]);
  const result = textSync(fromSync(latin1Bytes), { encoding: 'iso-8859-1' });
  assert.strictEqual(result, 'éèê');
}

async function testTextInvalidUtf8() {
  // Invalid UTF-8 sequence with fatal: true should throw
  const invalid = new Uint8Array([0xFF, 0xFE]);
  await assert.rejects(
    () => text(from(invalid)),
    { name: 'TypeError' }, // TextDecoder fatal throws TypeError
  );
}

async function testTextWithLimit() {
  // Limit caps total bytes; exceeding throws ERR_OUT_OF_RANGE
  await assert.rejects(
    () => text(from('hello world'), { limit: 5 }),
    { code: 'ERR_OUT_OF_RANGE' },
  );
  // Within limit should succeed
  const result = await text(from('hello'), { limit: 10 });
  assert.strictEqual(result, 'hello');
}

Promise.all([
  testTextSyncBasic(),
  testTextAsync(),
  testTextEncoding(),
  testTextNonUtf8Encoding(),
  testTextSyncNonUtf8Encoding(),
  testTextInvalidUtf8(),
  testTextWithLimit(),
]).then(common.mustCall());
