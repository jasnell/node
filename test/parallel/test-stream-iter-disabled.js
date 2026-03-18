'use strict';
const { spawnPromisified } = require('../common');
const assert = require('assert');
const { describe, it } = require('node:test');

describe('stream/iter gating', () => {
  it('fails to require node:stream/iter without flag', async () => {
    const { stderr, code } = await spawnPromisified(process.execPath, [
      '-e', 'require("node:stream/iter")',
    ]);
    assert.match(stderr, /No such built-in module: node:stream\/iter/);
    assert.notStrictEqual(code, 0);
  });

  it('fails to require stream/iter without flag', async () => {
    const { stderr, code } = await spawnPromisified(process.execPath, [
      '-e', 'require("stream/iter")',
    ]);
    assert.match(stderr, /Cannot find module/);
    assert.notStrictEqual(code, 0);
  });

  it('succeeds with --experimental-stream-iter', async () => {
    const { code } = await spawnPromisified(process.execPath, [
      '--experimental-stream-iter',
      '-e', 'require("node:stream/iter")',
    ]);
    assert.strictEqual(code, 0);
  });
});
