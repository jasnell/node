'use strict';

// --experimental-zygote rejects arguments it would otherwise ignore, and
// --version, --help and --v8-options take precedence over --connect.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawnSync } = require('child_process');
const fixtures = require('../common/fixtures');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');

function node(...args) {
  return spawnSync(process.execPath, args,
                   { encoding: 'utf8', timeout: common.platformTimeout(30_000) });
}

for (const [args, message] of [
  [['-e', '1'], /cannot be used with --eval or --print/],
  [['-p', '1'], /cannot be used with --eval or --print/],
  [[fixtures.path('empty.js')], /does not run a script; pass it to `node --connect` instead/],
  [['--test'], /cannot be used with --test, --watch, --interactive or --check/],
  [['--watch', fixtures.path('empty.js')], /cannot be used with --test, --watch/],
  [['-i'], /cannot be used with --test, --watch, --interactive or --check/],
]) {
  const result = node(`--experimental-zygote=${socket}`, ...args);
  assert.strictEqual(result.status, 9, `${args}: ${result.stderr}`);
  assert.match(result.stderr, message);
}

// Nothing listens on the socket: these must not try to connect.
const missing = tmpdir.resolve('missing.sock');
{
  const result = node(`--connect=${missing}`, '--version');
  assert.strictEqual(result.status, 0, result.stderr);
  assert.strictEqual(result.stdout, `${process.version}\n`);
}
{
  const result = node(`--connect=${missing}`, '--help');
  assert.strictEqual(result.status, 0, result.stderr);
  assert.match(result.stdout, /^Usage: node /);
}
{
  const result = node(`--connect=${missing}`, '--v8-options');
  assert.strictEqual(result.status, 0, result.stderr);
  assert.match(result.stdout, /Options:/);
}
