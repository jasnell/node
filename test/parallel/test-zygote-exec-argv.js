'use strict';

// A program forked from a zygote must see the zygote's execArgv without the
// zygote-only options (--experimental-zygote, --require, -r) *and their
// values*, so that subprocesses spawned with process.execArgv behave like a
// plain `node` and neither become zygotes nor re-run the preloads.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = common.PIPE;
const preload = tmpdir.resolve('preload.js');
fs.writeFileSync(preload, 'globalThis.preloaded = (globalThis.preloaded ?? 0) + 1;');

// Every spelling of the stripped options, interleaved with options that must
// be kept, including one whose value is a separate argument.
const zygote = spawn(process.execPath, [
  '--experimental-zygote', socket,
  '--require', preload,
  '--title', 'zygote-exec-argv',
  '-r', preload,
  '--stack-trace-limit=20',
  '--require=' + preload,
  '--experimental_zygote=' + socket,
], { stdio: ['ignore', 'inherit', 'pipe'] });
let zygoteStderr = '';
zygote.stderr.setEncoding('utf8');
zygote.stderr.on('data', (chunk) => zygoteStderr += chunk);
zygote.on('exit', common.mustCall((code, signal) => {
  assert.strictEqual(signal, 'SIGKILL', `zygote exited early:\n${zygoteStderr}`);
}));

function connect(code) {
  const child = spawnSync(process.execPath, [`--connect=${socket}`, '-p', code],
                          { encoding: 'utf8' });
  assert.strictEqual(child.status, 0, child.stderr);
  return child.stdout.trim();
}

function whenListening(callback) {
  if (fs.existsSync(socket)) return callback();
  assert.strictEqual(zygote.exitCode, null, zygoteStderr);
  setTimeout(whenListening, 20, callback);
}

whenListening(common.mustCall(() => {
  // The preloads ran in the zygote; the require cache dedupes the file.
  assert.strictEqual(connect('globalThis.preloaded'), '1');

  assert.deepStrictEqual(
    JSON.parse(connect('JSON.stringify(process.execArgv)')),
    ['--title', 'zygote-exec-argv', '--stack-trace-limit=20']);

  // A subprocess spawned with execArgv is a plain node process: it runs the
  // code it is given and does not re-run the preloads.
  const nested = 'require("child_process").execFileSync(process.execPath, ' +
    '[...process.execArgv, "-p", "typeof globalThis.preloaded"], ' +
    '{ encoding: "utf8" }).trim()';
  assert.strictEqual(connect(nested), 'undefined');

  zygote.kill('SIGKILL');
}));
