'use strict';

// A preload that listens for SIGTERM must not make the zygote ignore it, and
// programs must still get the preload's listener.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');
const preload = tmpdir.resolve('preload.js');
fs.writeFileSync(preload, `
  process.on('SIGTERM', () => {
    console.log('preload listener');
    process.exit(3);
  });
`);

const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`, '--require', preload],
                     { stdio: 'inherit' });
process.on('exit', () => zygote.kill('SIGKILL'));
const zygoteExited = new Promise((resolve) => zygote.on('exit', (...result) => resolve(result)));

const listening = common.mustCall(async () => {
  const client = spawn(process.execPath, [
    `--connect=${socket}`, '-e', 'console.log("ready"); setInterval(() => {}, 1000);',
  ], { stdio: ['ignore', 'pipe', 'inherit'] });
  let out = '';
  client.stdout.setEncoding('utf8');
  client.stdout.on('data', (chunk) => {
    out += chunk;
    if (out === 'ready\n') client.kill('SIGTERM');
  });
  const [code, signal] = await new Promise((resolve) => {
    client.on('exit', (...result) => resolve(result));
  });
  assert.strictEqual(out, 'ready\npreload listener\n');
  assert.deepStrictEqual([code, signal], [3, null]);

  zygote.kill('SIGTERM');
  const timeout = setTimeout(() => assert.fail('the zygote ignored SIGTERM'),
                             common.platformTimeout(5_000));
  assert.deepStrictEqual(await zygoteExited, [null, 'SIGTERM']);
  clearTimeout(timeout);
});

(function whenListening() {
  net.connect(socket)
    .on('connect', function() {
      this.destroy();
      listening();
    })
    .on('error', () => setTimeout(whenListening, 20));
})();
