'use strict';

// A zygote warns about what its preloads left open, unref'd, because every
// program inherits it; but not about stdio or signal listeners, which it
// deals with itself.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const preload = tmpdir.resolve('preload.js');
fs.writeFileSync(preload, `
  require('net').createServer().listen(0, '127.0.0.1').unref();
  setInterval(() => {}, 1000).unref();
  process.stdout.write('');
  process.on('SIGTERM', () => {});
`);

async function zygoteWarnings(...preloadArgs) {
  const socket = tmpdir.resolve(`zygote-${preloadArgs.length}.sock`);
  const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`, ...preloadArgs],
                       { stdio: ['ignore', 'ignore', 'pipe'] });
  process.on('exit', () => zygote.kill('SIGKILL'));
  let stderr = '';
  zygote.stderr.setEncoding('utf8');
  zygote.stderr.on('data', (chunk) => stderr += chunk);
  await new Promise((resolve) => {
    (function attempt() {
      net.connect(socket)
        .on('connect', function() {
          this.destroy();
          resolve();
        })
        .on('error', () => setTimeout(attempt, 20));
    })();
  });
  zygote.kill('SIGKILL');
  await new Promise((resolve) => zygote.on('exit', resolve));
  return stderr;
}

(async () => {
  const warned = await zygoteWarnings('--require', preload);
  assert.match(warned,
               /Every program run by this zygote inherits what the preloads left open: TCPServerWrap, Timeout\. /);
  assert.doesNotMatch(warned, /TTYWrap|PipeWrap|SignalWrap/);

  assert.doesNotMatch(await zygoteWarnings(), /inherits/);
})().then(common.mustCall());
