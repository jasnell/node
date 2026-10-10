'use strict';

// --import preloads run once, in the zygote, and programs find them already
// evaluated, even when a relative specifier would resolve to something else
// (here: nothing) from the client's working directory.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');
const zygoteDir = tmpdir.resolve('zygote');
const clientDir = tmpdir.resolve('client');
fs.mkdirSync(zygoteDir);
fs.mkdirSync(clientDir);
fs.writeFileSync(`${zygoteDir}/preload.mjs`, `
  globalThis.preloadRuns = (globalThis.preloadRuns ?? 0) + 1;
  globalThis.preloadPid = process.pid;
`);
fs.writeFileSync(`${clientDir}/main.mjs`, `
  console.log(JSON.stringify([globalThis.preloadRuns, globalThis.preloadPid !== process.pid]));
`);

const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`, '--import', './preload.mjs'],
                     { cwd: zygoteDir, stdio: 'inherit' });
process.on('exit', () => zygote.kill('SIGKILL'));

function connect(...args) {
  const child = spawnSync(process.execPath, [`--connect=${socket}`, ...args],
                          { cwd: clientDir, encoding: 'utf8' });
  assert.strictEqual(child.status, 0, child.stderr);
  return child.stdout;
}

const listening = common.mustCall(() => {
  const expected = '[1,true]\n';
  assert.strictEqual(connect('main.mjs'), expected);
  assert.strictEqual(
    connect('-p', 'JSON.stringify([globalThis.preloadRuns, globalThis.preloadPid !== process.pid])'),
    expected);
  zygote.kill('SIGKILL');
});

(function whenListening() {
  net.connect(socket)
    .on('connect', function() {
      this.destroy();
      listening();
    })
    .on('error', () => setTimeout(whenListening, 20));
})();
