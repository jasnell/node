'use strict';

// If the zygote cannot get a pidfd for a child it forked (out of file
// descriptors), only that request may fail; the zygote must keep serving.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

if (spawnSync('prlimit', ['--version']).status !== 0) common.skip('needs prlimit');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');

function connect() {
  return spawnSync(process.execPath, [`--connect=${socket}`, '-p', '6 * 7'],
                   { encoding: 'utf8', timeout: common.platformTimeout(20_000) });
}

function setSoftFdLimit(pid, limit) {
  const result = spawnSync('prlimit', [`--pid=${pid}`, `--nofile=${limit}:`], { encoding: 'utf8' });
  assert.strictEqual(result.status, 0, result.stderr);
}

const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`], { stdio: 'inherit' });
process.on('exit', () => zygote.kill('SIGKILL'));

const listening = common.mustCall(() => {
  // Let the zygote reap the child it forked for the probe connection.
  setTimeout(common.mustCall(check), 300);
});
(function whenListening() {
  net.connect(socket)
    .on('connect', function() {
      this.destroy();
      listening();
    })
    .on('error', () => setTimeout(whenListening, 20));
})();

function check() {
  assert.strictEqual(connect().stdout, '42\n');

  // Leave the zygote exactly one free descriptor: accept() gets it, and
  // pidfd_open() for the forked child fails.
  const used = new Set(fs.readdirSync(`/proc/${zygote.pid}/fd`).map(Number));
  let lowestFree = 0;
  while (used.has(lowestFree)) lowestFree++;
  setSoftFdLimit(zygote.pid, lowestFree + 1);
  const failed = connect();
  assert.strictEqual(failed.status, 127, failed.stderr);
  assert.strictEqual(failed.stdout, '');

  setSoftFdLimit(zygote.pid, 1024);
  const child = connect();
  assert.strictEqual(child.status, 0, child.stderr);
  assert.strictEqual(child.stdout, '42\n');
  assert.strictEqual(zygote.exitCode, null);
  zygote.kill('SIGKILL');
}
