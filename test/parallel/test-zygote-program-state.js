'use strict';

// A program run through a zygote must see process state as of its own start,
// not as of the zygote's: NODE_PATH and NODE_DEBUG from the client's
// environment, and process.uptime() from when the program was forked.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');
const modules = tmpdir.resolve('node_path');
fs.mkdirSync(modules);
fs.writeFileSync(`${modules}/zygote-state-module.js`, 'module.exports = "found";');

function whenListening(path, callback) {
  net.connect(path)
    .on('connect', function() {
      this.destroy();
      callback();
    })
    .on('error', () => setTimeout(whenListening, 20, path, callback));
}

// The zygote's environment has neither variable.
const zygoteEnv = { ...process.env };
delete zygoteEnv.NODE_PATH;
delete zygoteEnv.NODE_DEBUG;
const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`],
                     { env: zygoteEnv, stdio: 'inherit' });
zygote.on('exit', common.mustCall((code, signal) => {
  assert.strictEqual(signal, 'SIGKILL');
}));
process.on('exit', () => zygote.kill('SIGKILL'));

whenListening(socket, common.mustCall(() => {
  // Let the zygote age, so that its uptime is distinguishable.
  setTimeout(common.mustCall(() => {
    const child = spawnSync(process.execPath, [
      `--connect=${socket}`, '-p',
      `JSON.stringify({
        module: require('zygote-state-module'),
        debug: require('util').debuglog('zygotestate').enabled,
        uptime: process.uptime(),
      })`,
    ], {
      encoding: 'utf8',
      env: { ...zygoteEnv, NODE_PATH: modules, NODE_DEBUG: 'zygotestate' },
    });
    assert.strictEqual(child.status, 0, child.stderr);
    const state = JSON.parse(child.stdout);
    assert.strictEqual(state.module, 'found');
    assert.strictEqual(state.debug, true);
    assert(state.uptime < 1, `uptime ${state.uptime} counts from the zygote's start`);
    zygote.kill('SIGKILL');
  }), 1500);
}));
