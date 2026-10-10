'use strict';

// --experimental-zygote=<path> may only replace a stale socket at <path>. It
// must not delete regular files, directories or symbolic links, and must not
// take over the socket of a zygote that is still running.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();

function zygoteFails(path, message) {
  const result = spawnSync(process.execPath, [`--experimental-zygote=${path}`],
                           { encoding: 'utf8', timeout: common.platformTimeout(30_000) });
  assert.strictEqual(result.signal, null, result.stderr);
  assert.notStrictEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, message);
}

function connect(path, code) {
  const child = spawnSync(process.execPath, [`--connect=${path}`, '-p', code],
                          { encoding: 'utf8' });
  assert.strictEqual(child.status, 0, child.stderr);
  return child.stdout.trim();
}

// Calls `callback` once something accepts connections on `path`.
function whenListening(path, callback) {
  net.connect(path)
    .on('connect', function() {
      this.destroy();
      callback();
    })
    .on('error', () => setTimeout(whenListening, 20, path, callback));
}

const notASocket = /exists and is not a socket/;

{
  const file = tmpdir.resolve('regular-file');
  fs.writeFileSync(file, 'keep me');
  zygoteFails(file, notASocket);
  assert.strictEqual(fs.readFileSync(file, 'utf8'), 'keep me');
}

{
  const dir = tmpdir.resolve('directory');
  fs.mkdirSync(dir);
  zygoteFails(dir, notASocket);
  assert(fs.statSync(dir).isDirectory());
}

{
  const target = tmpdir.resolve('symlink-target');
  const link = tmpdir.resolve('symlink');
  fs.writeFileSync(target, 'keep me');
  fs.symlinkSync(target, link);
  zygoteFails(link, notASocket);
  assert(fs.lstatSync(link).isSymbolicLink());
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'keep me');
}

// A socket left behind by a server that was killed is replaced. A second
// zygote must not take over the socket while the first one is running.
{
  const socket = common.PIPE;
  const killed = spawnSync(process.execPath, [
    '-e',
    'require("net").createServer().listen(process.argv[1], ' +
      '() => process.kill(process.pid, "SIGKILL"))',
    socket,
  ]);
  assert.strictEqual(killed.signal, 'SIGKILL', killed.stderr.toString());
  assert(fs.lstatSync(socket).isSocket());

  const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`],
                       { stdio: ['ignore', 'inherit', 'pipe'] });
  let zygoteStderr = '';
  zygote.stderr.setEncoding('utf8');
  zygote.stderr.on('data', (chunk) => zygoteStderr += chunk);
  zygote.on('exit', common.mustCall((code, signal) => {
    assert.strictEqual(signal, 'SIGKILL', `zygote exited early:\n${zygoteStderr}`);
  }));

  whenListening(socket, common.mustCall(() => {
    assert.strictEqual(connect(socket, '"served"'), 'served');

    zygoteFails(socket, /another process is listening on /);
    assert.strictEqual(connect(socket, '"still served"'), 'still served');

    zygote.kill('SIGKILL');
  }));
}
