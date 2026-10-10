'use strict';

// Peers that connect to a TCP zygote and never complete the handshake must
// not make it spin when it runs out of file descriptors, nor let it hold an
// unbounded number of connections, and real clients must still get through.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');
if (!common.hasCrypto) common.skip('missing crypto');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');

const env = { ...process.env, NODE_ZYGOTE_TOKEN: 'accept-limits-test-token-0123456789' };
const kMaxPendingHandshakes = 64;

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function listening(port) {
  return new Promise((resolve) => {
    (function attempt() {
      net.connect(port, '127.0.0.1')
        .on('connect', function() {
          this.destroy();
          resolve();
        })
        .on('error', () => setTimeout(attempt, 20));
    })();
  });
}

// Connections that send nothing.
async function silentConnections(port, count) {
  const sockets = [];
  for (let i = 0; i < count; i++) {
    sockets.push(await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1', () => resolve(socket));
      // The zygote drops some of them.
      socket.on('error', () => {});
    }));
  }
  return sockets;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function cpuTicks(pid) {
  const fields = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1].split(' ');
  return Number(fields[11]) + Number(fields[12]);
}

function clientWorks(port) {
  const child = spawnSync(process.execPath, [`--connect=127.0.0.1:${port}`, '-p', '6 * 7'],
                          { encoding: 'utf8', env, timeout: common.platformTimeout(20_000) });
  assert.strictEqual(child.status, 0, child.stderr);
  assert.strictEqual(child.stdout, '42\n');
}

async function startZygote(port, shellPrefix = '') {
  const zygote = spawn('/bin/sh', [
    '-c', `${shellPrefix}exec "$@"`, 'sh', process.execPath, `--experimental-zygote=127.0.0.1:${port}`,
  ], { env, stdio: ['ignore', 'inherit', 'inherit'] });
  process.on('exit', () => zygote.kill('SIGKILL'));
  await listening(port);
  return zygote;
}

(async () => {
  // Out of file descriptors: the zygote backs off instead of spinning.
  {
    const port = await freePort();
    const zygote = await startZygote(port, 'ulimit -n 40 && ');
    const sockets = await silentConnections(port, 40);
    await sleep(300);
    const before = cpuTicks(zygote.pid);
    await sleep(1000);
    const used = cpuTicks(zygote.pid) - before;  // In 1/100 s.
    assert(used < 30, `the zygote used ${used * 10} ms of CPU in 1 s while out of fds`);
    for (const socket of sockets) socket.destroy();
    await sleep(300);
    clientWorks(port);
    zygote.kill('SIGKILL');
  }

  // Many silent peers: the zygote keeps only the newest handshakes, and a
  // real client still gets through while they stay connected.
  {
    const port = await freePort();
    const zygote = await startZygote(port);
    const baseline = fs.readdirSync(`/proc/${zygote.pid}/fd`).length;
    const sockets = await silentConnections(port, 150);
    await sleep(300);
    const open = fs.readdirSync(`/proc/${zygote.pid}/fd`).length - baseline;
    assert(open <= kMaxPendingHandshakes, `the zygote holds ${open} connections`);
    clientWorks(port);
    for (const socket of sockets) socket.destroy();
    zygote.kill('SIGKILL');
  }
})().then(common.mustCall());
