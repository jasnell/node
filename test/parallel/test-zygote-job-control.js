'use strict';

// Ctrl-Z (SIGTSTP to the client) must stop both the client and the program,
// and SIGCONT to the client (`fg`, `bg`) must continue both, over a Unix
// domain socket and over TCP.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

// Whether `pid` is stopped, or undefined once it is gone.
function stopped(pid) {
  try {
    const state = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1][0];
    return state === 'T';
  } catch {
    return undefined;
  }
}

async function until(predicate, what) {
  const deadline = Date.now() + common.platformTimeout(10_000);
  while (!predicate()) {
    assert(Date.now() < deadline, `timed out waiting until ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

// The kernel discards SIGTSTP in an orphaned process group, so job control
// cannot work there; the client would be in the same group as this probe.
const probe = spawnSync('/bin/sh', ['-c', 'sleep 5 & p=$!; kill -TSTP $p; sleep 0.3; ' +
                                    'cat /proc/$p/stat; kill -KILL $p']);
if (!/\) T /.test(probe.stdout.toString())) {
  common.skip('SIGTSTP is discarded in this process group (orphaned)');
}

function whenListening(connectArgs, callback) {
  net.connect(...connectArgs)
    .on('connect', function() {
      this.destroy();
      callback();
    })
    .on('error', () => setTimeout(whenListening, 20, connectArgs, callback));
}

async function check(address, connectArgs, env) {
  const zygote = spawn(process.execPath, [`--experimental-zygote=${address}`],
                       { env, stdio: ['ignore', 'inherit', 'inherit'] });
  process.on('exit', () => zygote.kill('SIGKILL'));
  await new Promise((resolve) => whenListening(connectArgs, resolve));

  const client = spawn(process.execPath, [
    `--connect=${address}`, '-e', 'console.log(process.pid); setInterval(() => {}, 1000);',
  ], { env, stdio: ['pipe', 'pipe', 'inherit'] });
  const exited = new Promise((resolve) => client.on('exit', (...result) => resolve(result)));
  const [line] = await new Promise((resolve) => {
    let out = '';
    client.stdout.on('data', function onData(chunk) {
      out += chunk;
      if (out.includes('\n')) {
        client.stdout.off('data', onData);
        resolve(out.split('\n'));
      }
    });
  });
  const program = Number(line);
  assert(program > 0 && program !== client.pid);

  client.kill('SIGTSTP');
  await until(() => stopped(client.pid) && stopped(program), `${address}: both stop`);
  client.kill('SIGCONT');
  await until(() => stopped(client.pid) === false && stopped(program) === false,
              `${address}: both continue`);

  client.kill('SIGTERM');
  assert.deepStrictEqual(await exited, [null, 'SIGTERM']);
  zygote.kill('SIGKILL');
}

(async () => {
  tmpdir.refresh();
  const socket = tmpdir.resolve('zygote.sock');
  await check(socket, [socket], process.env);

  if (common.hasCrypto) {
    const port = await new Promise((resolve) => {
      const server = net.createServer().listen(0, '127.0.0.1', () => {
        const { port } = server.address();
        server.close(() => resolve(port));
      });
    });
    const token = 'job-control-test-token-0123456789';
    const env = { ...process.env, NODE_ZYGOTE_TOKEN: token };
    await check(`127.0.0.1:${port}`, [port, '127.0.0.1'], env);
  }
})().then(common.mustCall());
