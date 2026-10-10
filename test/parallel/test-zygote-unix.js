'use strict';

// Programs run through a zygote over a Unix domain socket: script, -e and -p
// modes; argv, cwd, env, umask and stdin; exit codes and death by signal;
// signal forwarding; SIGHUP once the client is gone; a fresh Math.random()
// and crypto state per program; and a zygote that refuses to serve while a
// thread it cannot fork is alive.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');
const workdir = tmpdir.resolve('workdir');
fs.mkdirSync(workdir);
fs.writeFileSync(`${workdir}/main.js`, `
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => input += chunk);
  process.stdin.on('end', () => {
    console.log(JSON.stringify({
      argv: process.argv.slice(1),
      cwd: process.cwd(),
      env: process.env.ZYGOTE_UNIX_TEST,
      umask: process.umask(),
      input,
    }));
  });
`);

function connect(args, options = {}) {
  return spawnSync('/bin/sh', [
    '-c', 'umask 027 && exec "$@"', 'sh', process.execPath, `--connect=${socket}`, ...args,
  ], { cwd: workdir, encoding: 'utf8', env: { ...process.env, ZYGOTE_UNIX_TEST: 'passed' },
       ...options });
}

function connectAsync(code) {
  const child = spawn(process.execPath, [`--connect=${socket}`, '-e', code],
                      { stdio: ['ignore', 'pipe', 'inherit'] });
  child.stdout.setEncoding('utf8');
  child.output = '';
  child.ready = new Promise((resolve) => {
    child.stdout.on('data', (chunk) => {
      child.output += chunk;
      if (child.output.startsWith('ready\n')) resolve();
    });
  });
  child.exited = new Promise((resolve) => child.on('exit', (...result) => resolve(result)));
  return child;
}

function listening(path) {
  return new Promise((resolve) => {
    (function attempt() {
      net.connect(path)
        .on('connect', function() {
          this.destroy();
          resolve();
        })
        .on('error', () => setTimeout(attempt, 20));
    })();
  });
}

async function waitForFile(file) {
  const deadline = Date.now() + common.platformTimeout(10_000);
  while (!fs.existsSync(file)) {
    assert(Date.now() < deadline, `${file} did not appear`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

(async () => {
  const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`], { stdio: 'inherit' });
  process.on('exit', () => zygote.kill('SIGKILL'));
  await listening(socket);

  // Script mode, with argv, cwd, env, umask and stdin.
  {
    const child = connect(['main.js', 'a', 'b c'], { input: 'from stdin' });
    assert.strictEqual(child.status, 0, child.stderr);
    assert.deepStrictEqual(JSON.parse(child.stdout), {
      argv: [`${workdir}/main.js`, 'a', 'b c'],
      cwd: workdir,
      env: 'passed',
      umask: 0o027,
      input: 'from stdin',
    });
  }

  // -e and -p, with arguments.
  {
    const child = connect(['-e', 'console.log(JSON.stringify(process.argv.slice(1)))', 'x', 'y']);
    assert.strictEqual(child.status, 0, child.stderr);
    assert.deepStrictEqual(JSON.parse(child.stdout), ['x', 'y']);
    assert.strictEqual(connect(['-p', '6 * 7']).stdout, '42\n');
  }

  // Exit codes, death by signal, and an uncaught exception, whose stack trace
  // does not show the zygote's frames.
  {
    assert.strictEqual(connect(['-e', 'process.exit(3)']).status, 3);
    const killed = connect(['-e', 'process.kill(process.pid, "SIGTERM")']);
    assert.strictEqual(killed.signal, 'SIGTERM');
    const thrown = connect(['-e', 'throw new Error("boom")']);
    assert.strictEqual(thrown.status, 1);
    assert.match(thrown.stderr, /Error: boom/);
    assert.doesNotMatch(thrown.stderr, /serve|beforeExit/);
  }

  // Signals sent to the client reach the program.
  {
    const child = connectAsync(`
      process.on('SIGINT', () => {
        console.log('SIGINT');
        process.exit(4);
      });
      console.log('ready');
      setInterval(() => {}, 1000);
    `);
    await child.ready;
    child.kill('SIGINT');
    assert.deepStrictEqual(await child.exited, [4, null]);
    assert.strictEqual(child.output, 'ready\nSIGINT\n');
  }

  // The program gets SIGHUP once its client is gone.
  {
    const marker = tmpdir.resolve('hangup');
    const child = connectAsync(`
      process.on('SIGHUP', () => {
        require('fs').writeFileSync(${JSON.stringify(marker)}, '');
        process.exit(0);
      });
      console.log('ready');
      setInterval(() => {}, 1000);
    `);
    await child.ready;
    child.kill('SIGKILL');
    await child.exited;
    await waitForFile(marker);
  }

  // Siblings differ in pid, Math.random() and crypto's cached randomness.
  {
    const code = 'JSON.stringify([process.pid, Math.random(), crypto.randomUUID(), crypto.randomInt(2 ** 40)])';
    const children = [connect(['-p', code]), connect(['-p', code])];
    for (const child of children) assert.strictEqual(child.status, 0, child.stderr);
    const [a, b] = children.map((child) => JSON.parse(child.stdout));
    for (let i = 0; i < a.length; i++) assert.notStrictEqual(a[i], b[i], `index ${i}`);
  }

  zygote.kill('SIGKILL');

  // A thread that fork() would not copy makes the zygote refuse to serve.
  {
    const preload = tmpdir.resolve('worker-preload.js');
    fs.writeFileSync(preload, `
      const { Worker } = require('worker_threads');
      new Worker('setInterval(() => {}, 1000)', { eval: true }).unref();
    `);
    const result = spawnSync(process.execPath, [
      `--experimental-zygote=${tmpdir.resolve('unsafe.sock')}`, '--require', preload,
    ], { encoding: 'utf8', timeout: common.platformTimeout(30_000) });
    assert.notStrictEqual(result.status, 0);
    assert.match(result.stderr, /cannot fork while these threads are alive/);
  }
})().then(common.mustCall());
