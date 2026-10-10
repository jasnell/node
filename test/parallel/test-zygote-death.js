'use strict';

// When the zygote dies, its clients report the lost connection (exit code
// 125), and programs it forked for Unix domain socket clients get SIGHUP
// rather than running on unsupervised.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');
const marker = tmpdir.resolve('hangup');

const zygote = spawn(process.execPath, [`--experimental-zygote=${socket}`], { stdio: 'inherit' });
process.on('exit', () => zygote.kill('SIGKILL'));

const listening = common.mustCall(async () => {
  const client = spawn(process.execPath, [
    `--connect=${socket}`, '-e', `
      process.on('SIGHUP', () => {
        require('fs').writeFileSync(${JSON.stringify(marker)}, 'SIGHUP');
        process.exit(0);
      });
      console.log('ready');
      setInterval(() => {}, 1000);
    `,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  client.stderr.setEncoding('utf8');
  client.stderr.on('data', (chunk) => stderr += chunk);
  await new Promise((resolve) => client.stdout.once('data', resolve));

  zygote.kill('SIGKILL');
  const [code] = await new Promise((resolve) => client.on('exit', (...result) => resolve(result)));
  assert.strictEqual(code, 125);
  assert.match(stderr, /lost connection to the zygote/);

  const deadline = Date.now() + common.platformTimeout(5_000);
  while (!fs.existsSync(marker)) {
    assert(Date.now() < deadline, 'the program did not get SIGHUP');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.strictEqual(fs.readFileSync(marker, 'utf8'), 'SIGHUP');
});

(function whenListening() {
  net.connect(socket)
    .on('connect', function() {
      this.destroy();
      listening();
    })
    .on('error', () => setTimeout(whenListening, 20));
})();
