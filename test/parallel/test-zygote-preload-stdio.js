'use strict';

// A preload that keeps the zygote's process.stdout, when that is a TTY, must
// not let programs write to the zygote's terminal: the stream must reach the
// client, and programs must not hold the zygote's terminal open at all.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const tmpdir = require('../common/tmpdir');

if (spawnSync('script', ['--version']).status !== 0) common.skip('needs script(1)');

tmpdir.refresh();
const socket = tmpdir.resolve('zygote.sock');
const preload = tmpdir.resolve('preload.js');
const pidFile = tmpdir.resolve('zygote.pid');
fs.writeFileSync(preload, `
  globalThis.zygoteStdout = process.stdout;
  require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
`);

// script(1) runs the zygote on a pseudo-terminal of its own.
const terminal = spawn('script', [
  '-qec', `'${process.execPath}' --experimental-zygote='${socket}' --require '${preload}'`, '/dev/null',
], { stdio: ['pipe', 'pipe', 'inherit'] });
let terminalOutput = '';
terminal.stdout.setEncoding('utf8');
terminal.stdout.on('data', (chunk) => terminalOutput += chunk);
function stopZygote() {
  try {
    process.kill(Number(fs.readFileSync(pidFile, 'utf8')), 'SIGKILL');
  } catch {
    // Not started, or gone.
  }
  terminal.kill('SIGKILL');
}
process.on('exit', stopZygote);

const listening = common.mustCall(() => {
  const child = spawnSync(process.execPath, [`--connect=${socket}`, '-e', `
    assert(zygoteStdout.isTTY);
    zygoteStdout.write('through the preload\\'s stream\\n');
    const fs = require('fs');
    const terminals = fs.readdirSync('/proc/self/fd').filter((fd) => {
      try {
        return fs.readlinkSync('/proc/self/fd/' + fd).startsWith('/dev/pts/');
      } catch {
        return false;
      }
    });
    console.log('terminals: ' + terminals.length);
  `], { encoding: 'utf8' });
  assert.strictEqual(child.status, 0, child.stderr);
  assert.strictEqual(child.stdout, 'through the preload\'s stream\nterminals: 0\n');
  assert.doesNotMatch(terminalOutput, /through the preload/);
  stopZygote();
});

(function whenListening() {
  net.connect(socket)
    .on('connect', function() {
      this.destroy();
      listening();
    })
    .on('error', () => setTimeout(whenListening, 20));
})();
