'use strict';

// A program run through a TCP zygote must not find NODE_ZYGOTE_TOKEN anywhere
// in its memory, which it inherits from the zygote and its relay: not in its
// environment, not in the environment block the zygote started with, and not
// on the JavaScript heap.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');
if (!common.hasCrypto) common.skip('missing crypto');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const net = require('net');

const token = crypto.randomBytes(24).toString('base64');
const env = { ...process.env, NODE_ZYGOTE_TOKEN: token };
const mask = 0x5a;
const maskedToken = Buffer.from(token).map((byte) => byte ^ mask).toString('hex');

// Runs in the program. It only ever holds the masked token, and searches
// masked copies of its memory for it, so that the needle it searches for is
// not itself a copy of the token. The one buffer it reads into is unmasked
// again after each search: a masked copy of the needle's own memory would be
// the token.
const scan = `
  const fs = require('fs');
  const mask = ${mask};
  const needle = Buffer.from(process.argv[1], 'hex');
  const mem = fs.openSync('/proc/self/mem', 'r');
  const kChunk = 1 << 24;
  const chunk = Buffer.alloc(kChunk + needle.length);
  const xor = (n) => { for (let i = 0; i < n; i++) chunk[i] ^= mask; };
  let found = 0;
  let scanned = 0;
  for (const line of fs.readFileSync('/proc/self/maps', 'utf8').split('\\n')) {
    const [range, perms] = line.split(' ');
    if (!range || perms[0] !== 'r') continue;
    const [start, end] = range.split('-').map((hex) => BigInt('0x' + hex));
    // Overlap chunks by the needle's length, so that no match straddles two.
    for (let offset = start; offset < end; offset += BigInt(kChunk)) {
      const left = end - offset;
      const size = left < BigInt(chunk.length) ? Number(left) : chunk.length;
      let n;
      try {
        n = fs.readSync(mem, chunk, 0, size, offset);
      } catch {
        break;  // E.g. [vvar].
      }
      xor(n);
      if (chunk.subarray(0, n).indexOf(needle) !== -1) found++;
      xor(n);
      scanned += n;
    }
  }
  console.log(JSON.stringify({ found, scanned,
                               inEnv: process.env.NODE_ZYGOTE_TOKEN !== undefined }));
`;

function freePort(callback) {
  const server = net.createServer().listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    server.close(() => callback(port));
  });
}

function whenListening(port, callback) {
  net.connect(port, '127.0.0.1')
    .on('connect', function() {
      this.destroy();
      callback();
    })
    .on('error', () => setTimeout(whenListening, 20, port, callback));
}

freePort(common.mustCall((port) => {
  const zygote = spawn(process.execPath, [`--experimental-zygote=127.0.0.1:${port}`],
                       { env, stdio: ['ignore', 'inherit', 'pipe'] });
  let zygoteStderr = '';
  zygote.stderr.setEncoding('utf8');
  zygote.stderr.on('data', (chunk) => zygoteStderr += chunk);
  zygote.on('exit', common.mustCall((code, signal) => {
    assert.strictEqual(signal, 'SIGKILL', `zygote exited early:\n${zygoteStderr}`);
  }));
  process.on('exit', () => zygote.kill('SIGKILL'));

  whenListening(port, common.mustCall(() => {
    const child = spawnSync(process.execPath, [
      `--connect=127.0.0.1:${port}`, '-e', scan, maskedToken,
    ], { encoding: 'utf8', env, timeout: common.platformTimeout(60_000) });
    assert.strictEqual(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout);
    assert(result.scanned > 1 << 20, `only scanned ${result.scanned} bytes`);
    assert.strictEqual(result.inEnv, false);
    assert.strictEqual(result.found, 0,
                       `the token is in ${result.found} chunk(s) of the program's memory`);
    zygote.kill('SIGKILL');
  }));
}));
