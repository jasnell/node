'use strict';

// The zygote must reject malformed requests with exit status 125, ignore
// peers that do not speak TLS, and keep serving. A TLS-PSK client written
// against the documented key derivation sends the requests directly.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');
if (!common.hasCrypto) common.skip('missing crypto');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');

const token = crypto.randomBytes(24).toString('base64');
const env = { ...process.env, NODE_ZYGOTE_TOKEN: token };
const psk = crypto.createHash('sha256')
  .update('node zygote tls psk v1').update(Buffer.from([0])).update(token).digest();
const kModeEval = 1;
const kMaxPayloadSize = 1 << 20;
const kInvalidRequest = 125 << 8;  // W_EXITCODE(125, 0)

function header({ magic = 'NZYG', mode = kModeEval, argc = 1, envc = 0, payloadSize }) {
  const buffer = Buffer.alloc(24);
  buffer.write(magic, 0, 'latin1');
  buffer.writeUInt32BE(mode, 4);
  buffer.writeUInt32BE(argc, 8);
  buffer.writeUInt32BE(envc, 12);
  buffer.writeUInt32BE(0o022, 16);
  buffer.writeUInt32BE(payloadSize, 20);
  return buffer;
}

function request(fields, strings) {
  const payload = Buffer.from(strings.map((string) => `${string}\0`).join(''));
  return Buffer.concat([header({ ...fields, payloadSize: payload.length }), payload]);
}

// Sends `data` over TLS-PSK and returns the exit status the zygote reports.
function exitStatus(port, data) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '127.0.0.1', port, minVersion: 'TLSv1.3', ciphers: 'TLS_AES_128_GCM_SHA256',
      pskCallback: () => ({ psk, identity: 'node-zygote-v1' }),
      checkServerIdentity: () => undefined,
    }, () => socket.write(data));
    let received = Buffer.alloc(0);
    socket.on('data', (chunk) => received = Buffer.concat([received, chunk]));
    socket.on('error', reject);
    socket.on('close', () => resolve(received));
  }).then((received) => {
    // Frames: type, size, data. 'P' carries the program's pid, 'X' its wait
    // status, and comes last.
    const types = [];
    let offset = 0;
    let status;
    while (offset < received.length) {
      const type = received.toString('latin1', offset + 3, offset + 4);
      const size = received.readUInt32BE(offset + 4);
      types.push(type);
      if (type === 'X') status = received.readInt32BE(offset + 8);
      offset += 8 + size;
    }
    assert.strictEqual(offset, received.length);
    assert.strictEqual(types.at(-1), 'X', received.toString('hex'));
    // No program was started for a rejected request.
    assert.deepStrictEqual(types, status === kInvalidRequest ? ['X'] : ['P', 'X']);
    return status;
  });
}

(async () => {
  const port = await new Promise((resolve) => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
  const zygote = spawn(process.execPath, [`--experimental-zygote=127.0.0.1:${port}`],
                       { env, stdio: 'inherit' });
  process.on('exit', () => zygote.kill('SIGKILL'));
  await new Promise((resolve) => {
    (function attempt() {
      net.connect(port, '127.0.0.1')
        .on('connect', function() {
          this.destroy();
          resolve();
        })
        .on('error', () => setTimeout(attempt, 20));
    })();
  });

  // The client checks this itself.
  assert.strictEqual(await exitStatus(port, request({ magic: 'JUNK' }, ['/', '1'])), kInvalidRequest);
  assert.strictEqual(await exitStatus(port, request({ mode: 3 }, ['/', '1'])), kInvalidRequest);
  assert.strictEqual(await exitStatus(port, request({ argc: 0 }, ['/'])), kInvalidRequest);
  assert.strictEqual(await exitStatus(port, request({ envc: 5 }, ['/', '1'])), kInvalidRequest);
  assert.strictEqual(await exitStatus(port, header({ payloadSize: kMaxPayloadSize + 1 })), kInvalidRequest);
  // Not NUL-terminated.
  assert.strictEqual(await exitStatus(port, Buffer.concat([header({ payloadSize: 3 }), Buffer.from('/\x001')])),
                     kInvalidRequest);
  // A valid request works, so the ones above failed for their own reasons.
  assert.strictEqual(await exitStatus(port, request({}, ['/', 'process.exitCode = 7'])), 7 << 8);

  // Plain text instead of a TLS handshake.
  await new Promise((resolve) => {
    net.connect(port, '127.0.0.1', function() {
      this.end('GET / HTTP/1.1\r\n\r\n');
    }).on('close', resolve).on('error', () => {}).resume();
  });

  // Too large for the client to send at all. Linux limits each argument to
  // 128 KiB.
  const largeArgs = Array.from({ length: 10 }, () => 'x'.repeat(120_000));
  const tooLarge = spawnSync(process.execPath,
                             [`--connect=127.0.0.1:${port}`, '-e', '1', ...largeArgs],
                             { encoding: 'utf8', env });
  assert.strictEqual(tooLarge.status, 125);
  assert.match(tooLarge.stderr, /request too large/);

  const child = spawnSync(process.execPath, [`--connect=127.0.0.1:${port}`, '-p', '6 * 7'],
                          { encoding: 'utf8', env });
  assert.strictEqual(child.status, 0, child.stderr);
  assert.strictEqual(child.stdout, '42\n');
  zygote.kill('SIGKILL');
})().then(common.mustCall());
