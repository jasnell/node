'use strict';

// The zygote wire format is big-endian. A fake zygote written against the
// documented format checks the request that `node --connect` sends, and
// replies with a pid and a wait status the client must decode.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');

const assert = require('assert');
const { spawn } = require('child_process');
const net = require('net');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const socket = common.PIPE;
const kHeaderSize = 6 * 4;
const kModePrint = 2;

const server = net.createServer(common.mustCall((conn) => {
  let received = Buffer.alloc(0);
  conn.on('data', common.mustCallAtLeast((chunk) => {
    received = Buffer.concat([received, chunk]);
    if (received.length < kHeaderSize) return;
    const payloadSize = received.readUInt32BE(20);
    if (received.length < kHeaderSize + payloadSize) return;

    assert.strictEqual(received.toString('latin1', 0, 4), 'NZYG');
    assert.strictEqual(received.readUInt32BE(4), kModePrint);
    const argc = received.readUInt32BE(8);
    const envc = received.readUInt32BE(12);
    assert.strictEqual(received.readUInt32BE(16), 0o027);
    const strings = received.toString('utf8', kHeaderSize, kHeaderSize + payloadSize)
      .split('\0').slice(0, -1);
    assert.strictEqual(strings.length, 1 + argc + envc);
    assert.strictEqual(strings[0], process.cwd());
    assert.deepStrictEqual(strings.slice(1, 1 + argc), ['"code"', 'arg1', 'arg2']);
    assert(strings.slice(1 + argc).includes('ZYGOTE_WIRE_TEST=1'));

    // Reply{'P', pid}, then Reply{'X', wait status of `exit(42)`}.
    const reply = Buffer.alloc(16);
    reply.writeUInt32BE('P'.charCodeAt(0), 0);
    reply.writeInt32BE(12345, 4);
    reply.writeUInt32BE('X'.charCodeAt(0), 8);
    reply.writeInt32BE(42 << 8, 12);
    conn.end(reply);
  }));
}));

server.listen(socket, common.mustCall(() => {
  const child = spawn('/bin/sh', [
    '-c', 'umask 027 && exec "$@"', 'sh',
    process.execPath, `--connect=${socket}`, '-p', '"code"', 'arg1', 'arg2',
  ], { env: { ...process.env, ZYGOTE_WIRE_TEST: '1' }, stdio: ['ignore', 'pipe', 'inherit'] });
  child.on('exit', common.mustCall((code, signal) => {
    assert.strictEqual(signal, null);
    assert.strictEqual(code, 42);
    server.close();
  }));
}));
