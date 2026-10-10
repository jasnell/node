'use strict';

// `node --connect=<path>` hands its environment and stdio to the server, so
// it must refuse a socket that another user listens on (e.g. one planted in a
// shared directory such as /tmp) before sending anything.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');
if (process.getuid() !== 0) common.skip('needs root to listen as another user');

const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');
const tmpdir = require('../common/tmpdir');

tmpdir.refresh();
const nobody = 65534;
const shared = tmpdir.resolve('shared');
fs.mkdirSync(shared);
fs.chmodSync(shared, 0o777);
const socket = path.join(shared, 'zygote.sock');

const server = net.createServer(common.mustCall((conn) => {
  let received = 0;
  conn.on('data', (chunk) => received += chunk.length);
  conn.on('end', common.mustCall(() => {
    assert.strictEqual(received, 0);
    conn.end();
    server.close();
  }));
}));

// SO_PEERCRED reports the credentials the listener had when it called
// listen(), which net.Server.prototype.listen() does synchronously.
process.seteuid(nobody);
try {
  server.listen(socket);
} finally {
  process.seteuid(0);
}

server.on('listening', common.mustCall(() => {
  const client = spawnSync(process.execPath, [`--connect=${socket}`, '-p', '1'],
                           { encoding: 'utf8', timeout: common.platformTimeout(30_000) });
  assert.strictEqual(client.signal, null, client.stderr);
  assert.strictEqual(client.status, 125, client.stderr);
  assert.match(client.stderr,
               new RegExp(`refusing to use .*: it is served by uid ${nobody}, not uid 0`));
  assert.strictEqual(client.stdout, '');
}));
