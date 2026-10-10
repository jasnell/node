'use strict';

// `--experimental-zygote=host:port` and `--connect=host:port` talk TLS 1.3
// with a pre-shared key derived from NODE_ZYGOTE_TOKEN: the program runs and
// its stdio, signals and exit status are relayed; a client with another token
// is rejected; nothing crosses the wire in plaintext; and the client refuses a
// server that does not know the key, even if it presents a certificate.

const common = require('../common');
if (!common.isLinux) common.skip('--experimental-zygote is Linux only');
if (!common.hasCrypto) common.skip('missing crypto');

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fixtures = require('../common/fixtures');
const fs = require('fs');
const net = require('net');
const tls = require('tls');

const token = crypto.randomBytes(24).toString('base64');
const env = { ...process.env, NODE_ZYGOTE_TOKEN: token };

// Both sides reject tokens that are too short to be random enough, before
// using the network.
{
  const short = { ...process.env, NODE_ZYGOTE_TOKEN: 'x'.repeat(31) };
  const zygote = spawnSync(process.execPath, ['--experimental-zygote=127.0.0.1:1'],
                           { encoding: 'utf8', env: short });
  assert.notStrictEqual(zygote.status, 0);
  assert.match(zygote.stderr, /requires NODE_ZYGOTE_TOKEN with 32 to 256 characters/);
  const client = spawnSync(process.execPath, ['--connect=127.0.0.1:1', '-p', '1'],
                           { encoding: 'utf8', env: short });
  assert.strictEqual(client.status, 9);
  assert.match(client.stderr, /requires NODE_ZYGOTE_TOKEN with 32 to 256 characters/);
}

// A port nothing listens on right now.
function freePort(callback) {
  const server = net.createServer().listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    server.close(() => callback(port));
  });
}

function whenListening(port, callback) {
  net.connect(port, '127.0.0.1')
    .on('connect', function() {
      // Not a TLS client: the zygote drops the connection.
      this.destroy();
      callback();
    })
    .on('error', () => setTimeout(whenListening, 20, port, callback));
}

function client(port, args, options = {}) {
  return spawnSync(process.execPath, [`--connect=127.0.0.1:${port}`, ...args],
                   { encoding: 'utf8', env, timeout: common.platformTimeout(30_000), ...options });
}

// Like client(), for servers that run in this process: spawnSync() would block
// them.
function clientAsync(port, args, options = {}, onSpawn = () => {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [`--connect=127.0.0.1:${port}`, ...args],
                        { env, ...options });
    onSpawn(child);
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => stdout += chunk);
    child.stderr.on('data', (chunk) => stderr += chunk);
    child.on('close', (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
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
  // Do not leave the zygote behind if an assertion fails.
  process.on('exit', () => zygote.kill('SIGKILL'));

  whenListening(port, common.mustCall(async () => {
    // stdin, stdout, stderr and the exit code are relayed.
    {
      const child = client(port, ['-e', `
        process.stdin.setEncoding('utf8');
        let input = '';
        process.stdin.on('data', (chunk) => input += chunk);
        process.stdin.on('end', () => {
          console.log('stdout:' + input.toUpperCase());
          console.error('stderr:' + process.argv[1]);
          process.exitCode = 7;
        });`, 'arg1'], { input: 'hello zygote' });
      assert.strictEqual(child.status, 7, child.stderr);
      assert.strictEqual(child.stdout, 'stdout:HELLO ZYGOTE\n');
      assert.match(child.stderr, /stderr:arg1\n/);
    }

    // The program gets the client's environment without the token.
    {
      const child = client(port, [
        '-p', 'JSON.stringify([process.env.NODE_ZYGOTE_TOKEN, process.env.OTHER])',
      ], { env: { ...env, OTHER: 'kept' } });
      assert.strictEqual(child.status, 0, child.stderr);
      assert.strictEqual(child.stdout, '[null,"kept"]\n');
    }

    // A client with another token fails the handshake, and the zygote keeps
    // serving.
    {
      const child = client(port, ['-p', '1'], {
        env: { ...env, NODE_ZYGOTE_TOKEN: crypto.randomBytes(24).toString('base64') },
      });
      assert.strictEqual(child.status, 125);
      assert.strictEqual(child.stdout, '');
      assert.match(child.stderr, /TLS handshake with .* failed/);
      assert.strictEqual(client(port, ['-p', '"still serving"']).stdout,
                         'still serving\n');
    }

    // More than the 1 MiB that either side buffers, in both directions.
    {
      const input = crypto.randomBytes(3 << 20).toString('base64');
      const child = client(port, ['-e', `
        const chunks = [];
        process.stdin.on('data', (chunk) => chunks.push(chunk));
        process.stdin.on('end', () => {
          const data = Buffer.concat(chunks);
          process.stderr.write(require('crypto').createHash('sha256').update(data).digest('hex'));
          process.stdout.write(data.toString().split('').reverse().join(''));
        });`], { input, maxBuffer: 64 << 20 });
      assert.strictEqual(child.status, 0, child.stderr.slice(-1000));
      assert.match(child.stderr,
                   new RegExp(crypto.createHash('sha256').update(input).digest('hex')));
      assert.strictEqual(child.stdout.length, input.length);
      assert.strictEqual(child.stdout, input.split('').reverse().join(''));
    }

    // A TLS record that arrives in pieces must not make the client spin
    // while it waits for the rest.
    {
      const pauses = [];
      let clientPid;
      // CPU time of the client in ms, from /proc/<pid>/stat (USER_HZ = 100),
      // or undefined once it has exited.
      const cpuMs = () => {
        let stat;
        try {
          stat = fs.readFileSync(`/proc/${clientPid}/stat`, 'utf8');
        } catch {
          return undefined;
        }
        const fields = stat.split(') ')[1].split(' ');
        return (Number(fields[11]) + Number(fields[12])) * 10;
      };
      const proxy = net.createServer(common.mustCall((downstream) => {
        const upstream = net.connect(port, '127.0.0.1');
        downstream.on('error', () => upstream.destroy());
        upstream.on('error', () => downstream.destroy());
        downstream.pipe(upstream);
        // Forward each chunk from the zygote in two halves, with a pause in
        // between.
        let queue = Promise.resolve();
        upstream.on('data', (chunk) => {
          upstream.pause();
          queue = queue.then(async () => {
            const half = Math.ceil(chunk.length / 2);
            downstream.write(chunk.subarray(0, half));
            const start = { cpu: cpuMs(), time: Date.now() };
            await new Promise((resolve) => setTimeout(resolve, 200));
            const end = cpuMs();
            if (start.cpu !== undefined && end !== undefined) {
              pauses.push({ cpu: end - start.cpu, time: Date.now() - start.time });
            }
            downstream.write(chunk.subarray(half));
            upstream.resume();
          });
        });
        upstream.on('end', () => queue.then(() => downstream.end()));
      }));
      await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
      const child = await clientAsync(
        proxy.address().port,
        ['-e', 'console.log("one"); setTimeout(() => console.log("two"), 50)'],
        {}, (c) => clientPid = c.pid);
      proxy.close();
      assert.strictEqual(child.status, 0, child.stderr);
      assert.strictEqual(child.stdout, 'one\ntwo\n');
      assert(pauses.length >= 3, `only ${pauses.length} pauses`);
      const cpu = pauses.reduce((sum, p) => sum + p.cpu, 0);
      const time = pauses.reduce((sum, p) => sum + p.time, 0);
      assert(cpu < time / 4,
             `client used ${cpu} ms of CPU during ${time} ms of waiting`);
    }

    // Signals are forwarded.
    await new Promise((resolve) => {
      const child = spawn(process.execPath, [`--connect=127.0.0.1:${port}`, '-e', `
        process.on('SIGTERM', () => { console.log('got SIGTERM'); process.exit(3); });
        setInterval(() => {}, 1000);
        console.log('ready');`], { env });
      let stdout = '';
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
        if (stdout === 'ready\n') child.kill('SIGTERM');
      });
      child.on('exit', common.mustCall((code) => {
        assert.strictEqual(code, 3);
        assert.strictEqual(stdout, 'ready\ngot SIGTERM\n');
        resolve();
      }));
    });

    // Nothing crosses the wire in plaintext: not the token, not the
    // environment, not the program's output.
    {
      const recorded = [];
      const proxy = net.createServer(common.mustCall((downstream) => {
        const upstream = net.connect(port, '127.0.0.1');
        downstream.on('data', (chunk) => recorded.push(chunk));
        upstream.on('data', (chunk) => recorded.push(chunk));
        // The client exits as soon as it has the exit status, which may reset
        // either side.
        downstream.on('error', () => upstream.destroy());
        upstream.on('error', () => downstream.destroy());
        downstream.pipe(upstream).pipe(downstream);
      }));
      await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
      const marker = crypto.randomBytes(12).toString('hex');
      const child = await clientAsync(proxy.address().port,
                                      ['-p', 'process.env.MARKER + "-output"'],
                                      { env: { ...env, MARKER: marker } });
      proxy.close();
      assert.strictEqual(child.stdout, `${marker}-output\n`, child.stderr);
      const wire = Buffer.concat(recorded);
      // The first byte is a TLS handshake record.
      assert.strictEqual(wire[0], 0x16);
      for (const secret of [token, marker, `${marker}-output`]) {
        assert.strictEqual(wire.indexOf(secret), -1, `${secret} sent in plaintext`);
      }
    }

    // A server that presents a certificate instead of knowing the key gets
    // nothing.
    {
      const impostor = tls.createServer({
        key: fixtures.readKey('agent1-key.pem'),
        cert: fixtures.readKey('agent1-cert.pem'),
      }, common.mustNotCall('the client completed a handshake with the impostor'));
      await new Promise((resolve) => impostor.listen(0, '127.0.0.1', resolve));
      const child = await clientAsync(impostor.address().port, ['-p', '1']);
      impostor.close();
      assert.strictEqual(child.status, 125, child.stderr);
      assert.match(child.stderr, /TLS handshake with .* failed/);
    }

    zygote.kill('SIGKILL');
  }));
}));
