// Flags: --expose-internals
'use strict';

const common = require('../common');

if (!common.hasQuic)
  common.skip('quic support is not enabled');

const assert = require('assert');

const {
  isBlob,
} = require('internal/blob');

const {
  isSession,
} = require('internal/quic/session');

const {
  Endpoint,
} = require('net/quic');

const fixtures = require('../common/fixtures');

const kHelloCiphers = [
  {
    name: 'TLS_AES_128_GCM_SHA256',
    standardName: 'TLS_AES_128_GCM_SHA256',
    version: 'TLSv1.3'
  },
  {
    name: 'TLS_AES_256_GCM_SHA384',
    standardName: 'TLS_AES_256_GCM_SHA384',
    version: 'TLSv1.3'
  },
  {
    name: 'TLS_CHACHA20_POLY1305_SHA256',
    standardName: 'TLS_CHACHA20_POLY1305_SHA256',
    version: 'TLSv1.3'
  },
  {
    name: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
    standardName: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
    version: 'unknown'
  },
];

const endpoint = new Endpoint({ address: { port: 12345 } });

async function onClientHello(session) {
  const {
    alpn,
    servername,
    ciphers,
    done,
  } = await session.clienthello;

  assert.strictEqual(alpn, 'zzz');
  assert.strictEqual(servername, 'localhost');
  assert.deepStrictEqual(ciphers, kHelloCiphers);

  assert.throws(() => done(1), {
    code: 'ERR_INVALID_ARG_TYPE',
  });

  done();
  assert.throws(() => done(), {
    code: 'ERR_INVALID_STATE',
  });
}

async function onOCSPRequest(session) {
  const {
    certificate,
    issuer,
    respondWith,
  } = await session.ocsp;

  assert(certificate instanceof ArrayBuffer);
  assert.strictEqual(issuer, undefined);

  assert.throws(() => respondWith(1), {
    code: 'ERR_INVALID_ARG_TYPE',
  });

  respondWith(new Uint8Array(10));

  assert.throws(() => respondWith(), {
    code: 'ERR_INVALID_STATE',
  });
}

async function onHandshakeComplete(session) {
  await session.handshake;
  assert.strictEqual(session.alpn, 'zzz');
  assert.strictEqual(session.servername, 'localhost');
  assert.strictEqual(session.cipher.name, 'TLS_AES_128_GCM_SHA256');
  assert.strictEqual(session.cipher.version, 'TLSv1.3');
  assert.strictEqual(session.validationError.reason,
                     'unspecified certificate verification error');
  assert.strictEqual(session.validationError.code, 'UNSPECIFIED');
  assert.strictEqual(session.earlyData, true);
}

endpoint.onsession = common.mustCall(({ session }) => {
  assert.strictEqual(session.qlog, undefined);

  session.onstream = ({ stream, respondWith }) => {
    respondWith({ body: 'right back at you' });
    const readable = stream.streamReadable();
    readable.on('error', common.mustCall());
    readable.on('close', common.mustCall());
    readable.pipe(process.stdout);
  };

  Promise.all([
    onClientHello(session),
    onOCSPRequest(session),
    onHandshakeComplete(session),
  ]).then(common.mustCall());

});

endpoint.listen({
  alpn: 'zzz',
  secure: {
    key: fixtures.readKey('rsa_private.pem'),
    cert: fixtures.readKey('rsa_cert.crt'),
    keylog: true,
    ocsp: true,
    clientHello: true,
  },
});

const sessionTicket = Buffer.from(
  '308204c50201010202030404021301042063534470df5631cac72d0e0efaed66fc803037' +
  '8c4b8e5da930e4ec6b3db7c8e60420b627411cb31cdab7fd3060d9762412518296a3ad69' +
  'fe0855980e72a369e8d704a106020460be5e8ca20402021c20a382040630820402308202' +
  'eaa00302010202147f86780ca8f99095bad0d13ef4f6ae7181657edf300d06092a864886' +
  'f70d01010b05003081b0310b300906035504061302554b3114301206035504080c0b4163' +
  '6b6e61636b204c74643113301106035504070c0a52687973204a6f6e65733110300e0603' +
  '55040a0c076e6f64652e6a73311d301b060355040b0c145465737420544c532043657274' +
  '6966696361746531143012060355040b0c0b456e67696e656572696e6731123010060355' +
  '04030c096c6f63616c686f7374311b301906092a864886f70d010901160c616c65784061' +
  '75622e6465763020170d3139303632383231333634385a180f3232393330343131323133' +
  '3634385a3081b0310b300906035504061302554b3114301206035504080c0b41636b6e61' +
  '636b204c74643113301106035504070c0a52687973204a6f6e65733110300e060355040a' +
  '0c076e6f64652e6a73311d301b060355040b0c145465737420544c532043657274696669' +
  '6361746531143012060355040b0c0b456e67696e656572696e673112301006035504030c' +
  '096c6f63616c686f7374311b301906092a864886f70d010901160c616c6578406175622e' +
  '64657630820122300d06092a864886f70d01010105000382010f003082010a0282010100' +
  'b7dc58888a27b1c0b7bf3fc0d9c791eca8596650eeff96f27b9de70954dc2a759ddac798' +
  'e9401d29eaec5fa9e3afcdc37793957b5056ff026fa7912359300661b16cc25366783e38' +
  '79d10633ddfd07a2eafbff22064ad38bc986378602cad8af136e182340f85d930f7e42d2' +
  'a5a6f6cbf1f2e038d0281ab54e16745019cafbd2215f7ec9bbf6681984a54c8188873c9a' +
  '898061ef0ad90683dccc812ee9eb7f90dd959e76d152d9184c5f7b82072fe61fa10e9510' +
  '8d05b466038c71373c9fe4641a922dd3f88cfdb4e32374f3fe0b05762ea11dca5981ba29' +
  '3cbeb7d36f7a881cb28a04023c957376eb05ad03790de0becd3fe71b2a509196a72dbe19' +
  'b294b1f50203010001a310300e300c0603551d13040530030101ff300d06092a864886f7' +
  '0d01010b050003820101000f6141c143bd895e1506ba5375411dd18dfd6a326c75b6e736' +
  '427f37565b2607729822df569cc2a81faca918e9abd26a1ad731c333c6ec61aef8e21708' +
  '631f78ccc5924d9c8cb79989ce6e29cca7160aeee1bceb84675bdba5aab3cad079714e3b' +
  'a6917694d5bc83be56ae60a114d72616ed13303d79f99858839770be560d887002939cf2' +
  'bc1fcfd7e6abc559096f8a2b6dc453781fc8e70ed78134025fcaea57b05f5e4ad478783f' +
  'c7129c5b63b42a914569908bd25f75ab1203460977cacde3b769951ca54ed5eee5514a2f' +
  'e5d76bf8e6973b20b710475f5e289e954aa9f182bc22ea8fe01e640dd8897e22423c672e' +
  'be4346dca43b3f9b2846205fc015f2a41504136e6f64652e6a7320717569632073657276' +
  '6572a503020112a90402021c20aa22042051e820416e22f8b2eed0a023d2dfaa1dffa6e8' +
  'a03b7a7bdc8bf1f338233757f5ae07020500a847e338af07020500ffffffffb004040268' +
  '33', 'hex');

const transportParams = Buffer.from(
  '000000000000000000000000000000000000000000000000000000000000000000000000' +
  '000000000000000000000000000000000000000000000000000000000000000000000000' +
  '1400000000000000fa1508eb7cd0aaf78ee90d1029dafaba1f65578d0000000014000000' +
  '00000000ef8f291a2475af85511aefbfca9deb65e98cebc9000000001400000000000000' +
  '5e3289a306fa3c31f361c8d2be6f34f5739f9d6400000000000004000000000000000400' +
  '000000000000040000000000000010000000000064000000000000000300000000000000' +
  '0000000000000000f7ff0000000000000200000000000000030000000000000040787d01' +
  '00000000b004000000000000010001000000000000000000000000000000000000000000',
  'hex');

const client = new Endpoint();
const req = client.connect(endpoint.address, {
  alpn: 'zzz',
  hostname: 'localhost',
  secure: {
    keylog: true,
    ocsp: true,
  },
  qlog: false,
}, {
  sessionTicket,
  transportParams
});

req.keylog.pipe(process.stdout);

assert(isSession(req));

console.log(req.open({ body: 'hello there' }));

async function onOCSPResponse(session) {
  const { response } = await session.ocsp;
  assert.strictEqual(response.byteLength, 10);
}

async function onClientHandshakeComplete(session) {
  await session.handshake;
  assert.strictEqual(session.alpn, 'zzz');
  assert.strictEqual(session.servername, 'localhost');
  assert.strictEqual(session.cipher.name, 'TLS_AES_128_GCM_SHA256');
  assert.strictEqual(session.cipher.version, 'TLSv1.3');
  assert.strictEqual(session.earlyData, false);
  assert.strictEqual(
    session.validationError.reason,
    'self signed certificate');
  assert.strictEqual(
    session.validationError.code,
    'DEPTH_ZERO_SELF_SIGNED_CERT');
  assert(!isBlob(session.sessionTicket));
}

Promise.all([
  onOCSPResponse(req),
  onClientHandshakeComplete(req),
]).then(common.mustCall(), common.mustNotCall());

console.log(req);
