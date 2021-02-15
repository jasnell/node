'use strict';
const common = require('../common');
const assert = require('assert');
const net = require('net');

const {
  BlockList,
  SocketAddress
} = require('net');

{
  // This tests checks that if server._handle.getsockname
  // returns an error number, an error is thrown.

  const server = net.createServer({});
  server.listen(0, common.mustCall(function() {
    server._handle.getsockname = function(out) {
      return -1;
    };
    assert.throws(() => this.address(),
                  /^Error: address [\w|\s-\d]+$/);
    server.close();
  }));
}

[1, '', null, false].forEach((i) => {
  assert.throws(() => new SocketAddress(i), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

[1, {}, [], null, false].forEach((address) => {
  assert.throws(() => new SocketAddress({ address }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

[1, {}, [], null, false].forEach((family) => {
  assert.throws(() => new SocketAddress({ family }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

[{}, [], null, false].forEach((port) => {
  assert.throws(() => new SocketAddress({ port }), {
    code: 'ERR_SOCKET_BAD_PORT'
  });
});

[{}, [], null, false].forEach((flowlabel) => {
  assert.throws(() => new SocketAddress({ family: 'ipv6', flowlabel }), {
    code: 'ERR_INVALID_ARG_TYPE'
  });
});

[-1, 1048576].forEach((flowlabel) => {
  assert.throws(() => new SocketAddress({ family: 'ipv6', flowlabel }), {
    code: 'ERR_OUT_OF_RANGE'
  });
});


{
  const addr = new SocketAddress();
  assert.strictEqual(addr.family, 'ipv4');
  assert.strictEqual(addr.address, '0.0.0.0');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, undefined);
}

{
  const addr = new SocketAddress({ port: 30 });
  assert.strictEqual(addr.family, 'ipv4');
  assert.strictEqual(addr.address, '0.0.0.0');
  assert.strictEqual(addr.port, 30);
  assert.strictEqual(addr.flowlabel, undefined);
}

{
  const addr = new SocketAddress({ address: '123.123.123.123' });
  assert.strictEqual(addr.family, 'ipv4');
  assert.strictEqual(addr.address, '123.123.123.123');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, undefined);
}

{
  const addr = new SocketAddress({ address: '123.123.123.123', port: 30 });
  assert.strictEqual(addr.family, 'ipv4');
  assert.strictEqual(addr.address, '123.123.123.123');
  assert.strictEqual(addr.port, 30);
  assert.strictEqual(addr.flowlabel, undefined);
}

{
  const addr = new SocketAddress({ family: 'ipv6' });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, 0);
}

{
  const addr = new SocketAddress({ family: 'ipv6', address: '::1' });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::1');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, 0);
}

{
  const addr = new SocketAddress({ family: 'ipv6', address: '::1', port: 30 });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::1');
  assert.strictEqual(addr.port, 30);
  assert.strictEqual(addr.flowlabel, 0);
}

{
  const addr = new SocketAddress({ family: 'ipv6', port: 30 });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::');
  assert.strictEqual(addr.port, 30);
  assert.strictEqual(addr.flowlabel, 0);
}

{
  const addr = new SocketAddress({ family: 'ipv6', flowlabel: 0 });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, 0);
}

{
  const addr = new SocketAddress({ family: 'ipv6', flowlabel: 1 });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, 1);
}

{
  const addr = new SocketAddress({ family: 'ipv6', flowlabel: 1048575 });
  assert.strictEqual(addr.family, 'ipv6');
  assert.strictEqual(addr.address, '::');
  assert.strictEqual(addr.port, 0);
  assert.strictEqual(addr.flowlabel, 1048575);
}

{
  const addr = new SocketAddress({ address: '123.123.123.123' });
  const mc = new MessageChannel();
  mc.port1.onmessage = common.mustCall(({ data } ) => {
    assert.strictEqual(data.family, 'ipv4');
    assert.strictEqual(data.address, '123.123.123.123');
    assert.strictEqual(data.port, 0);
    assert.strictEqual(data.flowlabel, undefined);
    mc.port1.close();
  });
  mc.port2.postMessage(addr);
}

const addr1 = new SocketAddress({ address: '123.123.123.123' });
const addr2 = new SocketAddress({ address: '123.123.123.124' });

{
  const list = new BlockList();
  list.addAddress(addr1);
  assert(list.check(addr1));
}

{
  const list = new BlockList();
  list.addRange(addr1, addr2);
  assert.throws(() => list.addRange(addr2, addr1), {
    code: 'ERR_INVALID_ARG_VALUE'
  });
  assert(list.check(addr1));
  assert(list.check(addr2));
}

{
  const list = new BlockList();
  list.addSubnet(addr1, 16);
  assert(list.check(addr2));
}
