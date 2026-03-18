// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  from,
  fromSync,
  share,
  Share,
  SyncShare,
  text,
  textSync,

} = require('stream/iter');

// =============================================================================
// Share.from
// =============================================================================

async function testShareFrom() {
  const source = from('share-from');
  const shared = Share.from(source);
  const consumer = shared.pull();

  const data = await text(consumer);
  assert.strictEqual(data, 'share-from');
}

async function testShareFromRejectsNonStreamable() {
  assert.throws(
    () => Share.from(12345),
    { name: 'TypeError' },
  );
}

// =============================================================================
// SyncShare.fromSync
// =============================================================================

async function testSyncShareFromSync() {
  const source = fromSync('sync-share-from');
  const shared = SyncShare.fromSync(source);
  const consumer = shared.pull();

  const data = textSync(consumer);
  assert.strictEqual(data, 'sync-share-from');
}

async function testSyncShareFromRejectsNonStreamable() {
  assert.throws(
    () => SyncShare.fromSync(12345),
    { name: 'TypeError' },
  );
}

// =============================================================================
// Protocol validation
// =============================================================================

function testShareProtocolReturnsNull() {
  const obj = {
    [Symbol.for('Stream.shareProtocol')]() { return null; },
  };
  assert.throws(
    () => Share.from(obj),
    { code: 'ERR_INVALID_RETURN_VALUE' },
  );
}

function testShareProtocolReturnsNonObject() {
  const obj = {
    [Symbol.for('Stream.shareProtocol')]() { return 42; },
  };
  assert.throws(
    () => Share.from(obj),
    { code: 'ERR_INVALID_RETURN_VALUE' },
  );
}

function testSyncShareProtocolReturnsNull() {
  const obj = {
    [Symbol.for('Stream.shareSyncProtocol')]() { return null; },
  };
  assert.throws(
    () => SyncShare.fromSync(obj),
    { code: 'ERR_INVALID_RETURN_VALUE' },
  );
}

function testSyncShareProtocolReturnsNonObject() {
  const obj = {
    [Symbol.for('Stream.shareSyncProtocol')]() { return 'bad'; },
  };
  assert.throws(
    () => SyncShare.fromSync(obj),
    { code: 'ERR_INVALID_RETURN_VALUE' },
  );
}

// =============================================================================
// Block backpressure
// =============================================================================

async function testShareBlockBackpressure() {
  let itemIndex = 0;
  async function* source() {
    while (itemIndex < 5) {
      yield [new TextEncoder().encode(`item${itemIndex++}`)];
    }
  }
  const shared = share(source(), { highWaterMark: 2, backpressure: 'block' });
  const consumer = shared.pull();
  const items = [];
  for await (const batch of consumer) {
    for (const chunk of batch) {
      items.push(new TextDecoder().decode(chunk));
    }
  }
  assert.strictEqual(items.length, 5);
}

// =============================================================================
// Drop backpressure modes
// =============================================================================

async function testShareDropOldest() {
  const shared = share(
    (async function* () {
      for (let i = 0; i < 5; i++) {
        yield [new TextEncoder().encode(`${i}`)];
      }
    })(),
    { highWaterMark: 2, backpressure: 'drop-oldest' },
  );
  const consumer = shared.pull();
  const items = [];
  for await (const batch of consumer) {
    for (const chunk of batch) {
      items.push(new TextDecoder().decode(chunk));
    }
  }
  // Some items may have been dropped, but we should get at least the last ones
  assert.ok(items.length > 0);
}

async function testShareDropNewest() {
  const shared = share(
    (async function* () {
      for (let i = 0; i < 5; i++) {
        yield [new TextEncoder().encode(`${i}`)];
      }
    })(),
    { highWaterMark: 2, backpressure: 'drop-newest' },
  );
  const consumer = shared.pull();
  const items = [];
  for await (const batch of consumer) {
    for (const chunk of batch) {
      items.push(new TextDecoder().decode(chunk));
    }
  }
  assert.ok(items.length > 0);
}

Promise.all([
  testShareFrom(),
  testShareFromRejectsNonStreamable(),
  testSyncShareFromSync(),
  testSyncShareFromRejectsNonStreamable(),
  testShareProtocolReturnsNull(),
  testShareProtocolReturnsNonObject(),
  testSyncShareProtocolReturnsNull(),
  testSyncShareProtocolReturnsNonObject(),
  testShareBlockBackpressure(),
  testShareDropOldest(),
  testShareDropNewest(),
]).then(common.mustCall());
