// Flags: --experimental-stream-iter
'use strict';

const common = require('../common');
const assert = require('assert');
const {
  from,
  fromSync,
  push,
  merge,
  text,
} = require('stream/iter');

// =============================================================================
// merge
// =============================================================================

async function testMergeTwoSources() {
  const { writer: w1, readable: r1 } = push();
  const { writer: w2, readable: r2 } = push();

  w1.write('from-a');
  w1.end();
  w2.write('from-b');
  w2.end();

  const merged = merge(r1, r2);
  const chunks = [];
  for await (const batch of merged) {
    for (const chunk of batch) {
      chunks.push(new TextDecoder().decode(chunk));
    }
  }

  // Both sources should be present (order is temporal, not guaranteed)
  assert.strictEqual(chunks.length, 2);
  assert.ok(chunks.includes('from-a'));
  assert.ok(chunks.includes('from-b'));
}

async function testMergeSingleSource() {
  const source = from('only-one');
  const merged = merge(source);

  const data = await text(merged);
  assert.strictEqual(data, 'only-one');
}

async function testMergeEmpty() {
  const merged = merge();
  const batches = [];
  for await (const batch of merged) {
    batches.push(batch);
  }
  assert.strictEqual(batches.length, 0);
}

async function testMergeWithAbortSignal() {
  const ac = new AbortController();
  ac.abort();

  const source = from('data');
  const merged = merge(source, { signal: ac.signal });

  await assert.rejects(
    async () => {
      // eslint-disable-next-line no-unused-vars
      for await (const _ of merged) {
        assert.fail('Should not reach here');
      }
    },
    (err) => err.name === 'AbortError',
  );
}

// Regression test: merge() with sync iterable sources
async function testMergeSyncSources() {
  const s1 = fromSync('abc');
  const s2 = fromSync('def');
  const result = await text(merge(s1, s2));
  // Both sources should be fully consumed; order may vary
  assert.strictEqual(result.length, 6);
  for (const ch of 'abcdef') {
    assert.ok(result.includes(ch), `missing '${ch}' in '${result}'`);
  }
}

// =============================================================================
// Merge error propagation
// =============================================================================

async function testMergeSourceError() {
  async function* goodSource() {
    yield [new TextEncoder().encode('a')];
    // Slow so the bad source errors first
    await new Promise((r) => setTimeout(r, 50));
    yield [new TextEncoder().encode('b')];
  }

  async function* badSource() {
    yield [new TextEncoder().encode('x')];
    throw new Error('merge source boom');
  }
  await assert.rejects(async () => {
    // eslint-disable-next-line no-unused-vars
    for await (const _ of merge(goodSource(), badSource())) { /* consume */ }
  }, { message: 'merge source boom' });
}

async function testMergeConsumerBreak() {
  let source1Return = false;
  let source2Return = false;
  async function* source1() {
    try {
      while (true) yield [new TextEncoder().encode('a')];
    } finally {
      source1Return = true;
    }
  }

  async function* source2() {
    try {
      while (true) yield [new TextEncoder().encode('b')];
    } finally {
      source2Return = true;
    }
  }
  // eslint-disable-next-line no-unused-vars
  for await (const _ of merge(source1(), source2())) {
    break; // Break after first batch
  }
  await new Promise((r) => setTimeout(r, 10));
  // At least one source should be cleaned up
  assert.strictEqual(source1Return || source2Return, true);
}

async function testMergeSignalMidIteration() {
  const ac = new AbortController();
  async function* slowSource() {
    yield [new TextEncoder().encode('a')];
    await new Promise((r) => setTimeout(r, 100));
    yield [new TextEncoder().encode('b')];
  }
  const merged = merge(slowSource(), { signal: ac.signal });
  const iter = merged[Symbol.asyncIterator]();
  await iter.next(); // First batch
  ac.abort();
  await assert.rejects(() => iter.next(), { name: 'AbortError' });
}

Promise.all([
  testMergeTwoSources(),
  testMergeSingleSource(),
  testMergeEmpty(),
  testMergeWithAbortSignal(),
  testMergeSyncSources(),
  testMergeSourceError(),
  testMergeConsumerBreak(),
  testMergeSignalMidIteration(),
]).then(common.mustCall());
