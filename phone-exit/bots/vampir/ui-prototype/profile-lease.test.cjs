'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { create } = require('./profile-lease.js');

function locks() {
  const held = new Set(); let calls = 0;
  return { held, get calls() { return calls; }, async request(name, options, callback) {
    calls++;
    assert.deepEqual(options, { mode: 'exclusive', ifAvailable: true });
    if (held.has(name)) return callback(null);
    held.add(name);
    try { return await callback({ name }); } finally { held.delete(name); }
  } };
}

test('one writer owns a profile; retry after release loads a new lease', async () => {
  const manager = locks(), a = create(manager, 'bot-1'), b = create(manager, 'bot-1');
  assert.equal((await a.acquire()).status, 'owned');
  assert.equal((await b.acquire()).status, 'occupied');
  assert.equal(a.owned, true); assert.equal(b.owned, false);
  assert.equal((await a.acquire()).status, 'owned'); assert.equal(manager.calls, 2);
  await a.release(); assert.equal(a.owned, false);
  assert.equal((await b.acquire()).status, 'owned');
  assert.equal((await a.acquire()).status, 'occupied');
  await b.release(); assert.equal(manager.held.size, 0);
});

test('50 different profiles can own independent leases without background retries', async () => {
  const manager = locks(), owners = Array.from({ length: 50 }, (_, i) => create(manager, 'bot-' + i));
  const result = await Promise.all(owners.map(lease => lease.acquire()));
  assert.ok(result.every(x => x.status === 'owned')); assert.equal(manager.held.size, 50);
  const duplicate = create(manager, 'bot-23');
  assert.equal((await duplicate.acquire()).status, 'occupied'); assert.equal(manager.calls, 51);
  await Promise.all(owners.map(lease => lease.release())); assert.equal(manager.held.size, 0);
});

test('missing and rejecting APIs do not grant ownership', async () => {
  for (const manager of [null, {}, { request() { throw Error('disabled'); } }, { request() { return Promise.reject(Error('denied')); } }]) {
    const lease = create(manager, 'demo');
    const result = await lease.acquire();
    assert.ok(['unsupported', 'unavailable'].includes(result.status));
    assert.equal(lease.owned, false); await lease.release();
  }
});

test('page hide during acquisition invalidates a late callback and deduplicates requests', async () => {
  let callback, complete;
  const manager = { request(name, options, fn) { callback = fn; return new Promise(resolve => { complete = resolve; }); } };
  const lease = create(manager, 'demo'), first = lease.acquire(), again = lease.acquire();
  assert.equal(first, again);
  const released = lease.release();
  complete(await callback({ name: 'demo' }));
  assert.equal((await first).status, 'cancelled'); await released;
  assert.equal(lease.owned, false);
});
