'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const M = require('./model.js');

test('creation, unique names, locked slot, deletion and primary selection', () => {
  let s = M.apply(M.initial(), 'create', { name: 'Вампир', appearance: M.appearance(), uid: 'second' });
  assert.equal(s.characters.length, 2);
  assert.throws(() => M.apply(s, 'create', { name: 'Третий', appearance: M.appearance() }), /ячеек/);
  s = M.apply(s, 'delete', { id: 'demo-1' });
  assert.equal(s.characters[0].primary, true);
  assert.throws(() => M.apply(s, 'create', { name: 'вампир', appearance: M.appearance() }), /занято/);
  s = M.apply(s, 'delete', { id: 'demo-second' });
  assert.equal(s.selected, null); assert.equal(s.characters.length, 0);
});
test('transactions preserve original state, debit once, reject invalid amounts', () => {
  const start = M.initial();
  const s = M.apply(start, 'buy', { id: 'blessing', count: 2 });
  assert.equal(s.diamonds, 0); assert.equal(s.inventory.blessing, 3);
  assert.equal(start.diamonds, 2400);
  assert.throws(() => M.apply(s, 'buy', { id: 'blessing' }), /Недостаточно/);
  for (const count of [-1, 0, 1.5, 100, NaN]) assert.throws(() => M.apply(start, 'buy', { id: 'blade', count }));
});
test('equipment changes derived stats, removal restores baseline', () => {
  let s = M.apply(M.initial(), 'equip', { id: 'blade' });
  assert.equal(M.stats(s).attack, 162);
  s = M.apply(s, 'unequip', { slot: 'weapon' });
  assert.equal(M.stats(s).attack, 120);
  assert.throws(() => M.apply(s, 'equip', { id: 'book' }));
});
test('reward and mail cannot be claimed twice; collection consumes a book', () => {
  let s = M.initial(); assert.throws(() => M.apply(s, 'quest-claim'));
  for (let i = 0; i < 3; i++) s = M.apply(s, 'quest-step');
  s = M.apply(s, 'quest-claim'); assert.equal(s.gold, M.initial().gold + 500);
  assert.throws(() => M.apply(s, 'quest-claim'));
  s = M.apply(s, 'mail-claim'); assert.equal(s.inventory.potion, 35);
  assert.throws(() => M.apply(s, 'mail-claim'));
  s = M.apply(s, 'collection'); assert.equal(s.inventory.book, 1);
  assert.throws(() => M.apply(s, 'collection'));
});
test('profile storage is isolated for 50 bot windows and incompatible data is preserved', () => {
  const entries = new Map(), storage = { getItem: k => entries.get(k) ?? null };
  for (let i = 1; i <= 50; i++) {
    const s = M.apply(M.initial(), 'buy', { id: 'potion', count: i });
    entries.set(M.profileKey('demo-' + i), JSON.stringify({ dataset: 'snapshot-a', state: s }));
  }
  for (let i = 1; i <= 50; i++) assert.equal(M.load(storage, 'snapshot-a', 'demo-' + i).state.inventory.potion, 30 + i);
  const before = entries.get(M.profileKey('demo-1'));
  assert.ok(M.load(storage, 'snapshot-b', 'demo-1').issue);
  assert.equal(entries.get(M.profileKey('demo-1')), before);
  assert.throws(() => M.profileKey('../account'));
});
test('malformed saves, maps, appearance and settings cannot enter state', () => {
  for (const corrupt of [null, {}, { ...M.initial(), characters: [null] }, { ...M.initial(), quick: 'x' }]) assert.ok(!M.validate(corrupt));
  assert.ok(M.load({ getItem: () => '{' }, 'x').issue);
  assert.throws(() => M.apply(M.initial(), 'map-target', { x: Infinity, y: 0 }));
  assert.throws(() => M.apply(M.initial(), 'settings', { scale: 900 }));
  assert.throws(() => M.apply(M.initial(), 'create', { name: 'Имя', appearance: { ...M.appearance(), body: [-1] } }));
});
test('adapter emits independent immutable snapshots; 50 models remain isolated', () => {
  const bots = Array.from({ length: 50 }, () => M.adapter(M.initial()));
  const start = performance.now();
  for (let round = 0; round < 20; round++) bots.forEach(bot => bot.dispatch('quest-step'));
  const elapsed = performance.now() - start;
  bots[0].dispatch('buy', { id: 'blade' });
  assert.equal(bots[0].state.diamonds, 2250); assert.equal(bots[49].state.diamonds, 2400);
  const snapshot = bots[1].state; snapshot.gold = 0; assert.notEqual(bots[1].state.gold, 0);
  console.log('50 models / 1000 actions: ' + elapsed.toFixed(2) + ' ms; browser windows and live sessions not measured');
});
