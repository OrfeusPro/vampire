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

test('switching characters restores their independent inventory, equipment, balances and progress', () => {
  let s = M.initial();
  for (const [type, payload] of [['buy', { id: 'blade' }], ['equip', { id: 'blade' }], ['quest-step'], ['mail-claim'], ['collection'], ['map-target', { x: 30, y: 40 }], ['map-arrive'], ['quick', { slot: 4, id: 'blade' }]]) s = M.apply(s, type, payload);
  s = M.apply(s, 'create', { name: 'Второй', appearance: M.appearance(), uid: 'two' });
  assert.equal(s.diamonds, 2400); assert.deepEqual(s.equipped, {}); assert.equal(s.quest.progress, 0);
  assert.equal(s.inventory.potion, 30); assert.equal(s.inventory.book, 2); assert.equal(s.position, null); assert.equal(s.quick[4], null);
  s = M.apply(s, 'buy', { id: 'potion', count: 2 });
  s = M.apply(s, 'select', { id: 'demo-1' });
  assert.equal(s.diamonds, 2250); assert.equal(s.inventory.blade, 2); assert.equal(s.inventory.potion, 35); assert.equal(s.inventory.book, 1);
  assert.equal(s.equipped.weapon, 'blade'); assert.equal(s.quest.progress, 1); assert.equal(s.mailClaimed, true); assert.equal(s.collection, true);
  assert.deepEqual(s.position, { x: 30, y: 40 }); assert.equal(s.quick[4], 'blade');
  s = M.apply(s, 'select', { id: 'demo-two' });
  assert.equal(s.gold, M.initial().gold - 80); assert.equal(s.inventory.potion, 32); assert.equal(s.quest.progress, 0);
});
test('canonical saves contain no duplicated active projection and restore both characters', () => {
  let s = M.apply(M.initial(), 'buy', { id: 'blade' });
  s = M.apply(s, 'create', { name: 'Второй', appearance: M.appearance(), uid: 'two' });
  s = M.apply(s, 'buy', { id: 'helm' });
  const saved = M.serialize(s);
  assert.equal(Object.hasOwn(saved, 'gold'), false); assert.equal(Object.hasOwn(saved, 'inventory'), false);
  const loaded = M.load({ getItem: () => JSON.stringify({ dataset: 'same', state: saved }) }, 'same');
  assert.equal(loaded.issue, null); assert.equal(loaded.state.diamonds, 2310);
  const first = M.apply(loaded.state, 'select', { id: 'demo-1' }); assert.equal(first.diamonds, 2250);
  assert.equal(M.adapter(saved).state.diamonds, 2310);
});
test('deletion removes only the chosen character bank and empty profiles reject gameplay', () => {
  let s = M.apply(M.initial(), 'create', { name: 'Второй', appearance: M.appearance(), uid: 'two' });
  s = M.apply(s, 'buy', { id: 'helm' });
  s = M.apply(s, 'delete', { id: 'demo-1' });
  assert.equal(s.selected, 'demo-two'); assert.equal(s.diamonds, 2310); assert.equal(s.characterStates['demo-1'], undefined);
  s = M.apply(s, 'delete', { id: 'demo-two' });
  assert.deepEqual(s.characterStates, {}); assert.throws(() => M.apply(s, 'buy', { id: 'blade' }), /Сначала/);
  s = M.apply(s, 'create', { name: 'Новый', appearance: M.appearance(), uid: 'fresh' });
  assert.equal(s.diamonds, 2400); assert.equal(s.characters[0].primary, true);
});
test('schema 1 is preserved until explicit reset and inconsistent projections are rejected', () => {
  const old = JSON.stringify({ dataset: 'same', state: { ...M.initial(), schema: 1 } });
  let reads = 0;
  const loaded = M.load({ getItem: () => { reads++; return old; } }, 'same');
  assert.ok(loaded.issue); assert.equal(reads, 1); assert.equal(loaded.state.schema, M.SCHEMA);
  const s = M.initial(); s.characterStates['demo-1'].diamonds = 1;
  assert.equal(M.validate(s), false); assert.throws(() => M.serialize(s));
  const orphan = M.serialize(M.initial()); orphan.serverStates['Franz 2'].characterStates.orphan = orphan.serverStates['Franz 2'].characterStates['demo-1'];
  assert.equal(M.validate(orphan), false);
});

test('server banks isolate same character IDs, names, purchases, deletion and persisted progress', () => {
  let s = M.apply(M.initial(), 'buy', { id: 'blade' });
  s = M.apply(s, 'equip', { id: 'blade' });
  s = M.apply(s, 'quest-step');
  s = M.apply(s, 'server', { server: 'Kurzel 1', region: 'Азия' });
  assert.deepEqual(s.characters, []); assert.equal(s.selected, null);
  assert.throws(() => M.apply(s, 'buy', { id: 'blade' }), /Сначала/);
  s = M.apply(s, 'create', { name: 'Nocturne', uid: '1', appearance: M.appearance() });
  assert.equal(s.selected, 'demo-1'); assert.equal(s.diamonds, 2400);
  s = M.apply(s, 'buy', { id: 'helm' });
  s = M.apply(s, 'settings', { scale: 110 });
  const saved = M.serialize(s);
  assert.equal(Object.hasOwn(saved, 'characters'), false);
  const loaded = M.load({ getItem: () => JSON.stringify({ dataset: 'same', state: saved }) }, 'same');
  assert.equal(loaded.issue, null); assert.equal(loaded.state.diamonds, 2310);
  s = M.apply(loaded.state, 'server', { server: 'Franz 2' });
  assert.equal(s.characters[0].name, 'Nocturne'); assert.equal(s.diamonds, 2250);
  assert.equal(s.quest.progress, 1); assert.equal(s.equipped.weapon, 'blade');
  assert.equal(s.settings.scale, 110);
  s = M.apply(s, 'delete', { id: 'demo-1' });
  s = M.apply(s, 'server', { server: 'Kurzel 1' });
  assert.equal(s.characters.length, 1); assert.equal(s.diamonds, 2310);
  s = M.apply(s, 'server', { server: 'Kurzel 1' });
  assert.equal(s.diamonds, 2310);
  assert.throws(() => M.apply(s, 'server', { server: 'Franz 3' }), /недоступен/);
  assert.throws(() => M.apply(s, 'server', { server: 'Franz 2', region: 'unknown' }));
});

test('inactive server corruption and schema 2 are rejected without overwriting storage', () => {
  const corrupt = M.serialize(M.initial());
  corrupt.serverStates['Kurzel 1'].characterStates.orphan = {};
  assert.equal(M.validate(corrupt), false);
  const old = JSON.stringify({ dataset: 'same', state: { ...M.serialize(M.initial()), schema: 2 } });
  const store = { getItem: () => old, setItem: () => { throw Error('must not overwrite'); } };
  assert.ok(M.load(store, 'same').issue);
  assert.equal(store.getItem(), old);
  const unknown = M.serialize(M.initial()); unknown.serverStates.Unknown = unknown.serverStates['Franz 2'];
  assert.equal(M.validate(unknown), false);
});

test('class skills learn, upgrade, slot swap and auto settings update one shared state', () => {
  for (const [classId] of M.CLASSES) {
    let s = M.apply(M.initial(), 'create', { name: 'Ученик', uid: classId, appearance: { ...M.appearance(), classId } });
    const rows = M.skillsForClass(classId), [first, second, locked] = rows;
    assert.deepEqual(Object.keys(s.skills.levels), [first.id, second.id]);
    assert.throws(() => M.apply(s, 'skill-slot', { slot: 3, id: locked.id }), /слот/);
    assert.throws(() => M.apply(s, 'skill-cast', { id: locked.id, now: 1000 }), /изучен/);
    const before = s.gold;
    s = M.apply(s, 'skill-learn', { id: locked.id });
    assert.equal(s.gold, before - locked.learnCost);
    assert.throws(() => M.apply(s, 'skill-learn', { id: locked.id }));
    s = M.apply(s, 'skill-upgrade', { id: locked.id });
    s = M.apply(s, 'skill-upgrade', { id: locked.id });
    assert.equal(s.skills.levels[locked.id], 3); assert.equal(s.gold, before - 800);
    assert.throws(() => M.apply(s, 'skill-upgrade', { id: locked.id }));
    s = M.apply(s, 'skill-slot', { slot: 1, id: first.id });
    assert.deepEqual(s.skills.slots.slice(0, 2), [second.id, first.id]);
    s = M.apply(s, 'skill-slot', { slot: 4, id: locked.id });
    s = M.apply(s, 'skill-auto', { id: locked.id });
    assert.deepEqual(s.skills.auto, [locked.id]);
    s = M.apply(s, 'skill-slot', { slot: 4, id: null }); assert.equal(s.skills.slots[4], null);
    assert.throws(() => M.apply(s, 'skill-slot', { slot: 5, id: first.id }));
    const foreign = Object.values(M.SKILLS).find(skill => skill.classId !== classId);
    assert.throws(() => M.apply(s, 'skill-learn', { id: foreign.id }));
    s = M.apply(s, 'select', { id: 'demo-1' });
    assert.equal(s.gold, M.initial().gold);
  }
});

test('skill MP and cooldown are atomic, persistent, scoped to character and server', () => {
  let s = M.initial(), id = s.skills.slots[0], now = 1000;
  const startMp = s.mp;
  s = M.apply(s, 'skill-cast', { id, now });
  assert.equal(s.mp, startMp - M.SKILLS[id].mp); assert.equal(s.skills.readyAt[id], 4000);
  assert.throws(() => M.apply(s, 'skill-cast', { id, now: 3999 }), /перезарядке/);
  assert.equal(s.mp, startMp - M.SKILLS[id].mp);
  const restored = M.load({ getItem: () => JSON.stringify({ dataset: 'same', state: M.serialize(s) }) }, 'same');
  assert.equal(restored.issue, null);
  assert.throws(() => M.apply(restored.state, 'skill-cast', { id, now: 3999 }));
  s = M.apply(restored.state, 'skill-cast', { id, now: 4000 });
  s = M.apply(s, 'create', { name: 'Второй', uid: 'two', appearance: M.appearance() });
  assert.deepEqual(s.skills.readyAt, {});
  s = M.apply(s, 'select', { id: 'demo-1' }); assert.equal(s.skills.readyAt[id], 7000);
  s = M.apply(s, 'server', { server: 'Kurzel 1' });
  s = M.apply(s, 'create', { name: 'Третий', uid: '1', appearance: M.appearance() });
  assert.deepEqual(s.skills.readyAt, {});
  for (const time of [NaN, -1, Infinity, 1e16]) assert.throws(() => M.apply(s, 'skill-cast', { id, now: time }));
  while (s.mp >= M.SKILLS[id].mp) { s = M.apply(s, 'skill-cast', { id, now }); now += 3000; }
  const balance = s.mp; assert.throws(() => M.apply(s, 'skill-cast', { id, now }), /MP/); assert.equal(s.mp, balance);
});

test('corrupt skill levels, slots, auto and cooldown values are rejected', () => {
  for (const corrupt of [
    v => v.slots.push(null), v => { v.slots[1] = v.slots[0]; },
    v => { v.levels['120011'] = 4; }, v => { v.levels['140011'] = 1; },
    v => { v.auto = ['not-learned']; }, v => { v.readyAt['120011'] = -1; },
    v => { v.readyAt['120011'] = Infinity; }
  ]) {
    const s = M.serialize(M.initial()); corrupt(s.serverStates['Franz 2'].characterStates['demo-1'].skills);
    assert.equal(M.validate(s), false);
  }
});

test('skill training rejects insufficient gold without mutating a valid low-balance save', () => {
  const s = M.serialize(M.initial()), bank = s.serverStates['Franz 2'].characterStates['demo-1'];
  bank.gold = 50;
  const before = JSON.stringify(s);
  assert.throws(() => M.apply(s, 'skill-learn', { id: '120013' }), /золота/);
  assert.throws(() => M.apply(s, 'skill-upgrade', { id: '120011' }), /золота/);
  assert.equal(JSON.stringify(s), before);
});
