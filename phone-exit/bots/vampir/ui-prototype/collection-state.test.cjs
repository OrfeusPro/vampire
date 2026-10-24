const { test } = require('node:test');
const assert = require('node:assert/strict');
const M = require('./model.js'), C = M.COLLECTIONS;
const source = 'a'.repeat(64);
function fixture(enchant = '0', id = '11001') {
  const req = (rid, itemId, count) => ({ item_id: itemId, row: { Id: rid, GroupId: id, CollectType: '1', CollectParam: itemId, EnchantLevel: enchant, Count: count } });
  return { entry: { id, name: 'Fixture collection ' + id, row: { OperationGroupId: '6011001' }, requirements: [req('1000001', '11011000', '2'), req('1000002', '11011002', '1')], bonuses: [{ row: { Type: '423', GroupId: '6011001', Min: '3', Max: '3' }, name: { Name: 'Basic DMG' }, display: { IsPercentage: '0' } }] },
    items: { '11011000': { id: '11011000', name: 'Fixture sword', icon: { images: [{ sha256: 'b'.repeat(64), url: 'collection-assets/' + 'b'.repeat(64) + '.png', asset_path: '/Game/Fixture/Sword' }] } }, '11011002': { id: '11011002', name: 'Fixture second sword', icon: { images: [] } } } };
}
const payload = (state, bundle, requirementId) => ({ scope: { server: state.server, character: state.selected }, bundle, requirementId });
test('source requirements debit exact quantities once; only full completion contributes bonuses', () => {
  const bundle = C.normalize(fixture(), source), start = M.initial();
  assert.throws(() => M.apply(start, 'collection-enroll', payload(start, bundle, '1000001')), /Недостаточно/);
  let s = M.apply(start, 'collection-supply', payload(start, bundle));
  assert.equal(s.collections.items['11011000@0'].count, 2);
  assert.deepEqual(start.collections, C.initial());
  s = M.apply(s, 'collection-enroll', payload(s, bundle, '1000001'));
  assert.equal(s.collections.items['11011000@0'].count, 0);
  assert.equal(s.collections.entries['11001'].registered.length, 1);
  assert.deepEqual(C.bonuses(s.collections), []);
  const before = M.clone(s);
  assert.throws(() => M.apply(s, 'collection-enroll', payload(s, bundle, '1000001')), /уже/);
  assert.deepEqual(s, before);
  s = M.apply(s, 'collection-enroll', payload(s, bundle, '1000002'));
  assert.equal(C.complete(s.collections.entries['11001']), true);
  assert.equal(C.bonuses(s.collections)[0].min, 3);
  assert.equal(M.stats(s).attack, 120); // No false conversion of Basic DMG into generic attack.
  assert.throws(() => M.apply(s, 'collection-supply', payload(s, bundle)), /уже/);
});
test('enhancement buckets and shared items remain distinct; a depleted collection cannot reuse another enhancement', () => {
  const base = C.normalize(fixture(), source), enhanced = C.normalize(fixture('6', '11002'), source);
  let s = M.apply(M.initial(), 'collection-supply', payload(M.initial(), base));
  assert.throws(() => M.apply(s, 'collection-enroll', payload(s, enhanced, '1000001')), /Недостаточно/);
  s = M.apply(s, 'collection-supply', payload(s, enhanced));
  s = M.apply(s, 'collection-enroll', payload(s, enhanced, '1000001'));
  assert.equal(s.collections.items['11011000@0'].count, 2); assert.equal(s.collections.items['11011000@6'].count, 0);
  assert.equal(s.inventory.blade, 1); // Similar illustrations do not join source and demo IDs.
});
test('favorite and registration lock are persistent, independent flags; locked registration is atomic', () => {
  const bundle = C.normalize(fixture(), source); let s = M.initial();
  s = M.apply(s, 'collection-favorite', payload(s, bundle));
  s = M.apply(s, 'collection-lock', payload(s, bundle));
  s = M.apply(s, 'collection-supply', payload(s, bundle));
  assert.equal(s.collections.entries['11001'].favorite, true);
  assert.throws(() => M.apply(s, 'collection-enroll', payload(s, bundle, '1000001')), /заблокирована/);
  assert.equal(s.collections.items['11011000@0'].count, 2);
  s = M.apply(s, 'collection-lock', payload(s, bundle));
  s = M.apply(s, 'collection-enroll', payload(s, bundle, '1000001'));
  assert.equal(s.collections.entries['11001'].favorite, true);
});
test('collection progress, inventory and bonuses restore per character and server; stale confirmation is rejected', () => {
  const bundle = C.normalize(fixture(), source); let s = M.initial();
  s = M.apply(s, 'collection-supply', payload(s, bundle));
  s = M.apply(s, 'collection-enroll', payload(s, bundle, '1000001'));
  const stale = payload(s, bundle, '1000002');
  s = M.apply(s, 'create', { name: 'Другой', appearance: M.appearance(), uid: 'other' });
  assert.deepEqual(s.collections, C.initial());
  assert.throws(() => M.apply(s, 'collection-enroll', stale), /изменился/);
  s = M.apply(s, 'select', { id: 'demo-1' });
  assert.equal(s.collections.entries['11001'].registered.length, 1);
  const storage = { getItem: () => JSON.stringify({ dataset: 'fixture', state: M.serialize(s) }) };
  s = M.load(storage, 'fixture').state;
  assert.equal(s.collections.items['11011002@0'].count, 1);
  s = M.apply(s, 'server', { server: 'Kurzel 1' });
  s = M.apply(s, 'create', { name: 'Другой', appearance: M.appearance(), uid: 'other' });
  assert.deepEqual(s.collections, C.initial());
  assert.throws(() => M.apply(s, 'collection-enroll', stale), /изменился/);
  s = M.apply(s, 'server', { server: 'Franz 2' });
  assert.equal(s.collections.entries['11001'].registered.length, 1);
});
test('source replacement, changed requirements and forged input stock cannot mutate a valid bank', () => {
  const bundle = C.normalize(fixture(), source); let s = M.initial();
  s = M.apply(s, 'collection-supply', payload(s, bundle));
  assert.throws(() => M.apply(s, 'collection-enroll', payload(s, { ...bundle, source: 'c'.repeat(64) }, '1000001')), /смешивать/);
  const changed = M.clone(bundle); changed.definition.requirements[0].count = 1;
  assert.throws(() => M.apply(s, 'collection-enroll', payload(s, changed, '1000001')), /изменилось/);
  const forged = M.clone(bundle); forged.items['11011000@0'].count = 100;
  assert.throws(() => M.apply(M.initial(), 'collection-enroll', payload(M.initial(), forged, '1000001')), /набор/);
  for (const mutate of [d => d.entry.requirements[0].row.Count = '-1', d => d.entry.requirements[0].row.CollectParam = '999', d => d.entry.bonuses[0].row.Min = '', d => d.items['11011000'].icon.images[0].url = '/external']) {
    const data = fixture(); mutate(data); assert.throws(() => C.normalize(data, source));
  }
});
test('malformed progress and schema 4 saves are rejected without overwriting the old save', () => {
  const bundle = C.normalize(fixture(), source); const s = M.apply(M.initial(), 'collection-supply', payload(M.initial(), bundle));
  for (const mutate of [c => c.entries['11001'].registered = ['missing'], c => c.items['11011000@0'].count = -1, c => c.source = null, c => c.entries['11001'].locked = 'yes']) {
    const next = M.clone(s); mutate(next.collections); next.characterStates[next.selected].collections = M.clone(next.collections); next.serverStates[next.server].characterStates[next.selected].collections = M.clone(next.collections); assert.equal(M.validate(next), false);
  }
  const old = M.serialize(s); old.schema = 4;
  const raw = JSON.stringify({ dataset: 'fixture', state: old });
  const storage = { getItem: () => raw, setItem: () => assert.fail('must preserve old save') };
  assert.match(M.load(storage, 'fixture').issue, /сброс/);
});
