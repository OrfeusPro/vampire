const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('./collection-catalog.js');

test('source ordering and filters retain IDs; pages stay bounded and handle empty results', () => {
  const index = { entries: Array.from({ length: 85 }, (_, n) => ({ id: String(n), name: 'Collection ' + n, tab: n % 2 ? '1' : '2', rarity_id: n % 3 ? '0' : '1' })) };
  assert.equal(C.select(index).length, 85);
  assert.deepEqual(C.select(index, { query: '  COLLECTION 84 ', tab: '2', rarity: '1' }).map(x => x.id), ['84']);
  assert.equal(C.select(index, { query: '84', tab: '1' }).length, 0);
  const last = C.page(index.entries, 99);
  assert.equal(last.number, 2); assert.equal(last.rows.length, 5); assert.equal(last.count, 3);
  assert.deepEqual(C.page([], -1), { rows: [], number: 0, count: 1 });
});

function fixture() {
  return { entries: [{ id: '1', file: 'collection-data/entries-0.json' }, { id: '2', file: 'collection-data/entries-1.json' }],
    items: { '11': 'collection-data/items-0.json', '12': 'collection-data/items-0.json' },
    chunks: { 'collection-data/entries-0.json': 'entry hash', 'collection-data/entries-1.json': 'second hash', 'collection-data/items-0.json': 'item hash' } };
}
test('lazy reads coalesce concurrent requests and preserve repeated requirements; close prevents reloading', async () => {
  const calls = [];
  const loader = C.create(async (file, signal, expected) => {
    calls.push({ file, signal, expected });
    if (file === 'collection-index.json') return fixture();
    if (file === 'collection-data/entries-0.json') return { '1': { id: '1', requirements: [{ item_id: '11' }, { item_id: '12' }, { item_id: '11' }] } };
    return { '11': { id: '11', name: 'Sword' }, '12': { id: '12', name: 'Helm' } };
  });
  assert.equal(calls.length, 0);
  const [first, second] = await Promise.all([loader.entry('1'), loader.entry('1')]);
  assert.equal(first.entry.requirements.length, 3); assert.equal(Object.keys(first.items).length, 2);
  assert.deepEqual(first, second); assert.equal(calls.length, 3);
  assert.equal(calls[1].expected, 'entry hash'); assert.equal(calls[2].expected, 'item hash');
  await assert.rejects(loader.entry('999'), /отсутствует/);
  loader.close(); assert.equal(calls[0].signal.aborted, true);
  await assert.rejects(loader.index(), { name: 'AbortError' });
  assert.equal(calls.length, 3);
});
test('failed requests can retry and missing referenced records fail rather than invent content', async () => {
  let fail = true;
  const loader = C.create(async file => {
    if (file === 'collection-index.json') return fixture();
    if (fail) throw Error('checksum mismatch');
    return {};
  });
  await assert.rejects(loader.entry('1'), /checksum/);
  fail = false;
  await assert.rejects(loader.entry('1'), /Нарушена связь/);
  loader.close();
});
test('index failure retries explicitly, with no polling or background reads', async () => {
  let calls = 0;
  const loader = C.create(async () => { if (++calls === 1) throw Error('offline'); return fixture(); });
  await assert.rejects(loader.index(), /offline/);
  assert.equal(calls, 1);
  assert.equal((await loader.index()).entries.length, 2);
  assert.equal(calls, 2); loader.close();
});
test('bounded cache evicts older source chunks instead of retaining every visited collection', async () => {
  const calls = [];
  const meta = { entries: [], items: {}, chunks: {} };
  for (let i = 0; i < 8; i++) { const file = 'collection-data/entries-' + i + '.json'; meta.entries.push({ id: String(i), file }); meta.chunks[file] = 'hash'; }
  const loader = C.create(async file => {
    calls.push(file);
    if (file === 'collection-index.json') return meta;
    const id = file.match(/entries-(\d+)/)[1]; return { [id]: { id, requirements: [] } };
  });
  for (let i = 0; i < 8; i++) await loader.entry(String(i));
  await loader.entry('7'); assert.equal(calls.length, 9);
  await loader.entry('0'); assert.equal(calls.length, 10);
  loader.close();
});
test('actual fetch reader rejects altered chunk bytes before exposing a collection', async () => {
  const original = global.fetch;
  global.fetch = async file => new Response(JSON.stringify(file === 'collection-index.json' ? fixture() : { '1': { id: '1', requirements: [] } }));
  const loader = C.create();
  try { await assert.rejects(loader.entry('1'), /Контрольная сумма/); }
  finally { loader.close(); global.fetch = original; }
});
