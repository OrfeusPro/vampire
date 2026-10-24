'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const L = require('./layout-schema.js');
const frame = { x: 0, y: 0, width: 390, height: 100 };
function fixture() {
  const nodes = {
    '1': { name: 'Root', kind: 'CanvasPanel', incoming: [] },
    '2': { name: 'Inset', kind: 'CanvasPanel', incoming: [{ parent: '1', slot: '10' }] },
    '3': { name: 'HP', kind: 'ProgressBar', incoming: [{ parent: '2', slot: '11' }] }
  };
  const make = (parent_export, content_export, offsets, minimum = [0, 0], maximum = [1, 1], alignment = [0, 0]) => ({ decoded: { parent_export, content_export, auto_size: false, layout: { offsets, anchors: { minimum, maximum }, alignment } } });
  return { schema: 1, kind: 'local_widget_schema', nodes, slots: {
    '10': make(1, 2, { left: 15, top: 10, right: 0, bottom: 10 }),
    '11': make(2, 3, { left: 82, top: -12, right: 2, bottom: 14 }, [0, .5], [1, .5], [0, .5])
  } };
}
const solve = (schema, extra = {}) => L.solve(schema, { root: 'Root', frame, targets: { hp: 'HP' }, ...extra });

test('schema interpreter walks current source slots; one parent change moves every consumer without a rewritten chain', () => {
  const schema = fixture();
  assert.deepEqual(solve(schema).rects.hp, { x: 97, y: 31, width: 291, height: 14 });
  schema.slots['10'].decoded.layout.offsets.left = 25;
  assert.deepEqual(solve(schema).rects.hp, { x: 107, y: 31, width: 281, height: 14 });
  assert.deepEqual(solve(fixture()).rects.hp, { x: 97, y: 31, width: 291, height: 14 });
});

test('omitted defaults require an explicit demo policy and remain reported assumptions', () => {
  const schema = fixture(); delete schema.slots['11'].decoded.auto_size;
  assert.equal(solve(schema).unknowns.hp.code, 'unknown_auto_size');
  const result = solve(schema, { policy: { omitted_auto_size_false: true } });
  assert.equal(result.rects.hp.width, 291); assert.equal(result.assumptions.length, 1);
  assert.equal(schema.slots['11'].decoded.auto_size, undefined);
});

test('unknown desired size, unsupported containers, cycles, missing nodes and duplicate parents never get guessed frames', () => {
  let schema = fixture(); schema.slots['11'].decoded.auto_size = true;
  assert.equal(solve(schema).unknowns.hp.code, 'unknown_canvas');
  assert.equal(solve(schema, { desired: { '3': { width: 500, height: 22 } } }).rects.hp.height, 22);
  schema = fixture(); schema.nodes['2'].kind = 'HorizontalBox'; assert.equal(solve(schema).unknowns.hp.code, 'unsupported_container');
  schema = fixture(); schema.nodes['3'].incoming.push({ parent: '1', slot: '20' }); assert.equal(solve(schema).unknowns.hp.code, 'multiple_parents');
  schema = fixture(); schema.nodes['2'].incoming = [{ parent: '3', slot: '10' }]; schema.slots['10'].decoded.parent_export = 3; assert.equal(solve(schema).unknowns.hp.code, 'cycle');
  schema = fixture(); delete schema.nodes['2']; assert.equal(solve(schema).unknowns.hp.code, 'missing_node');
});

test('explicit roots, duplicate names, slot ownership and valid frames are mandatory', () => {
  const schema = fixture();
  assert.throws(() => solve(schema, { root: 'Unknown' }), /Корень/);
  assert.throws(() => solve(schema, { frame: { ...frame, width: NaN } }), /геометрия/);
  schema.nodes['4'] = { name: 'HP', kind: 'Image', incoming: [] };
  assert.equal(solve(schema).unknowns.hp.code, 'ambiguous_or_missing_target');
  assert.ok(solve(schema, { targets: { hp: '3' } }).rects.hp);
  schema.slots['11'].decoded.content_export = 4;
  assert.equal(solve(schema, { targets: { hp: '3' } }).unknowns.hp.code, 'invalid_slot');
});
