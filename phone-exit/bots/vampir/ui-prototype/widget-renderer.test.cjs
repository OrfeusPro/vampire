'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const R = require('./widget-renderer.js');
const G = require('./geometry.js');
function fixture() {
  const node = (name, kind, incoming = []) => ({ name, kind, incoming, source: { sha256: name } });
  return { schema: 1, kind: 'local_widget_schema', nodes: {
    '1': node('Root', 'CanvasPanel'), '2': node('Body', 'Overlay', [{ parent: '1', slot: '10' }]),
    '3': node('HP', 'ProgressBar', [{ parent: '2', slot: '11' }]),
    '4': node('TextHP', 'NkTextBlock', [{ parent: '2', slot: '12' }]), '5': node('Unused', 'Unknown_C')
  }, slots: {
    '10': { decoded: { parent_export: 1, content_export: 2, auto_size: false, layout: { offsets: { left: 10, top: 20, right: 200, bottom: 30 }, anchors: { minimum: [0, 0], maximum: [0, 0] }, alignment: [0, 0] } } },
    '11': { decoded: { parent_export: 2, content_export: 3, padding: { left: 2, top: 3, right: 4, bottom: 5 }, horizontal_alignment: 0, vertical_alignment: 0 } },
    '12': { decoded: { parent_export: 2, content_export: 4, padding: { left: 0, top: 0, right: 0, bottom: 0 }, horizontal_alignment: 2, vertical_alignment: 2 } }
  } };
}
const bindings = { hp: { control: 'HP', kind: 'ProgressBar' }, text: { control: 'TextHP', kind: 'NkTextBlock' } };
const options = { root: 'Root', frame: { x: 0, y: 0, width: 400, height: 100 }, desired: { '4': { width: 50, height: 12 } } };

test('renderer plan reconstructs shared ancestors once and uses local frames rather than reapplying screen offsets', () => {
  const plan = R.plan(fixture(), options, bindings);
  assert.deepEqual(plan.unknowns, {});
  assert.deepEqual(plan.widgets.map(w => w.id), ['1', '2', '3', '4']);
  assert.deepEqual(plan.widgets.find(w => w.id === '3').rect, { x: 2, y: 3, width: 194, height: 22 });
  assert.deepEqual(plan.widgets.find(w => w.id === '4').rect, { x: 75, y: 9, width: 50, height: 12 });
  assert.equal(plan.widgets.some(w => w.id === '5'), false);
});

test('projection refuses missing controls, wrong source types, duplicate bindings and unsupported intermediate widget classes', () => {
  assert.equal(R.plan(fixture(), options, { bad: { control: 'Missing', kind: 'Image' } }).unknowns.bad.code, 'ambiguous_or_missing_control');
  assert.equal(R.plan(fixture(), options, { bad: { control: 'HP', kind: 'NkButton' } }).unknowns.bad.code, 'binding_kind_mismatch');
  assert.equal(R.plan(fixture(), options, { ...bindings, other: bindings.hp }).unknowns.other.code, 'duplicate_binding');
  const schema = fixture(); schema.nodes['2'].kind = 'UnknownContainer';
  assert.ok(Object.values(R.plan(schema, options, bindings).unknowns).some(e => e.code === 'unsupported_container'));
});

test('alignment preserves padding, clamps desired size, and requires measured size for non-fill axes', () => {
  const slot = { padding: { left: 10, top: 5, right: 20, bottom: 15 }, horizontal_alignment: 3, vertical_alignment: 2 };
  const parent = { x: 7, y: 9, width: 100, height: 60 };
  assert.deepEqual(G.aligned(slot, parent, { width: 30, height: 10 }).rect, { x: 57, y: 29, width: 30, height: 10 });
  assert.deepEqual(G.aligned(slot, parent, { width: 300, height: 100 }).rect, { x: 17, y: 14, width: 70, height: 40 });
  assert.ok(G.aligned(slot, parent).unknown);
  assert.ok(G.aligned({ ...slot, vertical_alignment: undefined }, parent, { width: 30, height: 10 }).unknown);
});

test('omitted Overlay padding stays unknown until the demo policy explicitly permits zero', () => {
  const schema = fixture(); delete schema.slots['11'].decoded.padding;
  assert.equal(R.plan(schema, options, bindings).unknowns['3'].code, 'unknown_alignment');
  const plan = R.plan(schema, { ...options, policy: { omitted_padding_zero: true } }, bindings);
  assert.deepEqual(plan.unknowns, {}); assert.equal(plan.assumptions.length, 2);
  assert.equal(schema.slots['11'].decoded.padding, undefined);
});
