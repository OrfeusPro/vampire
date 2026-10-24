'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const G = require('./geometry.js');
const slot = (offsets, minimum, maximum, alignment, extra = {}) => ({ layout: { offsets, anchors: { minimum, maximum }, alignment }, ...extra });

test('collection source Canvas chains keep the list and effects column adjacent at both viewport sizes', () => {
  // WBP_ItemCollectionUI: CanvasPanel_41 -> slots 83/92 and 88.
  // Caller allocates the root; this does not resolve the outer SafeZone or native DPI curve.
  const list = { chain: [
    { decoded: slot({ left: -20, top: 0, right: -20, bottom: 2 }, [0, 0], [1, 1], [0, 0]), provenance: { slot_export: 92 } },
    { decoded: slot({ left: 20, top: 220, right: 695, bottom: 120 }, [0, 0], [1, 1], [0, 0]), provenance: { slot_export: 83 } }
  ] };
  const effects = { chain: [{ decoded: slot({ left: -20, top: 200, right: 655, bottom: 122 }, [1, 0], [1, 1], [1, 0]), provenance: { slot_export: 88 } }] };
  const root = G.rect(0, 0, 2400, 1350), l = G.chain(list, root), r = G.chain(effects, root);
  assert.deepEqual(l.rect, { x: 0, y: 220, width: 1725, height: 1008 });
  assert.deepEqual(r.rect, { x: 1725, y: 200, width: 655, height: 1028 });
  for (const width of [1280, 1920]) {
    const left = G.cssRect(l.rect, width / 2400), right = G.cssRect(r.rect, width / 2400);
    assert.equal(left.x + left.width, right.x);
    assert.ok(right.x + right.width < width);
  }
});

test('source purchase footer and button chain preserve bottom-center placement', () => {
  // WBP_ShopPurchasePopup / ButtonPurchase; full source chain is in button-evidence.json.
  const footer = slot({ left: 7, top: -7, right: 7, bottom: 120 }, [0, 1], [1, 1], [.5, 1]);
  const buy = slot({ left: 0, top: -20, right: 400, bottom: 80 }, [.5, 1], [.5, 1], [.5, 1]);
  const binding = { chain: [{ decoded: buy, provenance: { slot_export: 1 } }, { decoded: footer, provenance: { slot_export: 2 } }] };
  const result = G.chain(binding, G.rect(0, 0, 1236, 816));
  assert.deepEqual(result.rect, { x: 418, y: 709, width: 400, height: 80 });
  assert.deepEqual(G.cssRect(result.rect, .5), { x: 209, y: 354.5, width: 200, height: 40 });
});
test('stretched margins and fixed offsets have different meanings', () => {
  const p = G.rect(20, 30, 1000, 600);
  const fixed = G.canvas(slot({ left: -10, top: -20, right: 100, bottom: 80 }, [1, 1], [1, 1], [1, 1]), p);
  assert.deepEqual(fixed.rect, { x: 910, y: 530, width: 100, height: 80 });
  const stretched = G.canvas(slot({ left: 10, top: 20, right: 30, bottom: 40 }, [0, 0], [1, 1], [.5, .5]), p);
  assert.deepEqual(stretched.rect, { x: 30, y: 50, width: 960, height: 540 });
});
test('AutoSize requires known desired size and does not invent a viewport rectangle', () => {
  const s = slot({ left: 0, top: 0, right: 600, bottom: 400 }, [.5, .5], [.5, .5], [.5, .5], { auto_size: 1 });
  const parent = G.rect(0, 0, 1920, 1080);
  assert.ok(G.canvas(s, parent).unknown);
  assert.deepEqual(G.canvas(s, parent, { width: 800, height: 500 }).rect, { x: 560, y: 290, width: 800, height: 500 });
});
test('DPI 100/125/150/200 percent is applied once; UI Scale is separate', () => {
  for (const factor of [1, 1.25, 1.5, 2]) {
    const params = { cssWidth: 1920, cssHeight: 1080, devicePixelRatio: factor, osDpiScale: factor, applicationScale: 1, uiScale: 1, dpiCurveScale: 1 };
    assert.equal(G.units(params).cssPerLogical, 1);
    assert.ok(Math.abs(G.units({ ...params, uiScale: .8 }).cssPerLogical - .8) < 1e-12);
    assert.equal(G.units({ ...params, applicationScale: 1.25 }).physicalPerLogical, factor * 1.25);
  }
  assert.ok(G.units({ cssWidth: 1920, cssHeight: 1080, devicePixelRatio: 1 }).unknown);
});
test('unsupported containers stop resolution; allocated frame assumption is explicit', () => {
  const entry = { decoded: { parent: { type: 'ScaleBox', name: 'ScaleBox_0' } }, provenance: { slot_export: 10 } };
  assert.ok(G.chain({ chain: [entry] }, G.rect(0, 0, 800, 600)).unknown);
  entry.decoded.parent.type = 'WidgetSwitcher';
  assert.ok(G.chain({ chain: [entry], allowAllocatedFrame: true }, G.rect(0, 0, 800, 600)).assumptions.length);
});
test('negative allocation and nonfinite values are rejected', () => {
  assert.throws(() => G.rect(0, 0, -1, 10));
  assert.throws(() => G.cssRect(G.rect(0, 0, 10, 10), NaN));
  const negative = slot({ left: 700, right: 700, top: 0, bottom: 0 }, [0, 0], [1, 1], [0, 0]);
  assert.ok(G.canvas(negative, G.rect(0, 0, 800, 600)).unknown);
  assert.ok(G.canvas({ layout: { offsets: {}, anchors: {} } }, G.rect(0, 0, 800, 600)).unknown);
});
