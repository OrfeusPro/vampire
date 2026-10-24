/* Local schema interpreter. No DOM, polling, native events or inferred runtime roots. */
(function(root) {
  'use strict';
  const G = typeof module !== 'undefined' && module.exports ? require('./geometry.js') : root.VampirGeometry;
  function solve(schema, { root: selectedRoot, frame, targets, desired = {}, policy = {} }) {
    if (schema?.schema !== 1 || schema.kind !== 'local_widget_schema') throw Error('Неизвестная версия схемы интерфейса.');
    G.rect(frame.x, frame.y, frame.width, frame.height);
    const nodes = schema.nodes, cache = new Map(), assumptions = new Set(), visiting = new Set();
    function fail(code, node, slot, message) { return { unknown: { code, node, slot, message } }; }
    function find(value) {
      if (Object.hasOwn(nodes, value)) return String(value);
      const matches = Object.entries(nodes).filter(([, node]) => node.name === value);
      return matches.length === 1 ? matches[0][0] : null;
    }
    const rootId = find(selectedRoot);
    if (!rootId) throw Error('Корень схемы не найден или неоднозначен.');
    cache.set(rootId, { rect: { ...frame } });
    function resolve(id) {
      if (!id) return fail('ambiguous_or_missing_target', id, null, 'Целевой контрол не найден или неоднозначен.');
      if (cache.has(id)) return cache.get(id);
      if (visiting.has(id)) return fail('cycle', id, null, 'Цикл родительских слотов.');
      const node = nodes[id];
      if (!node) return fail('missing_node', id, null, 'Контрол родителя отсутствует.');
      if (node.incoming.length !== 1) return fail(node.incoming.length ? 'multiple_parents' : 'outside_selected_root', id, null, 'Нет единственной цепочки до выделенного корня.');
      const edge = node.incoming[0], slot = schema.slots[edge.slot];
      if (!slot || String(slot.decoded.parent_export) !== edge.parent || String(slot.decoded.content_export) !== id) return fail('invalid_slot', id, edge.slot, 'Ребро не соответствует исходному слоту.');
      visiting.add(id);
      const parent = resolve(edge.parent);
      visiting.delete(id);
      if (parent.unknown) return parent;
      if (nodes[edge.parent].kind !== 'CanvasPanel' || !slot.decoded.layout) return fail('unsupported_container', id, edge.slot, 'Расчёт контейнера ' + nodes[edge.parent].kind + ' ещё не подключён.');
      const decoded = { ...slot.decoded };
      if (decoded.auto_size === undefined) {
        if (!policy.omitted_auto_size_false) return fail('unknown_auto_size', id, edge.slot, 'Наследуемый AutoSize не установлен.');
        decoded.auto_size = false;
        assumptions.add('slot ' + edge.slot + ': отсутствующий AutoSize принят false только по явной политике демо.');
      } else if (![0, 1, false, true].includes(decoded.auto_size)) return fail('invalid_auto_size', id, edge.slot, 'Некорректный AutoSize.');
      const result = G.canvas(decoded, parent.rect, desired[id]);
      const value = result.unknown ? fail('unknown_canvas', id, edge.slot, result.unknown) : result;
      cache.set(id, value); return value;
    }
    const rects = {}, unknowns = {};
    for (const [key, target] of Object.entries(targets)) {
      const result = resolve(find(target));
      if (result.unknown) unknowns[key] = result.unknown;
      else rects[key] = result.rect;
    }
    return { rects, unknowns, assumptions: [...assumptions].sort(), scope: 'local_canvas_only' };
  }
  const api = { solve };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirLayoutSchema = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
