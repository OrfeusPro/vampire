/* Source-bound projected widget tree. Bindings/actions are explicit demo adapters. */
(function(root) {
  'use strict';
  const L = typeof module !== 'undefined' && module.exports ? require('./layout-schema.js') : root.VampirLayoutSchema;
  const supported = new Set(['CanvasPanel', 'Overlay', 'SizeBox', 'ProgressBar', 'NkTextBlock', 'NkButton']);
  function plan(schema, options, bindings) {
    const ids = {}, targets = {}, parents = {}, problems = {}, bound = new Set();
    const find = value => Object.hasOwn(schema.nodes, value) ? String(value) : (() => {
      const matches = Object.keys(schema.nodes).filter(k => schema.nodes[k].name === value);
      return matches.length === 1 ? matches[0] : null;
    })();
    const rootId = find(options.root);
    if (!rootId) throw Error('Неоднозначный корень генерации.');
    for (const [key, binding] of Object.entries(bindings)) {
      const id = find(binding.control); ids[key] = id;
      if (!id) { problems[key] = { code: 'ambiguous_or_missing_control' }; continue; }
      if (bound.has(id)) { problems[key] = { code: 'duplicate_binding', node: id }; continue; }
      bound.add(id);
      if (binding.kind !== schema.nodes[id].kind) { problems[key] = { code: 'binding_kind_mismatch', node: id }; continue; }
      let cursor = id; const seen = new Set();
      while (cursor && !seen.has(cursor)) {
        seen.add(cursor); targets[cursor] = cursor;
        if (cursor === rootId) break;
        const node = schema.nodes[cursor];
        if (!node || node.incoming.length !== 1) break;
        parents[cursor] = node.incoming[0].parent; cursor = parents[cursor];
      }
    }
    targets[rootId] = rootId;
    const layout = L.solve(schema, { ...options, targets });
    const unknowns = { ...problems, ...layout.unknowns }, widgets = [], visited = new Set();
    function emit(id) {
      if (visited.has(id)) return;
      visited.add(id);
      const node = schema.nodes[id];
      if (!node || !layout.rects[id]) return;
      if (!supported.has(node.kind)) { unknowns[id] = { code: 'unsupported_widget_kind', kind: node.kind }; return; }
      const parent = id === rootId ? null : parents[id];
      if (parent) emit(parent);
      if (parent && !widgets.some(w => w.id === parent)) return;
      const box = layout.rects[id], origin = parent ? layout.rects[parent] : options.frame;
      widgets.push({ id, parent, name: node.name, kind: node.kind, source: node.source,
        rect: { x: box.x - origin.x, y: box.y - origin.y, width: box.width, height: box.height } });
    }
    Object.keys(targets).forEach(emit);
    return { root: rootId, ids, widgets, unknowns, assumptions: [...layout.assumptions,
      'Отрисована явная проекция выбранных контролов; visibility, порядок наложения, Brush и native events требуют проверки.'] };
  }
  function mount({ document, schema, options, bindings, actions = {} }) {
    const compiled = plan(schema, options, bindings);
    if (Object.keys(compiled.unknowns).length) throw Error('Генерация виджетов: ' + JSON.stringify(compiled.unknowns));
    const elements = {}, all = new Map();
    for (const widget of compiled.widgets) {
      const tag = widget.kind === 'NkButton' ? 'button' : widget.kind === 'NkTextBlock' ? 'span' : 'div';
      const node = document.createElement(tag); node.className = 'compiled-widget';
      node.dataset.widgetKind = widget.kind; node.dataset.sourceExport = widget.id; node.dataset.sourceSha = widget.source.sha256;
      const box = widget.rect;
      Object.assign(node.style, { position: widget.parent ? 'absolute' : '',
        left: `calc(${box.x} * var(--ui-component-unit))`, top: `calc(${box.y} * var(--ui-component-unit))`,
        width: `calc(${box.width} * var(--ui-component-unit))`, height: `calc(${box.height} * var(--ui-component-unit))` });
      if (tag === 'button') node.type = 'button';
      if (widget.kind === 'ProgressBar') {
        node.setAttribute('role', 'progressbar'); node.setAttribute('aria-valuemin', '0');
        const fill = document.createElement('div'); fill.className = 'vital-fill'; node.append(fill);
      }
      all.set(widget.id, node); if (widget.parent) all.get(widget.parent).append(node);
    }
    const buttonNodes = [];
    for (const [key, binding] of Object.entries(bindings)) {
      const node = all.get(compiled.ids[key]); elements[key] = node;
      if (binding.className) node.classList.add(...binding.className.split(/\s+/));
      if (binding.label) node.setAttribute('aria-label', binding.label);
      if (Number.isInteger(binding.demo_layer)) node.style.zIndex = String(binding.demo_layer);
      if (binding.kind === 'NkButton') {
        const action = actions[binding.action]; node.disabled = typeof action !== 'function';
        node.onclick = typeof action === 'function' ? () => { node.focus({ preventScroll: true }); action(); } : null;
        buttonNodes.push(node);
      }
    }
    let closed = false;
    function update(values) {
      if (closed) throw Error('Проекция виджетов закрыта.');
      // Validate all requested progress values before modifying any view.
      for (const [key, value] of Object.entries(values)) {
        if (!elements[key] || !['ProgressBar', 'NkTextBlock'].includes(bindings[key].kind)) throw Error('Нет привязки обновляемого значения: ' + key);
        if (bindings[key].kind === 'ProgressBar' && (!value || ![value.value, value.max].every(Number.isFinite) || value.max <= 0 || value.value < 0 || value.value > value.max)) throw Error('Некорректное значение полосы: ' + key);
      }
      for (const [key, value] of Object.entries(values)) {
        const node = elements[key]; if (!node) throw Error('Нет привязки: ' + key);
        if (bindings[key].kind === 'ProgressBar') {
          node.firstChild.style.width = value.value / value.max * 100 + '%';
          node.setAttribute('aria-valuenow', String(value.value)); node.setAttribute('aria-valuemax', String(value.max));
          node.setAttribute('aria-valuetext', String(value.value) + '/' + String(value.max));
        } else if (bindings[key].kind === 'NkTextBlock') node.textContent = String(value);
        else throw Error('Тип не поддерживает обновление значения: ' + key);
      }
    }
    return { node: all.get(compiled.root), elements, update, compiled,
      dispose() { closed = true; buttonNodes.forEach(n => { n.onclick = null; }); } };
  }
  const api = { plan, mount };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirWidgetRenderer = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
