/* Pure canvas geometry. Caller supplies known parent/scale/desired-size inputs.
 * Results are frontend calculations, not a replay of Unreal/Slate runtime.
 */
(function (root) {
  'use strict';
  const finite = n => typeof n === 'number' && Number.isFinite(n);
  function rect(x, y, width, height) {
    if (![x, y, width, height].every(finite) || width < 0 || height < 0) throw Error('Некорректная геометрия контейнера.');
    return { x, y, width, height };
  }
  function canvas(slot, parent, desired) {
    const l = slot.layout;
    if (!l?.offsets || !Array.isArray(l.anchors?.minimum) || !Array.isArray(l.anchors?.maximum) || !Array.isArray(l.alignment) || [l.anchors.minimum, l.anchors.maximum, l.alignment].some(x => x.length !== 2)) return { unknown: 'Нет полной Canvas-геометрии.' };
    const { offsets: o, anchors: a, alignment } = l;
    if (![o.left, o.top, o.right, o.bottom, ...a.minimum, ...a.maximum, ...alignment].every(finite)) return { unknown: 'Некорректные Canvas-поля.' };
    const dimensions = [['x', 'width', 'left', 'right', 0], ['y', 'height', 'top', 'bottom', 1]], result = {};
    for (const [axis, size, start, end, i] of dimensions) {
      const stretched = a.minimum[i] !== a.maximum[i];
      let length;
      if (stretched) length = parent[size] * (a.maximum[i] - a.minimum[i]) - o[start] - o[end];
      else if (slot.auto_size) {
        if (!desired || !finite(desired[size])) return { unknown: 'AutoSize: desired size не установлен для ' + axis + '.' };
        length = desired[size];
      } else length = o[end];
      if (!finite(length) || length < 0) return { unknown: 'Размер выходит за допустимые границы.' };
      result[axis] = parent[axis] + parent[size] * a.minimum[i] + o[start] - (stretched ? 0 : alignment[i] * length);
      result[size] = length;
    }
    return { rect: result };
  }
  function aligned(slot, parent, desired) {
    const p = slot.padding, h = slot.horizontal_alignment, v = slot.vertical_alignment;
    if (!p || !['left', 'right', 'top', 'bottom'].every(k => finite(p[k]))) return { unknown: 'Padding контейнера не установлен.' };
    if (![h, v].every(n => Number.isInteger(n) && n >= 0 && n <= 3)) return { unknown: 'Alignment контейнера не установлен.' };
    const result = {};
    for (const [axis, size, start, end, alignment] of [['x', 'width', 'left', 'right', h], ['y', 'height', 'top', 'bottom', v]]) {
      const available = Math.max(0, parent[size] - p[start] - p[end]);
      if (alignment !== 0 && (!desired || !finite(desired[size]) || desired[size] < 0)) return { unknown: 'Нужен desired size для alignment ' + axis + '.' };
      const length = alignment === 0 ? available : Math.min(available, desired[size]);
      const extra = alignment === 2 ? (available - length) / 2 : alignment === 3 ? available - length : 0;
      result[axis] = parent[axis] + p[start] + extra; result[size] = length;
    }
    return { rect: result };
  }
  function chain(binding, parent, desired = {}) {
    let current = parent;
    const assumptions = [], used = [];
    for (const entry of [...binding.chain].reverse()) {
      const d = entry.decoded;
      if (d.layout) {
        const result = canvas(d, current, desired[d.content_export]);
        if (result.unknown) return { unknown: result.unknown, slot: entry.provenance.slot_export, used };
        current = result.rect; used.push(entry.provenance.slot_export);
      } else if (['WidgetSwitcher', 'HorizontalBox'].includes(d.parent?.type) && binding.allowAllocatedFrame && Object.values(d.padding || {}).every(n => n === 0)) {
        assumptions.push('Контрол использует выделенную рамку ' + d.parent.name + '; desired size / visibility требуют сверки.');
      } else return { unknown: 'Контейнер ' + (d.parent?.type || 'unknown') + ' ещё не рассчитан.', slot: entry.provenance.slot_export, used };
    }
    return { rect: current, assumptions, used };
  }
  function desiredTree(node) {
    if (!node || typeof node !== 'object') return { unknown: 'Нет схемы desired size.' };
    const assumptions = [...(node.assumptions || [])];
    if (node.excluded_reason) return { width: 0, height: 0, assumptions: [...assumptions, node.excluded_reason] };
    if (node.kind === 'fixed') {
      if (![node.width, node.height].every(n => finite(n) && n >= 0)) return { unknown: 'Нет обеих явных размеров SizeBox.' };
      return { width: node.width, height: node.height, assumptions };
    }
    if (!['HorizontalBox', 'VerticalBox', 'Overlay'].includes(node.kind) || !Array.isArray(node.children) || !node.children.length) return { unknown: 'Desired size контейнера ' + node.kind + ' не разобран.' };
    let width = 0, height = 0;
    for (const child of node.children) {
      const result = desiredTree(child.node);
      if (result.unknown) return result;
      assumptions.push(...result.assumptions);
      const padding = child.padding;
      if (!padding || !['left', 'right', 'top', 'bottom'].every(k => finite(padding[k]))) return { unknown: 'Padding слота desired size не установлен.' };
      const w = result.width + padding.left + padding.right, h = result.height + padding.top + padding.bottom;
      if (node.kind === 'HorizontalBox') { width += w; height = Math.max(height, h); }
      else if (node.kind === 'VerticalBox') { width = Math.max(width, w); height += h; }
      else { width = Math.max(width, w); height = Math.max(height, h); }
    }
    if (![width, height].every(n => finite(n) && n >= 0)) return { unknown: 'Недопустимый desired size.' };
    return { width, height, assumptions: [...new Set(assumptions)] };
  }
  function units({ cssWidth, cssHeight, devicePixelRatio, osDpiScale, applicationScale, uiScale, dpiCurveScale }) {
    const values = [cssWidth, cssHeight, devicePixelRatio, osDpiScale, applicationScale, uiScale, dpiCurveScale];
    if (!values.every(n => finite(n) && n > 0)) return { unknown: 'Нужно явно установить DPI, ApplicationScale, UI Scale и DPI curve scale.' };
    const physicalPerLogical = osDpiScale * applicationScale * uiScale * dpiCurveScale;
    const cssPerLogical = physicalPerLogical / devicePixelRatio;
    return { cssPerLogical, physicalPerLogical, logicalViewport: rect(0, 0, cssWidth / cssPerLogical, cssHeight / cssPerLogical) };
  }
  function cssRect(value, scale) {
    if (!finite(scale) || scale <= 0) throw Error('Некорректный масштаб.');
    return rect(value.x * scale, value.y * scale, value.width * scale, value.height * scale);
  }
  function referenceScale(parent, binding, uiScale = 1) {
    if (![parent.width, parent.height, binding.reference_width, uiScale].every(n => finite(n) && n > 0)) throw Error('Некорректные входы масштаба демо.');
    let scale = parent.width / binding.reference_width;
    if (binding.reference_height !== undefined) {
      if (!finite(binding.reference_height) || binding.reference_height <= 0) throw Error('Некорректная высота reference frame.');
      scale = Math.min(scale, parent.height / binding.reference_height);
    }
    return scale * uiScale;
  }
  const api = { rect, canvas, aligned, chain, desiredTree, referenceScale, units, cssRect };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirGeometry = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
