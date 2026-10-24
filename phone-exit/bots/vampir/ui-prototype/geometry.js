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
  const api = { rect, canvas, chain, units, cssRect };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirGeometry = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
