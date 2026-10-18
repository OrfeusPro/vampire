(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ItemStatModel = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const partKey = part => JSON.stringify(['OperationCategory', 'IsExtra', 'Index'].map(k => part.row[k] ?? ''));
  const operationKey = operation => JSON.stringify([operation.row.Type, operation.row.OperationRarity]);
  const range = (min, max) => min === max ? min : min + '–' + max;
  function subtract(a, b) {
    if (!/^-?\d+(\.\d+)?$/.test(a) || !/^-?\d+(\.\d+)?$/.test(b)) return null;
    const digits = Math.max((a.split('.')[1] || '').length, (b.split('.')[1] || '').length);
    const integer = value => { const [whole, fraction = ''] = value.split('.'); return BigInt(whole + fraction.padEnd(digits, '0')); };
    let difference = integer(a) - integer(b);
    const sign = difference < 0n ? '-' : difference > 0n ? '+' : '';
    if (difference < 0n) difference = -difference;
    let text = difference.toString().padStart(digits + 1, '0');
    if (digits) text = (text.slice(0, -digits) + '.' + text.slice(-digits)).replace(/0+$/, '').replace(/\.$/, '');
    return sign + text;
  }
  function compare(operation, part, baseParts) {
    const total = range(operation.row.Min, operation.row.Max);
    const unavailable = { total, base: total, delta: null, added: false, unavailable: true };
    const parts = baseParts.filter(p => partKey(p) === partKey(part));
    if (parts.length !== 1 || part.operations.filter(o => operationKey(o) === operationKey(operation)).length !== 1) return unavailable;
    const candidates = parts[0].operations.filter(o => operationKey(o) === operationKey(operation));
    if (candidates.length > 1) return unavailable;
    const source = candidates[0]?.row || { Min: '0', Max: '0' };
    const min = subtract(operation.row.Min, source.Min), max = subtract(operation.row.Max, source.Max);
    if (min === null || max === null) return unavailable;
    return { total, base: range(source.Min, source.Max), delta: min === '0' && max === '0' ? null : range(min, max), added: candidates.length === 0 };
  }
  return { compare, subtract };
});
