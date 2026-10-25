/* Catalog selection only; resource names do not prove runtime window roles. */
(function(root) {
  'use strict';
  function filter(records, { query = '', scope = 'all', kind = 'all' } = {}) {
    if (!Array.isArray(records) || !['all', 'name', 'ui-name'].includes(scope) || !['all', 'popup', 'other'].includes(kind)) throw Error('Неизвестный режим отбора каталога.');
    const needle = String(query).trim().toLowerCase();
    return records.filter(row => {
      const name = String(row.name || '');
      if (scope === 'ui-name' && !name.includes('UI')) return false;
      if (kind !== 'all' && Boolean(row.popup) !== (kind === 'popup')) return false;
      const text = scope === 'all' ? name + ' ' + String(row.path || '') : name;
      return text.toLowerCase().includes(needle);
    });
  }
  const api = { filter };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirCatalogQuery = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
