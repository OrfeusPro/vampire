/* Historical catalog browser. No inventory mutations or game transport. */
(function(root) {
  'use strict';
  const PAGE_SIZE = 40;
  function select(index, { query = '', tab = '', rarity = '' } = {}) {
    const q = query.trim().toLocaleLowerCase();
    return index.entries.filter(row => (!tab || row.tab === tab) && (!rarity || row.rarity_id === rarity) &&
      (!q || (row.id + ' ' + row.name).toLocaleLowerCase().includes(q)));
  }
  function page(rows, requested) {
    const count = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    const number = Math.max(0, Math.min(count - 1, requested));
    return { rows: rows.slice(number * PAGE_SIZE, (number + 1) * PAGE_SIZE), number, count };
  }
  async function read(file, signal, expected) {
    const response = await fetch(file, { signal });
    if (!response.ok) throw Error('Каталог недоступен: HTTP ' + response.status);
    const bytes = await response.arrayBuffer();
    if (expected) {
      const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(x => x.toString(16).padStart(2, '0')).join('');
      if (hash !== expected) throw Error('Контрольная сумма каталога не совпала.');
    }
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  function create(readJSON = read) {
    const controller = new AbortController(), cache = new Map(), pending = new Map();
    let indexPromise;
    const index = () => {
      if (controller.signal.aborted) return Promise.reject(new DOMException('Каталог закрыт.', 'AbortError'));
      if (!indexPromise) indexPromise = readJSON('collection-index.json', controller.signal).catch(error => { indexPromise = null; throw error; });
      return indexPromise;
    };
    async function chunk(file) {
      if (cache.has(file)) { const value = cache.get(file); cache.delete(file); cache.set(file, value); return value; }
      if (!pending.has(file)) {
        const promise = index().then(meta => {
          if (!/^collection-data\/(entries|items)-\d+\.json$/.test(file) || !meta.chunks[file]) throw Error('Неизвестная часть каталога.');
          return readJSON(file, controller.signal, meta.chunks[file]);
        }).then(value => {
          if (!controller.signal.aborted) cache.set(file, value);
          while (cache.size > 5) cache.delete(cache.keys().next().value);
          return value;
        }).finally(() => pending.delete(file));
        pending.set(file, promise);
      }
      return pending.get(file);
    }
    async function entry(id) {
      const meta = await index(), spec = meta.entries.find(row => row.id === id);
      if (!spec) throw Error('Коллекция отсутствует в снимке.');
      const value = (await chunk(spec.file))[id];
      if (!value || value.id !== id) throw Error('Нарушена связь коллекции.');
      const itemIds = [...new Set(value.requirements.map(row => row.item_id))];
      const items = Object.fromEntries(await Promise.all(itemIds.map(async itemId => {
        const item = (await chunk(meta.items[itemId]))[itemId];
        if (!item || item.id !== itemId) throw Error('Нарушена связь предмета коллекции.');
        return [itemId, item];
      })));
      return { entry: value, items };
    }
    return { index, entry, close() { controller.abort(); cache.clear(); pending.clear(); indexPromise = null; } };
  }
  const api = { select, page, create, PAGE_SIZE };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.VampirCollectionCatalog = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
