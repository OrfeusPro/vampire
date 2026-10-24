/* Sparse per-character demo collection state. Source values do not prove server rules. */
(function(root) {
  'use strict';
  const clone = value => JSON.parse(JSON.stringify(value));
  const id = value => typeof value === 'string' && /^\d{1,16}$/.test(value);
  const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const text = value => typeof value === 'string' && value.length > 0 && value.length <= 1000;
  const integer = (value, min = 0, max = 1000000) => Number.isSafeInteger(value) && value >= min && value <= max;
  const object = value => value && typeof value === 'object' && !Array.isArray(value);
  const key = (itemId, enchant) => itemId + '@' + enchant;
  const initial = () => ({ source: null, items: {}, entries: {} });
  const complete = entry => entry.registered.length === entry.requirements.length;
  function validIcon(icon) {
    return icon === null || (object(icon) && sha(icon.sha256) && icon.url === 'collection-assets/' + icon.sha256 + '.png' && typeof icon.asset_path === 'string' && icon.asset_path.startsWith('/Game/') && icon.asset_path.length <= 1000);
  }
  function validDefinition(entry) {
    return object(entry) && id(entry.id) && text(entry.name) && Array.isArray(entry.requirements) && entry.requirements.length > 0 && entry.requirements.length <= 100 &&
      new Set(entry.requirements.map(row => row.id)).size === entry.requirements.length && entry.requirements.every(row => object(row) && id(row.id) && id(row.itemId) && integer(row.enchant, 0, 100) && integer(row.count, 1)) &&
      Array.isArray(entry.bonuses) && entry.bonuses.length > 0 && entry.bonuses.length <= 100 && entry.bonuses.every(b => object(b) && id(b.type) && text(b.name) && [b.min, b.max].every(n => Number.isFinite(n) && Math.abs(n) <= 1e9) && b.min <= b.max && [null, '0', '1'].includes(b.percentage));
  }
  function valid(value) {
    if (!object(value) || !object(value.items) || !object(value.entries) || (value.source !== null && !sha(value.source)) || Object.keys(value.items).length > 10000 || Object.keys(value.entries).length > 5000) return false;
    if (value.source === null && (Object.keys(value.items).length || Object.keys(value.entries).length)) return false;
    if (Object.entries(value.items).some(([k, item]) => !object(item) || !id(item.itemId) || !integer(item.enchant, 0, 100) || k !== key(item.itemId, item.enchant) || !integer(item.count, 0, 1e9) || !text(item.name) || !validIcon(item.icon))) return false;
    return Object.entries(value.entries).every(([entryId, entry]) => validDefinition(entry) && entryId === entry.id && ['supplied', 'favorite', 'locked'].every(k => typeof entry[k] === 'boolean') &&
      Array.isArray(entry.registered) && new Set(entry.registered).size === entry.registered.length && entry.registered.every(reqId => entry.requirements.some(row => row.id === reqId)) &&
      entry.requirements.every(row => Object.hasOwn(value.items, key(row.itemId, row.enchant))));
  }
  function normalize(data, source) {
    if (!sha(source) || !object(data?.entry) || !object(data.items)) throw Error('Нет проверенного источника коллекции.');
    const e = data.entry;
    const definition = { id: e.id, name: e.name, requirements: e.requirements.map(req => {
      const row = req.row;
      if (row.CollectType !== '1' || row.GroupId !== e.id || row.CollectParam !== req.item_id || !/^\d+$/.test(row.Count) || !/^\d+$/.test(row.EnchantLevel)) throw Error('Тип или связь требования не поддержаны.');
      return { id: row.Id, itemId: req.item_id, count: Number(row.Count), enchant: Number(row.EnchantLevel) };
    }), bonuses: e.bonuses.map(b => {
      if (b.row.GroupId !== e.row.OperationGroupId || !String(b.row.Min ?? '').trim() || !String(b.row.Max ?? '').trim()) throw Error('Нарушен источник бонуса коллекции.');
      return { type: b.row.Type, name: b.name?.Name || b.enum?.name || 'Параметр ' + b.row.Type,
        min: Number(b.row.Min), max: Number(b.row.Max), percentage: ['0', '1'].includes(b.display?.IsPercentage) ? b.display.IsPercentage : null };
    }) };
    if (!validDefinition(definition)) throw Error('Некорректное определение коллекции.');
    const items = {};
    for (const req of definition.requirements) {
      const item = data.items[req.itemId];
      if (!item || item.id !== req.itemId || !text(item.name)) throw Error('Отсутствует исходный предмет коллекции.');
      const candidates = item.icon?.images || [], image = candidates.length === 1 ? candidates[0] : null;
      const icon = image ? { url: image.url, sha256: image.sha256, asset_path: image.asset_path } : null;
      if (!validIcon(icon)) throw Error('Иконка коллекции не относится к снимку.');
      items[key(req.itemId, req.enchant)] = { itemId: req.itemId, enchant: req.enchant, name: item.name, icon, count: 0 };
    }
    return { source, definition, items };
  }
  function change(value, mode, bundle, requirementId) {
    if (!valid(value) || !sha(bundle?.source) || !validDefinition(bundle?.definition) || !object(bundle.items)) throw Error('Некорректные данные регистрации.');
    const next = clone(value), definition = bundle.definition;
    const expectedKeys = new Set(definition.requirements.map(req => key(req.itemId, req.enchant)));
    if (Object.keys(bundle.items).length !== expectedKeys.size || Object.entries(bundle.items).some(([k, item]) => !expectedKeys.has(k) || item?.count !== 0)) throw Error('Некорректный набор исходных предметов.');
    if (next.source !== null && next.source !== bundle.source) throw Error('Источник коллекций изменился. Наборы нельзя смешивать.');
    next.source = bundle.source;
    let entry = next.entries[definition.id];
    if (entry) {
      const saved = { id: entry.id, name: entry.name, requirements: entry.requirements, bonuses: entry.bonuses };
      if (JSON.stringify(saved) !== JSON.stringify(definition)) throw Error('Определение коллекции изменилось.');
    } else next.entries[definition.id] = entry = { ...clone(definition), registered: [], supplied: false, favorite: false, locked: false };
    for (const [k, item] of Object.entries(bundle.items)) {
      if (next.items[k]) {
        const previous = { ...next.items[k], count: 0 };
        if (JSON.stringify(previous) !== JSON.stringify(item)) throw Error('Источник предмета изменился.');
      } else next.items[k] = clone(item);
    }
    if (!valid(next)) throw Error('Нарушена связь предметов и коллекции.');
    if (mode === 'supply') {
      if (entry.supplied || complete(entry)) throw Error('Тестовый набор для этой коллекции уже выдан или не требуется.');
      const needed = {};
      for (const req of entry.requirements) if (!entry.registered.includes(req.id)) { const k = key(req.itemId, req.enchant); needed[k] = (needed[k] || 0) + req.count; }
      for (const [k, count] of Object.entries(needed)) next.items[k].count = Math.max(next.items[k].count, count);
      entry.supplied = true;
    } else if (mode === 'enroll') {
      if (entry.locked) throw Error('Регистрация в коллекцию заблокирована в демо.');
      const req = entry.requirements.find(row => row.id === requirementId);
      if (!req || entry.registered.includes(req.id)) throw Error('Требование отсутствует или уже зарегистрировано.');
      const item = next.items[key(req.itemId, req.enchant)];
      if (item.count < req.count) throw Error('Недостаточно предметов с требуемым усилением.');
      item.count -= req.count; entry.registered.push(req.id);
    } else if (mode === 'favorite') entry.favorite = !entry.favorite;
    else if (mode === 'lock') entry.locked = !entry.locked;
    else throw Error('Неизвестная операция коллекции.');
    if (!valid(next)) throw Error('Результат регистрации не прошёл проверку.');
    return next;
  }
  function bonuses(value) {
    const sums = new Map();
    for (const entry of Object.values(value.entries)) if (complete(entry)) for (const bonus of entry.bonuses) {
      const k = bonus.type + ':' + bonus.percentage, row = sums.get(k) || { ...bonus, min: 0, max: 0, collections: 0 };
      row.min += bonus.min; row.max += bonus.max; row.collections++; sums.set(k, row);
    }
    return [...sums.values()];
  }
  const api = { initial, valid, normalize, change, bonuses, key, complete };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.VampirCollections = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
