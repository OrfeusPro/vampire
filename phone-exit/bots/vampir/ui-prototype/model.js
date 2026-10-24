/* Local demo adapter. This file has no transport and never accepts credentials. */
(function (root) {
  'use strict';
  const SCHEMA = 1, STORAGE_KEY = 'phone-exit.vampir.ui-demo.v1';
  const CLASSES = [['SwordMan', 'Кровавый рыцарь'], ['Gunner', 'Стрелок'], ['Fighter', 'Карнаж'], ['DarkMage', 'Тёмный маг'], ['Reaper', 'Мрачный Жнец']];
  const clone = value => JSON.parse(JSON.stringify(value));
  function profileKey(profile = 'demo-01') {
    if (!/^[a-zA-Z0-9_-]{1,48}$/.test(profile)) throw Error('Некорректный идентификатор окна.');
    return STORAGE_KEY + '.' + profile;
  }
  function appearance() { return { gender: 'Female', classId: 'Reaper', preset: 1, hair: 1, face: 1, eyes: 1, makeup: 1, voice: 1, body: [50, 50, 50, 50, 50, 50, 50] }; }
  function initial() {
    return { schema: SCHEMA, server: 'Franz 2', region: 'Весь мир', characters: [{ id: 'demo-1', name: 'Nocturne', level: 18, appearance: appearance(), primary: true }], selected: 'demo-1',
      gold: 16880438, diamonds: 2400, inventory: { blade: 1, helm: 1, armor: 1, potion: 30, blessing: 1, book: 2 }, equipped: {},
      quest: { progress: 0, claimed: false, auto: false }, hp: 10576, mp: 2453, experience: 0,
      position: null, target: null, follow: false, quick: ['potion', 'blessing', 'book', null, null],
      settings: { labels: true, sounds: false, scale: 100 }, mailClaimed: false, collection: false };
  }
  const PRODUCTS = {
    blade: { name: 'Меч сумерек', kind: 'equipment', slot: 'weapon', icon: 'IMG_Flat_Character', price: 150, currency: 'diamonds', attack: 42, description: 'Демонстрационный предмет. Повышает атаку при экипировке.' },
    helm: { name: 'Шлем стража', kind: 'equipment', slot: 'head', icon: 'IMG_Flat_Dress', price: 90, currency: 'diamonds', defense: 18, description: 'Демонстрационная экипировка для ячейки головы.' },
    armor: { name: 'Доспех ночи', kind: 'equipment', slot: 'body', icon: 'IMG_Flat_Dress', price: 200, currency: 'diamonds', defense: 35, description: 'Демонстрационный доспех. Бонус применяется к характеристикам.' },
    potion: { name: 'Зелье восстановления', kind: 'consumable', icon: 'IMG_Flat_Potion', price: 40, currency: 'gold', description: 'Восстанавливает 1200 HP в локальной модели.' },
    blessing: { name: 'Благодать добычи (28 дн.)', kind: 'consumable', icon: 'IMG_Flat_Item', price: 1200, currency: 'diamonds', description: 'Демонстрационный эффект: получение опыта +3%. Цены и условия не являются данными сервера.' },
    book: { name: 'Книга гравировки', kind: 'material', icon: 'IMG_Flat_Skill', price: 30, currency: 'diamonds', description: 'Материал локальной демонстрации коллекции.' }
  };
  function validate(state) {
    if (!state || state.schema !== SCHEMA || !Array.isArray(state.characters) || state.characters.length > 3) return false;
    if (!Number.isSafeInteger(state.gold) || !Number.isSafeInteger(state.diamonds) || state.gold < 0 || state.diamonds < 0) return false;
    if (!state.inventory || Object.entries(state.inventory).some(([id, n]) => !PRODUCTS[id] || !Number.isSafeInteger(n) || n < 0)) return false;
    if (!state.equipped || Object.entries(state.equipped).some(([slot, id]) => !PRODUCTS[id] || PRODUCTS[id].slot !== slot || !(state.inventory[id] > 0))) return false;
    const ids = new Set();
    for (const c of state.characters) {
      if (!c || typeof c.id !== 'string' || ids.has(c.id) || typeof c.name !== 'string' || !/^.{2,16}$/u.test(c.name) || !validAppearance(c.appearance) || !Number.isFinite(c.level)) return false;
      ids.add(c.id);
    }
    if (state.selected !== null && !ids.has(state.selected)) return false;
    return state.quest && Number.isInteger(state.quest.progress) && state.quest.progress >= 0 && state.quest.progress <= 3 &&
      typeof state.quest.claimed === 'boolean' && typeof state.quest.auto === 'boolean' &&
      Number.isFinite(state.hp) && state.hp >= 0 && state.hp <= 12440 && Number.isFinite(state.mp) && state.mp >= 0 && state.mp <= 4085 &&
      Number.isSafeInteger(state.experience) && state.experience >= 0 &&
      Array.isArray(state.quick) && state.quick.length === 5 && state.quick.every(x => x === null || PRODUCTS[x]) &&
      state.settings && typeof state.settings.labels === 'boolean' && [80, 90, 100, 110, 120].includes(state.settings.scale) &&
      typeof state.region === 'string' && ['Franz 2', 'Kurzel 1', 'Franz 3'].includes(state.server) &&
      [state.position, state.target].every(p => p === null || (Number.isFinite(p.x) && Number.isFinite(p.y) && Math.abs(p.x) <= 1e9 && Math.abs(p.y) <= 1e9));
  }
  function validAppearance(a) {
    return a && ['Female', 'Male'].includes(a.gender) && CLASSES.some(x => x[0] === a.classId) &&
      ['preset', 'hair', 'face', 'eyes', 'makeup', 'voice'].every(k => Number.isInteger(a[k]) && a[k] >= 1 && a[k] <= 32) &&
      Array.isArray(a.body) && a.body.length === 7 && a.body.every(n => Number.isFinite(n) && n >= 0 && n <= 100);
  }
  function load(storage, dataset, profile = 'demo-01') {
    try {
      const raw = storage.getItem(profileKey(profile));
      if (!raw) return { state: initial(), issue: null };
      const value = JSON.parse(raw);
      if (value.dataset !== dataset || !validate(value.state)) return { state: initial(), issue: 'Сохранение относится к другому набору данных или повреждено. Выберите явный сброс; исходная запись сохранена.' };
      return { state: value.state, issue: null };
    } catch { return { state: initial(), issue: 'Локальное сохранение недоступно или повреждено. Автоматическая перезапись отключена.' }; }
  }
  function stats(state) {
    return Object.values(state.equipped).reduce((out, id) => ({ attack: out.attack + (PRODUCTS[id].attack || 0), defense: out.defense + (PRODUCTS[id].defense || 0) }), { attack: 120, defense: 80 });
  }
  function apply(state, type, payload = {}) {
    const next = clone(state), fail = message => { throw Error(message); };
    const item = PRODUCTS[payload.id];
    switch (type) {
      case 'server':
        if (!['Franz 2', 'Kurzel 1'].includes(payload.server)) fail('Сервер недоступен для входа.');
        next.server = payload.server; next.region = payload.region || 'Весь мир'; break;
      case 'select':
      case 'primary':
        if (!next.characters.some(c => c.id === payload.id)) fail('Выберите персонажа.');
        next.selected = payload.id;
        if (type === 'primary') next.characters.forEach(c => c.primary = c.id === payload.id);
        break;
      case 'create': {
        const name = String(payload.name || '').trim();
        if (!/^[\p{L}\p{N}_-]{2,16}$/u.test(name)) fail('Имя: от 2 до 16 букв, цифр, знаков _ или -.');
        if (next.characters.length >= 2) fail('Свободных ячеек нет. Третья ячейка заблокирована в демо.');
        if (next.characters.some(c => c.name.toLocaleLowerCase() === name.toLocaleLowerCase())) fail('Такое имя уже занято в демо.');
        if (!validAppearance(payload.appearance)) fail('Некорректные параметры внешности.');
        const id = 'demo-' + (payload.uid || Date.now().toString(36));
        if (next.characters.some(c => c.id === id)) fail('Повторный идентификатор персонажа.');
        next.characters.push({ id, name, level: 1, appearance: clone(payload.appearance), primary: next.characters.length === 0 }); next.selected = id; break;
      }
      case 'delete':
        if (!next.characters.some(c => c.id === payload.id)) fail('Персонаж уже удалён.');
        next.characters = next.characters.filter(c => c.id !== payload.id);
        if (!next.characters.some(c => c.primary) && next.characters[0]) next.characters[0].primary = true;
        next.selected = next.characters[0]?.id || null; break;
      case 'buy': {
        if (!item) fail('Товар отсутствует.');
        const count = payload.count ?? 1;
        if (!Number.isInteger(count) || count < 1 || count > 99) fail('Количество: от 1 до 99.');
        const cost = item.price * count;
        if (next[item.currency] < cost) fail('Недостаточно ресурсов.');
        next[item.currency] -= cost; next.inventory[payload.id] = (next.inventory[payload.id] || 0) + count; break;
      }
      case 'equip':
        if (!item?.slot || !next.inventory[payload.id]) fail('Предмет нельзя экипировать.');
        next.equipped[item.slot] = payload.id; break;
      case 'unequip':
        if (!['weapon', 'head', 'body'].includes(payload.slot)) fail('Неизвестная ячейка.');
        delete next.equipped[payload.slot]; break;
      case 'use':
        if (item?.kind !== 'consumable' || !next.inventory[payload.id]) fail('Предмет нельзя использовать.');
        if (payload.id === 'potion' && next.hp === 12440) fail('Здоровье уже восстановлено.');
        next.inventory[payload.id]--;
        if (payload.id === 'potion') next.hp = Math.min(12440, next.hp + 1200);
        if (payload.id === 'blessing') next.experience += 30;
        break;
      case 'quick':
        if (!Number.isInteger(payload.slot) || payload.slot < 0 || payload.slot >= 5 || (payload.id !== null && !item)) fail('Некорректный быстрый слот.');
        next.quick[payload.slot] = payload.id; break;
      case 'quest-step': next.quest.progress = Math.min(3, next.quest.progress + 1); break;
      case 'quest-auto': next.quest.auto = !next.quest.auto; break;
      case 'quest-claim':
        if (next.quest.progress < 3 || next.quest.claimed) fail('Награда пока недоступна.');
        next.quest.claimed = true; next.gold += 500; next.experience += 100; break;
      case 'mail-claim':
        if (next.mailClaimed) fail('Подарок уже получен.');
        next.mailClaimed = true; next.inventory.potion += 5; break;
      case 'collection':
        if (next.collection || !next.inventory.book) fail('Нет подходящего предмета или коллекция уже заполнена.');
        next.collection = true; next.inventory.book--; break;
      case 'map-target': next.target = { x: payload.x, y: payload.y }; break;
      case 'map-arrive': next.position = next.target; next.target = null; break;
      case 'map-position': next.position = { x: payload.x, y: payload.y }; break;
      case 'follow': next.follow = !next.follow; break;
      case 'settings':
        for (const key of ['labels', 'sounds', 'scale']) if (Object.hasOwn(payload, key)) next.settings[key] = payload[key]; break;
      default: fail('Действие не реализовано: ' + type);
    }
    if (!validate(next)) fail('Изменение не прошло проверку состояния.');
    return next;
  }
  function adapter(state, onChange) {
    return { get state() { return clone(state); }, dispatch(type, payload) { state = apply(state, type, payload); onChange?.(clone(state), type); return clone(state); } };
  }
  const api = { SCHEMA, STORAGE_KEY, profileKey, CLASSES, PRODUCTS, initial, appearance, clone, validate, load, stats, apply, adapter };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirDemo = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
