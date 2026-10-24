/* Local demo adapter. This file has no transport and never accepts credentials. */
(function (root) {
  'use strict';
  const SCHEMA = 5, STORAGE_KEY = 'phone-exit.vampir.ui-demo.v1';
  const VITAL_LIMITS = Object.freeze({ hp: 12440, mp: 4085 });
  const Skill = typeof module !== 'undefined' && module.exports ? require('./skills.js') : root.VampirSkills;
  const Collection = typeof module !== 'undefined' && module.exports ? require('./collection-state.js') : root.VampirCollections;
  const CLASSES = [['SwordMan', 'Кровавый рыцарь'], ['Gunner', 'Стрелок'], ['Fighter', 'Карнаж'], ['DarkMage', 'Тёмный маг'], ['Reaper', 'Мрачный Жнец']];
  const clone = value => JSON.parse(JSON.stringify(value));
  function profileKey(profile = 'demo-01') {
    if (!/^[a-zA-Z0-9_-]{1,48}$/.test(profile)) throw Error('Некорректный идентификатор окна.');
    return STORAGE_KEY + '.' + profile;
  }
  function appearance() { return { gender: 'Female', classId: 'Reaper', preset: 1, hair: 1, face: 1, eyes: 1, makeup: 1, voice: 1, body: [50, 50, 50, 50, 50, 50, 50] }; }
  const CHARACTER_FIELDS = ['gold', 'diamonds', 'inventory', 'equipped', 'quest', 'hp', 'mp', 'experience', 'position', 'target', 'follow', 'quick', 'mailClaimed', 'collection', 'skills', 'collections'];
  function characterState(classId = 'Reaper') {
    return { gold: 16880438, diamonds: 2400, inventory: { blade: 1, helm: 1, armor: 1, potion: 30, blessing: 1, book: 2 }, equipped: {},
      quest: { progress: 0, claimed: false, auto: false }, hp: 10576, mp: 2453, experience: 0,
      position: null, target: null, follow: false, quick: ['potion', 'blessing', 'book', null, null],
      mailClaimed: false, collection: false, skills: Skill.initial(classId), collections: Collection.initial() };
  }
  const SERVERS = ['Franz 2', 'Kurzel 1'];
  const SERVER_FIELDS = ['characters', 'selected', 'characterStates'];
  function serverFields(state) { return Object.fromEntries(SERVER_FIELDS.map(key => [key, clone(state[key])])); }
  function project(state) {
    const bank = clone(state.serverStates[state.server]);
    return { ...state, ...bank, ...clone(bank.characterStates[bank.selected] || characterState()) };
  }
  function characterFields(state) { return Object.fromEntries(CHARACTER_FIELDS.map(key => [key, clone(state[key])])); }
  function canonical(state) {
    return clone(Object.fromEntries(['schema', 'server', 'region', 'serverStates', 'settings'].map(key => [key, state[key]])));
  }
  function initial() {
    return project({ schema: SCHEMA, server: 'Franz 2', region: 'Весь мир', serverStates: {
      'Franz 2': { characters: [{ id: 'demo-1', name: 'Nocturne', level: 18, appearance: appearance(), primary: true }], selected: 'demo-1', characterStates: { 'demo-1': characterState() } },
      'Kurzel 1': { characters: [], selected: null, characterStates: {} }
    }, settings: { labels: true, sounds: false, scale: 100 } });
  }

  const PRODUCTS = {
    blade: { name: 'Меч сумерек', kind: 'equipment', slot: 'weapon', icon: 'IMG_Flat_Character', price: 150, currency: 'diamonds', attack: 42, description: 'Демонстрационный предмет. Повышает атаку при экипировке.' },
    helm: { name: 'Шлем стража', kind: 'equipment', slot: 'head', icon: 'IMG_Flat_Dress', price: 90, currency: 'diamonds', defense: 18, description: 'Демонстрационная экипировка для ячейки головы.' },
    armor: { name: 'Доспех ночи', kind: 'equipment', slot: 'body', icon: 'IMG_Flat_Dress', price: 200, currency: 'diamonds', defense: 35, description: 'Демонстрационный доспех. Бонус применяется к характеристикам.' },
    potion: { name: 'Зелье восстановления', kind: 'consumable', icon: 'IMG_Flat_Potion', price: 40, currency: 'gold', description: 'Восстанавливает 1200 HP в локальной модели.' },
    blessing: { name: 'Благодать добычи (28 дн.)', kind: 'consumable', icon: 'IMG_Flat_Item', price: 1200, currency: 'diamonds', description: 'Демонстрационный эффект: получение опыта +3%. Цены и условия не являются данными сервера.' },
    book: { name: 'Книга гравировки', kind: 'material', icon: 'IMG_Flat_Skill', price: 30, currency: 'diamonds', description: 'Материал локальной демонстрации коллекции.' }
  };
  function validCharacterState(state) {
    if (!state || typeof state !== 'object') return false;
    if (!Number.isSafeInteger(state.gold) || !Number.isSafeInteger(state.diamonds) || state.gold < 0 || state.diamonds < 0) return false;
    if (!state.inventory || Array.isArray(state.inventory) || Object.keys(PRODUCTS).some(id => !Object.hasOwn(state.inventory, id)) || Object.entries(state.inventory).some(([id, n]) => !Object.hasOwn(PRODUCTS, id) || !Number.isSafeInteger(n) || n < 0)) return false;
    if (!state.equipped || Array.isArray(state.equipped) || Object.entries(state.equipped).some(([slot, id]) => !Object.hasOwn(PRODUCTS, id) || PRODUCTS[id].slot !== slot || !(state.inventory[id] > 0))) return false;
    return !!(state.quest && Number.isInteger(state.quest.progress) && state.quest.progress >= 0 && state.quest.progress <= 3 &&
      typeof state.quest.claimed === 'boolean' && typeof state.quest.auto === 'boolean' &&
      Number.isFinite(state.hp) && state.hp >= 0 && state.hp <= VITAL_LIMITS.hp && Number.isFinite(state.mp) && state.mp >= 0 && state.mp <= VITAL_LIMITS.mp &&
      Number.isSafeInteger(state.experience) && state.experience >= 0 && typeof state.follow === 'boolean' &&
      typeof state.mailClaimed === 'boolean' && typeof state.collection === 'boolean' && Collection.valid(state.collections) &&
      Array.isArray(state.quick) && state.quick.length === 5 && state.quick.every(x => x === null || Object.hasOwn(PRODUCTS, x)) &&
      [state.position, state.target].every(p => p === null || (p && typeof p === 'object' && Number.isFinite(p.x) && Number.isFinite(p.y) && Math.abs(p.x) <= 1e9 && Math.abs(p.y) <= 1e9)));
  }
  function validateActive(state) {
    if (!state || state.schema !== SCHEMA || !Array.isArray(state.characters) || state.characters.length > 2) return false;
    if (!state.characterStates || typeof state.characterStates !== 'object' || Array.isArray(state.characterStates)) return false;
    const ids = new Set();
    for (const c of state.characters) {
      if (!c || !/^demo-[a-zA-Z0-9_-]{1,64}$/.test(c.id) || ids.has(c.id) || typeof c.name !== 'string' || !/^[\p{L}\p{N}_-]{2,16}$/u.test(c.name) || !validAppearance(c.appearance) || !Number.isInteger(c.level) || c.level < 1 || c.level > 1000 || typeof c.primary !== 'boolean') return false;
      if (!Object.hasOwn(state.characterStates, c.id) || !validCharacterState(state.characterStates[c.id]) || !Skill.validate(state.characterStates[c.id].skills, c.appearance.classId)) return false;
      ids.add(c.id);
    }
    if ((state.characters.length === 0) !== (state.selected === null) || (state.selected !== null && !ids.has(state.selected))) return false;
    if (state.characters.filter(c => c.primary).length !== (ids.size ? 1 : 0) || Object.keys(state.characterStates).some(id => !ids.has(id))) return false;
    // Render projections are accepted only if they agree with the canonical bank.
    const active = state.characterStates[state.selected] || characterState();
    if (CHARACTER_FIELDS.some(key => Object.hasOwn(state, key)) && CHARACTER_FIELDS.some(key => JSON.stringify(state[key]) !== JSON.stringify(active[key]))) return false;
    return !!(state.settings && typeof state.settings.labels === 'boolean' && typeof state.settings.sounds === 'boolean' && [80, 90, 100, 110, 120].includes(state.settings.scale) &&
      ['Весь мир', 'Европа', 'Азия'].includes(state.region) && ['Franz 2', 'Kurzel 1', 'Franz 3'].includes(state.server));
  }
  function validate(state) {
    if (!state || state.schema !== SCHEMA || !SERVERS.includes(state.server) ||
        !state.serverStates || typeof state.serverStates !== 'object' || Array.isArray(state.serverStates) ||
        Object.keys(state.serverStates).length !== SERVERS.length) return false;
    for (const server of SERVERS) {
      const bank = state.serverStates[server];
      if (!bank || typeof bank !== 'object' || Array.isArray(bank) ||
          Object.keys(bank).length !== SERVER_FIELDS.length || !SERVER_FIELDS.every(key => Object.hasOwn(bank, key)) ||
          !validateActive({ schema: state.schema, server, region: state.region, settings: state.settings, ...bank })) return false;
    }
    const bank = state.serverStates[state.server];
    if (SERVER_FIELDS.some(key => Object.hasOwn(state, key)) &&
        SERVER_FIELDS.some(key => JSON.stringify(state[key]) !== JSON.stringify(bank[key]))) return false;
    return validateActive({ schema: state.schema, server: state.server, region: state.region,
      settings: state.settings, ...bank, ...Object.fromEntries(CHARACTER_FIELDS.filter(key => Object.hasOwn(state, key)).map(key => [key, state[key]])) });
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
      return { state: project(value.state), issue: null };
    } catch { return { state: initial(), issue: 'Локальное сохранение недоступно или повреждено. Автоматическая перезапись отключена.' }; }
  }
  function stats(state) {
    return Object.values(state.equipped).reduce((out, id) => ({ attack: out.attack + (PRODUCTS[id].attack || 0), defense: out.defense + (PRODUCTS[id].defense || 0) }), { attack: 120, defense: 80 });
  }
  function vitals(state) {
    return Object.entries(VITAL_LIMITS).map(([id, max]) => {
      const value = state[id];
      if (!Number.isFinite(value) || value < 0 || value > max) throw Error('Некорректное значение ' + id.toUpperCase());
      return { id, name: id.toUpperCase(), value, max, ratio: value / max };
    });
  }
  function apply(state, type, payload = {}) {
    if (!validate(state)) throw Error('Некорректное исходное состояние.');
    const next = project(canonical(state)), fail = message => { throw Error(message); };
    const previousCharacter = next.selected;
    if (!previousCharacter && !['create', 'server', 'settings'].includes(type)) fail('Сначала создайте персонажа.');
    const item = PRODUCTS[payload.id];
    switch (type) {
      case 'server': {
        if (!SERVERS.includes(payload.server)) fail('Сервер недоступен для входа.');
        next.server = payload.server; next.region = payload.region || 'Весь мир';
        const result = project(canonical(next));
        if (!validate(result)) fail('Изменение сервера не прошло проверку состояния.');
        return result;
      }
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
        delete next.characterStates[payload.id];
        if (!next.characters.some(c => c.primary) && next.characters[0]) next.characters[0].primary = true;
        if (next.selected === payload.id) next.selected = next.characters[0]?.id || null; break;
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
        if (payload.id === 'potion' && next.hp === VITAL_LIMITS.hp) fail('Здоровье уже восстановлено.');
        next.inventory[payload.id]--;
        if (payload.id === 'potion') next.hp = Math.min(VITAL_LIMITS.hp, next.hp + 1200);
        if (payload.id === 'blessing') next.experience += 30;
        break;
      case 'skill-learn': {
        const skill = Skill.skills[payload.id], c = next.characters.find(c => c.id === next.selected);
        if (!skill || skill.classId !== c.appearance.classId || next.skills.levels[payload.id]) fail('Навык недоступен для изучения.');
        if (next.gold < skill.learnCost) fail('Недостаточно золота.');
        next.gold -= skill.learnCost; next.skills.levels[payload.id] = 1; break;
      }
      case 'skill-upgrade': {
        const level = next.skills.levels[payload.id], skill = Skill.skills[payload.id];
        if (!level || level >= skill.maxLevel) fail('Повышение уровня недоступно.');
        const cost = level * 100;
        if (next.gold < cost) fail('Недостаточно золота.');
        next.gold -= cost; next.skills.levels[payload.id]++; break;
      }
      case 'skill-slot': {
        if (!Number.isInteger(payload.slot) || payload.slot < 0 || payload.slot >= 5 || (payload.id !== null && !Object.hasOwn(next.skills.levels, payload.id))) fail('Некорректный слот навыка.');
        const other = payload.id === null ? -1 : next.skills.slots.indexOf(payload.id);
        if (other >= 0) next.skills.slots[other] = next.skills.slots[payload.slot];
        next.skills.slots[payload.slot] = payload.id; break;
      }
      case 'skill-auto':
        if (!Object.hasOwn(next.skills.levels, payload.id)) fail('Сначала изучите навык.');
        next.skills.auto = next.skills.auto.includes(payload.id) ? next.skills.auto.filter(id => id !== payload.id) : [...next.skills.auto, payload.id]; break;
      case 'skill-cast': {
        const skill = Skill.skills[payload.id], now = payload.now;
        if (!skill || !Object.hasOwn(next.skills.levels, payload.id)) fail('Навык не изучен.');
        if (!Number.isSafeInteger(now) || now < 0 || now > 1e15 - skill.cooldown) fail('Некорректное время применения.');
        if ((next.skills.readyAt[payload.id] || 0) > now) fail('Навык на перезарядке.');
        if (next.mp < skill.mp) fail('Недостаточно MP.');
        next.mp -= skill.mp; next.skills.readyAt[payload.id] = now + skill.cooldown; break;
      }
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
      case 'collection-supply':
      case 'collection-enroll':
      case 'collection-favorite':
      case 'collection-lock':
        if (payload.scope?.server !== next.server || payload.scope?.character !== next.selected) fail('Персонаж или сервер изменился. Откройте коллекцию заново.');
        next.collections = Collection.change(next.collections, type.slice('collection-'.length), payload.bundle, payload.requirementId); break;
      case 'map-target': next.target = { x: payload.x, y: payload.y }; break;
      case 'map-arrive': next.position = next.target; next.target = null; break;
      case 'map-position': next.position = { x: payload.x, y: payload.y }; break;
      case 'follow': next.follow = !next.follow; break;
      case 'settings':
        for (const key of ['labels', 'sounds', 'scale']) if (Object.hasOwn(payload, key)) next.settings[key] = payload[key]; break;
      default: fail('Действие не реализовано: ' + type);
    }
    if (next.selected !== previousCharacter) {
      if (previousCharacter && next.characters.some(c => c.id === previousCharacter)) next.characterStates[previousCharacter] = characterFields(next);
      if (next.selected && !next.characterStates[next.selected]) next.characterStates[next.selected] = characterState(next.characters.find(c => c.id === next.selected).appearance.classId);
      Object.assign(next, clone(next.characterStates[next.selected] || characterState()));
    } else if (next.selected) next.characterStates[next.selected] = characterFields(next);
    next.serverStates[next.server] = serverFields(next);
    if (!validate(next)) fail('Изменение не прошло проверку состояния.');
    return next;
  }
  function adapter(state, onChange) {
    if (!validate(state)) throw Error('Некорректное начальное состояние.');
    state = project(canonical(state));
    return { get state() { return clone(state); }, dispatch(type, payload) { state = apply(state, type, payload); onChange?.(clone(state), type); return clone(state); } };
  }
  function serialize(state) { if (!validate(state)) throw Error('Некорректное сохранение.'); return canonical(state); }
  const api = { SCHEMA, VITAL_LIMITS, SERVERS, SKILLS: Skill.skills, skillsForClass: Skill.forClass, COLLECTIONS: Collection, STORAGE_KEY, profileKey, CLASSES, PRODUCTS, initial, appearance, clone, validate, load, serialize, stats, vitals, apply, adapter };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirDemo = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
