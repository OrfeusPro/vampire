/* Interactive offline shell; unknown game behavior is exposed in the inspector. */
(() => {
  'use strict';
  const M = VampirDemo, app = document.getElementById('app'), windows = document.getElementById('windows');
  const requestedProfile = new URLSearchParams(location.search).get('bot') || 'demo-01';
  const profile = /^[a-zA-Z0-9_-]{1,48}$/.test(requestedProfile) ? requestedProfile : 'demo-01';
  const storageKey = M.profileKey(profile);
  const economy = new URLSearchParams(location.search).get('economy') !== 'off';
  let textures, manifest, registry, sourceItems, layouts, buttonLayouts, adapter, storageIssue, storageBlocked = false;
  let screen = 'auth', draft = M.appearance(), undo = [], redo = [], createTab = 'Пресет', toastTimer, busy = false;
  const dialogs = [], renderers = new Map(); let characterName = '';
  const state = () => adapter.state;
  const el = (tag, text, className) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; };
  const append = (parent, ...children) => { parent.append(...children.filter(Boolean)); return parent; };
  const fmt = n => Number(n).toLocaleString('ru-RU');
  function button(text, fn, className = '', disabled = false) { const b = el('button', text, className + ((!className || className === 'primary') ? ' original-button' : '')); b.type = 'button'; b.disabled = disabled; b.onclick = fn; return b; }
  let geometryFrame;
  function updateButtonGeometry() {
    cancelAnimationFrame(geometryFrame);
    geometryFrame = requestAnimationFrame(() => {
      if (!buttonLayouts) return;
      for (const node of document.querySelectorAll('[data-native-button]')) {
        const binding = buttonLayouts.bindings[node.dataset.nativeButton], parent = node.closest('dialog') || app;
        if (!binding || !parent.clientWidth || !parent.clientHeight) continue;
        const scale = parent.clientWidth / binding.reference_width * state().settings.scale / 100;
        const result = VampirGeometry.chain(binding, VampirGeometry.rect(0, 0, parent.clientWidth / scale, parent.clientHeight / scale));
        node.dataset.geometryState = result.unknown ? 'unresolved' : result.assumptions.length ? 'allocated-frame-assumption' : 'canvas-calculation';
        if (result.unknown) { node.dataset.geometryUnknown = result.unknown; continue; }
        const box = VampirGeometry.cssRect(result.rect, scale), origin = parent.getBoundingClientRect();
        Object.assign(node.style, { position: 'fixed', left: origin.left + parent.clientLeft + box.x + 'px', top: origin.top + parent.clientTop + box.y + 'px', width: box.width + 'px', height: box.height + 'px', margin: '0', minWidth: '0', padding: '0 .4em', zIndex: '2' });
      }
    });
  }
  const geometryObserver = new ResizeObserver(updateButtonGeometry);
  function nativeButton(node, key) { node.dataset.nativeButton = key; return node; }
  function image(name, className = '') {
    const value = textures[name];
    if (!value) return el('span', '◇', 'missing-icon ' + className);
    const img = el('img', undefined, className); img.src = value.url; img.alt = ''; img.loading = 'lazy'; return img;
  }
  function icon(name, label, fn, key) {
    const b = button('', fn, 'icon-button'); b.title = label; b.setAttribute('aria-label', label);
    append(b, image(name), el('span', label)); if (key) append(b, el('kbd', key)); return b;
  }
  function notify(text) { const n = document.getElementById('toast'); n.textContent = text; n.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => n.hidden = true, 4500); }
  function action(type, payload) { try { adapter.dispatch(type, payload); return true; } catch (error) { info('Действие недоступно', error.message); return false; } }
  function persist(value) {
    if (storageBlocked) return;
    try { localStorage.setItem(storageKey, JSON.stringify({ dataset: manifest.data_id || manifest.id, state: M.serialize(value) })); }
    catch { storageBlocked = true; storageIssue = 'Не удалось сохранить демо. Текущее состояние доступно до закрытия страницы.'; notify(storageIssue); }
  }
  function currentCharacter() { return state().characters.find(c => c.id === state().selected); }
  function className(id) { return M.CLASSES.find(x => x[0] === id)?.[1] || id; }
  function portrait(a = M.appearance(), full = false) { return image(full ? 'IMG_Class_' + a.classId + '_' + a.gender : 'IMG_Customize_Preset_' + a.gender + '_' + String(a.preset).padStart(2, '0'), full ? 'character-image' : 'portrait'); }
  function currency(key, value) {
    const n = el('span', undefined, 'currency');
    n.setAttribute('aria-label', (key === 'gold' ? 'Золото: ' : 'Алмазы: ') + fmt(value));
    return append(n, image(key === 'gold' ? 'IMG_Asset_Gold' : 'IMG_Asset_Diamond'), el('span', fmt(value)));
  }
  function currencies() { return append(el('div', undefined, 'currencies'), currency('gold', state().gold), currency('diamonds', state().diamonds)); }

  function field(label, input) {
    const direct = /^(INPUT|SELECT|TEXTAREA)$/.test(input.tagName), n = el(direct ? 'label' : 'div', undefined, 'field'), text = el('span', label);
    if (!direct) { text.id = 'label-' + crypto.randomUUID(); input.setAttribute('role', 'group'); input.setAttribute('aria-labelledby', text.id); }
    append(n, text, input); return n;
  }
  function input(type, placeholder = '') { const n = document.createElement('input'); n.type = type; n.placeholder = placeholder; return n; }
  function select(values, value, fn) { const n = document.createElement('select'); values.forEach(x => { const option = el('option', typeof x === 'string' ? x : x[1]); option.value = typeof x === 'string' ? x : x[0]; n.append(option); }); n.value = value; n.onchange = () => fn(n.value); return n; }
  function tabs(names, current, fn) { const n = el('nav', undefined, 'tabs'); n.setAttribute('aria-label', 'Вкладки'); names.forEach(name => { const b = button(name, () => fn(name), name === current ? 'active' : ''); b.setAttribute('aria-pressed', String(name === current)); n.append(b); }); return n; }
  function closeDialog(dialog) { if (!dialog.open) return; dialog.close(); }
  function focusIdentity(node) {
    return node && node !== document.body ? { label: node.getAttribute('aria-label'), title: node.getAttribute('title'), text: node.textContent, tag: node.tagName } : null;
  }
  function restoreFocus(identity, scope) {
    if (!identity || !scope) return;
    const candidates = [...scope.querySelectorAll('button,input,select,a')];
    const match = candidates.find(n => n.tagName === identity.tag && !n.disabled &&
      (identity.label ? n.getAttribute('aria-label') === identity.label : identity.title ? n.getAttribute('title') === identity.title : n.textContent === identity.text));
    match?.focus({ preventScroll: true });
  }
  function modal(title, render, className = '') {
    const invoker = focusIdentity(document.activeElement);
    const dialog = el('dialog', undefined, className), heading = el('h2', title), body = el('div', undefined, 'dialog-body');
    const placement = layouts.profiles[className];
    if (placement) {
      const [x, y, w, h] = placement.rect;
      dialog.classList.add('placed-window'); dialog.dataset.layoutResource = placement.resource;
      Object.assign(dialog.style, { left: x * 100 + 'vw', top: y * 100 + 'dvh', width: w * 100 + 'vw', height: h * 100 + 'dvh', margin: '0', maxWidth: '100vw', maxHeight: '100dvh' });
    }
    heading.id = 'window-' + crypto.randomUUID(); dialog.setAttribute('aria-labelledby', heading.id);
    const header = el('header', undefined, 'window-heading');
    append(header, heading, button('×', () => closeDialog(dialog), 'close'));
    header.lastChild.setAttribute('aria-label', 'Закрыть ' + title);
    if (className === 'item-card') nativeButton(header.lastChild, 'item-close');
    append(dialog, header, body); windows.append(dialog); dialogs.push(dialog);
    const redraw = () => { const focused = dialog.contains(document.activeElement) ? focusIdentity(document.activeElement) : null; body.replaceChildren(); render(body, dialog); restoreFocus(focused, dialog); updateButtonGeometry(); };
    renderers.set(dialog, redraw);
    dialog.addEventListener('close', () => { geometryObserver.unobserve(dialog); renderers.delete(dialog); const at = dialogs.indexOf(dialog); if (at >= 0) dialogs.splice(at, 1); dialog.remove(); restoreFocus(invoker, dialogs.filter(d => d.open).at(-1) || app); });
    redraw(); dialog.showModal(); geometryObserver.observe(dialog); updateButtonGeometry(); return dialog;
  }
  function info(title, message) { return modal(title, body => append(body, el('p', message), button('Понятно', () => closeDialog(dialogs.at(-1)), 'primary'))); }
  function confirm(title, message, fn) {
    return modal(title, (body, dialog) => {
      const actions = el('div', undefined, 'actions');
      append(actions, button('Отмена', () => closeDialog(dialog)), button('Подтвердить', () => { closeDialog(dialog); fn(); }, 'primary'));
      append(body, el('p', message), actions);
    });
  }
  function transition(next) { dialogs.slice().reverse().forEach(closeDialog); clearTimeout(toastTimer); document.getElementById('toast').hidden = true; cooldowns.clear(); screen = next; render(); }
  function pageTitle(text, back) { const n = el('header', undefined, 'page-title'); append(n, button('❮', back, 'back'), el('h1', text)); return n; }
  function footerNote() { return el('small', 'Демонстрационный режим · игровые команды не отправляются', 'demo-note'); }
  function render() {
    const focused = app.contains(document.activeElement) ? focusIdentity(document.activeElement) : null;
    app.replaceChildren(); app.className = 'screen screen-' + screen;
    if (screen === 'auth') renderAuth();
    if (screen === 'servers') renderServers();
    if (screen === 'title') renderTitle();
    if (screen === 'characters') renderCharacters();
    if (screen === 'classes') renderClasses();
    if (screen === 'create') renderCreate();
    if (screen === 'game') renderGame();
    app.append(footerNote());
    restoreFocus(focused, app);
    updateButtonGeometry();
  }
  function renderAuth() {
    const panel = el('section', undefined, 'auth-panel');
    const form = el('form'), name = input('text', 'Имя для демо'), password = input('password', 'Любое тестовое значение');
    name.required = true; name.maxLength = 32; name.autocomplete = 'off'; password.required = true; password.autocomplete = 'off';
    const submit = el('button', 'Войти', 'primary'); submit.type = 'submit';
    const error = el('p', '', 'form-error'); error.setAttribute('role', 'alert');
    form.onsubmit = event => {
      event.preventDefault(); if (busy) return;
      if (!name.value.trim()) { error.textContent = 'Укажите имя для демонстрации.'; return; }
      if (name.value.trim().toLowerCase() === 'error') { error.textContent = 'Демонстрация отказа входа. Измените имя и повторите.'; return; }
      busy = true; submit.disabled = true; submit.textContent = 'Вход…';
      password.value = ''; setTimeout(() => { busy = false; transition('servers'); }, 350);
    };
    append(form, field('Имя демопользователя', name), field('Тестовый пароль', password), error, submit);
    append(panel, el('div', 'VAMPIR', 'wordmark'), el('h1', 'Авторизация'), el('p', 'Локальный прототип интерфейса. Используйте вымышленные данные.'), form,
      button('Помощь со входом', () => info('Авторизация', 'Данные никуда не отправляются. Имя error показывает тестовый отказ. Пароль не сохраняется.')));
    app.append(panel);
  }
  function renderServers() {
    const panel = el('section', undefined, 'server-panel'); let region = state().region, group = state().server.split(' ')[0];
    append(app, pageTitle('Выбор сервера', () => transition('auth')));
    const groups = ['Franz', 'Kurzel'], list = el('div', undefined, 'server-list');
    function refresh() {
      list.replaceChildren();
      for (const server of group === 'Franz' ? ['Franz 2', 'Franz 3'] : ['Kurzel 1']) {
        const row = button('', () => { if (action('server', { server, region })) transition('title'); }, 'server-row');
        append(row, el('strong', server), el('span', server === 'Franz 3' ? 'Технические работы' : server === state().server ? 'Выбран · доступен' : 'Доступен', server === 'Franz 3' ? 'danger' : 'available')); if (server !== 'Franz 3') row.append(el('small', 'Персонажей в демо: ' + state().serverStates[server].characters.length)); list.append(row);
      }
    }
    append(panel, field('Регион', select(['Весь мир', 'Европа', 'Азия'], region, value => region = value)),
      tabs(groups, group, () => {}), list);
    // Rebuild only group navigation, keeping region selection intact.
    const choose = value => { group = value; panel.querySelector('nav').replaceWith(tabs(groups, group, choose)); refresh(); };
    panel.querySelector('nav').replaceWith(tabs(groups, group, choose)); refresh(); app.append(panel);
  }
  function renderTitle() {
    append(app, pageTitle('Vampir', () => transition('servers')));
    const tools = el('nav', undefined, 'top-tools');
    append(tools, icon('IMG_Flat_AccountGiftReceive', 'Подарки', () => openSection('Почта')), icon('IMG_Flat_Setting', 'Настройки', openSettings), icon('IMG_Flat_Change', 'Обновить', () => notify('Демонстрационный каталог сервера обновлён.')));
    const center = el('section', undefined, 'title-center');
    const enter = button('Пожалуйста, коснитесь экрана.', () => {
      if (busy) return; busy = true; enter.disabled = true; enter.textContent = 'Загрузка персонажей…';
      setTimeout(() => { busy = false; transition('characters'); }, 450);
    }, 'enter-game');
    append(center, el('div', 'VAMPIR', 'wordmark'), enter, el('p', '◎ ' + state().region), button(state().server + '  ⟳', () => transition('servers'), 'server-choice'));
    append(app, tools, center);
  }
  function renderCharacters() {
    append(app, pageTitle('Выбор персонажа', () => transition('title')));
    const c = currentCharacter(), left = el('section', undefined, 'character-details'), right = el('section', undefined, 'character-slots');
    if (c) {
      append(left, el('div', '✧', 'class-emblem'), el('p', 'Ур. ' + c.level + ' ' + className(c.appearance.classId)), el('h2', c.name), el('hr'), el('p', 'Последний вход: демонстрация'), el('p', 'Место входа: Пепельные останки'), el('p', 'Сервер: ' + state().server));
      const figure = el('div', undefined, 'character-preview'); append(figure, portrait(c.appearance, true)); app.append(figure);
    } else append(left, el('h2', 'Персонажей пока нет'), el('p', 'Создайте первого персонажа.'));
    state().characters.forEach(item => {
      const row = button('', () => { action('select', { id: item.id }); render(); }, 'character-slot ' + (c?.id === item.id ? 'selected' : ''));
      append(row, portrait(item.appearance), el('span', (item.primary ? '★ ' : '') + item.name + '\nУр. ' + item.level + ' ' + className(item.appearance.classId))); right.append(row);
    });
    if (state().characters.length < 2) right.append(button('＋ Создать персонажа', () => transition('classes'), 'character-slot'));
    right.append(button('♙ Заблокированная ячейка', () => info('Ячейка персонажа', 'Дополнительная ячейка недоступна в демонстрации.'), 'character-slot locked'));
    if (c) right.append(button(c.primary ? '★ Основной персонаж' : 'Назначить основным', () => { action('primary', { id: c.id }); render(); }));
    const actions = el('div', undefined, 'bottom-actions');
    append(actions, nativeButton(button('Удалить персонажа', () => confirm('Удаление персонажа', 'Удалить ' + c?.name + ' из локальной демонстрации?', () => { action('delete', { id: c.id }); render(); }), '', !c), 'character-delete'),
      nativeButton(button('Начать игру', () => transition('game'), 'primary', !c), 'character-start'));
    append(app, left, right, actions);
  }
  function renderClasses() {
    append(app, pageTitle('Выбор класса', () => transition('characters')));
    const list = el('section', undefined, 'class-list');
    M.CLASSES.forEach(([id, name]) => {
      const card = button('', () => { draft = M.appearance(); draft.classId = id; undo = []; redo = []; createTab = 'Пресет'; characterName = ''; transition('create'); }, 'class-card');
      append(card, portrait({ ...M.appearance(), classId: id }, true), el('h2', name)); list.append(card);
    });
    append(app, list, el('p', 'Выберите желаемый класс.', 'class-instruction'));
  }
  function editDraft(fn) { undo.push(M.clone(draft)); if (undo.length > 100) undo.shift(); redo = []; fn(draft); render(); }
  function renderCreate() {
    append(app, pageTitle('Создать персонажа', () => transition('classes')));
    const side = el('nav', undefined, 'customize-nav');
    [['Пресет', 'Preset'], ['Причёска', 'Hair'], ['Лицо', 'Character'], ['Глаза', 'Detail'], ['Кастомизация', 'PresetA'], ['Тело', 'Body'], ['Голос', 'Chat']].forEach(([name, iconName]) => {
      const b = icon('IMG_Flat_' + iconName, name, () => { createTab = name; render(); }); b.classList.toggle('active', createTab === name); side.append(b);
    });
    const preview = el('section', undefined, 'customize-preview'); append(preview, portrait(draft, true), el('p', '2D-превью · параметры сохраняются; геометрия модели не изменяется.', 'preview-note'));
    const options = el('section', undefined, 'customize-options'), history = el('div', undefined, 'history');
    append(history, button('↶ Отменить', () => { redo.push(M.clone(draft)); draft = undo.pop(); render(); }, '', !undo.length),
      button('↷ Повторить', () => { undo.push(M.clone(draft)); draft = redo.pop(); render(); }, '', !redo.length),
      button('⟳ Сброс', () => editDraft(a => Object.assign(a, M.appearance(), { gender: a.gender, classId: a.classId }))));
    options.append(history);
    const keys = { 'Пресет': ['preset', 'Preset_' + draft.gender], 'Причёска': ['hair', 'Hair_' + draft.gender], 'Лицо': ['face', 'Face_' + draft.gender], 'Глаза': ['eyes', 'Eye'], 'Кастомизация': ['makeup', 'Decal_' + draft.gender] };
    if (keys[createTab]) {
      const [key, prefix] = keys[createTab], grid = el('div', undefined, 'preset-grid');
      const available = Object.keys(textures).filter(n => n.startsWith('IMG_Customize_' + prefix + '_')).slice(0, 16);
      (available.length ? available : Object.keys(textures).filter(n => n.startsWith('IMG_Customize_Preset_' + draft.gender + '_')).slice(0, 16)).forEach((name, i) => {
        const b = button('', () => editDraft(a => a[key] = i + 1), draft[key] === i + 1 ? 'selected' : ''); b.setAttribute('aria-label', createTab + ' ' + (i + 1)); b.append(image(name)); grid.append(b);
      }); options.append(grid);
    } else if (createTab === 'Тело') {
      ['Телосложение', 'Рост', 'Голова', 'Грудь', 'Талия', 'Бёдра', 'Нижняя часть тела'].forEach((name, i) => {
        const range = input('range'); range.min = 0; range.max = 100; range.value = draft.body[i]; range.setAttribute('aria-label', name);
        const value = el('output', String(draft.body[i]));
        range.oninput = () => value.textContent = range.value;
        range.onchange = () => editDraft(a => a.body[i] = Number(range.value));
        const row = el('div', undefined, 'slider-row'), minus = button('−', () => editDraft(a => a.body[i] = Math.max(0, a.body[i] - 1))), plus = button('+', () => editDraft(a => a.body[i] = Math.min(100, a.body[i] + 1)));
        minus.setAttribute('aria-label', 'Уменьшить: ' + name); plus.setAttribute('aria-label', 'Увеличить: ' + name);
        append(row, minus, range, plus, value); options.append(field(name, row));
      });
    } else for (let i = 1; i <= 3; i++) options.append(button('Голос (тип ' + ['A', 'B', 'C'][i - 1] + ')', () => { editDraft(a => a.voice = i); notify('Тип голоса сохранён. Звуковое превью пока отсутствует.'); }, draft.voice === i ? 'selected' : ''));
    const gender = el('div', undefined, 'gender');
    append(gender, button('♂', () => editDraft(a => { a.gender = 'Male'; a.preset = 1; }), draft.gender === 'Male' ? 'selected' : ''), button('♀', () => editDraft(a => { a.gender = 'Female'; a.preset = 1; }), draft.gender === 'Female' ? 'selected' : ''));
    const actions = el('div', undefined, 'create-actions'); actions.append(button('Создать персонажа', openCharacterName, 'primary'));
    append(app, side, preview, options, gender, actions);
  }
  function openCharacterName() {
    modal('Имя персонажа', (body, dialog) => {
      const form = el('form', undefined, 'character-name-form'), name = input('text', 'Имя персонажа');
      name.required = true; name.maxLength = 16; name.value = characterName; name.autocomplete = 'off'; name.autofocus = true;
      name.oninput = () => characterName = name.value;
      const error = el('p', '', 'form-error'); error.setAttribute('role', 'alert');
      const submit = el('button', 'Создать', 'primary'); submit.type = 'submit';
      form.onsubmit = event => {
        event.preventDefault();
        try { adapter.dispatch('create', { name: name.value, appearance: draft }); transition('characters'); }
        catch (e) { error.textContent = e.message; name.focus(); }
      };
      const controls = el('div', undefined, 'actions'); append(controls, button('Отмена', () => closeDialog(dialog)), submit);
      append(form, field('Имя персонажа', name), el('p', 'От 2 до 16 букв, цифр, знаков _ или -.'), error, controls);
      body.append(form); name.focus();
    }, 'name-window');
  }
  function gameFrame() { return document.getElementById('world'); }
  function sendMap(type, payload) { gameFrame()?.contentWindow?.postMessage({ source: 'vampir-demo', type, payload }, location.origin); }
  function mapState() { const s = state(); sendMap('state', { position: s.position, target: s.target, follow: s.follow, labels: s.settings.labels }); }
  function renderGame() {
    const holder = el('div', undefined, 'map-holder'); holder.id = 'map-holder';
    const hud = el('div', undefined, 'hud'); hud.id = 'hud'; append(app, holder, hud); updateMapActivity(); refreshHud();
  }
  function updateMapActivity() {
    const holder = document.getElementById('map-holder'); if (!holder) return;
    const active = !document.hidden && (!economy || document.hasFocus());
    if (!active) {
      if (gameFrame() || !holder.firstChild) holder.replaceChildren(button('Карта приостановлена · активируйте окно', () => { window.focus(); mountMap(); }, 'map-paused'));
    } else if (!gameFrame()) mountMap();
  }
  function mountMap() {
    const holder = document.getElementById('map-holder'); if (!holder || gameFrame()) return;
    const frame = el('iframe'); frame.id = 'world'; frame.title = '2D-карта игрового мира'; frame.src = 'map.html'; frame.onload = mapState; holder.replaceChildren(frame);
  }
  function refreshHud() {
    const hud = document.getElementById('hud'); if (!hud) return; hud.replaceChildren();
    const s = state(), c = currentCharacter(); if (!c) { transition('characters'); return; }
    const health = button('', () => openSection('Персонаж'), 'health');
    const bars = el('div', undefined, 'health-bars');
    for (const [name, value, max] of [['HP', s.hp, 12440], ['MP', s.mp, 4085]]) {
      const bar = el('div', undefined, 'bar ' + name.toLowerCase()); bar.style.setProperty('--fill', value / max * 100 + '%'); bar.setAttribute('aria-label', name + ' ' + value + ' из ' + max); bar.append(el('span', fmt(value) + '/' + fmt(max))); bars.append(bar);
    }
    append(health, portrait(c.appearance), bars);
    const top = el('nav', undefined, 'hud-top');
    [['Alarm', 'Уведомления', () => openSection('Уведомления')], ['Quest', 'Задания', openQuests], ['Shop', 'Магазин', openShop], ['Inventory', 'Сумка', openBag], ['Menu', 'Меню', openMenu]].forEach(([ico, label, fn]) => top.append(icon('IMG_Flat_' + ico, label, fn)));
    const mapTools = el('div', undefined, 'minimap');
    append(mapTools, el('strong', 'Nocturne'), el('span', 'Карта мира'), button('Открыть карту', openWorldMap), button(s.follow ? '◉ Слежение вкл.' : '◎ Следовать', () => action('follow')));
    const quests = el('section', undefined, 'quest-tracker');
    append(quests, button('✧ Предвестник войны', openQuests, 'quest-title'), el('p', 'Исследуйте Тропу испытаний ' + s.quest.progress + '/3'), button(s.quest.auto ? '☑ Автовыполнение' : '☐ Автовыполнение', () => action('quest-auto')), button('Следующий шаг', () => { if (action('quest-step')) notify('Демонстрационный шаг задания выполнен.'); }));
    const left = el('nav', undefined, 'hud-left');
    [['Character', 'Персонаж'], ['Skill', 'Навыки'], ['Chat', 'Чат'], ['ItemCollection', 'Коллекции']].forEach(([ico, title]) => left.append(icon('IMG_Flat_' + ico, title, () => openSection(title))));
    const quick = el('div', undefined, 'quickbar');
    s.quick.forEach((id, i) => { const b = button('', () => id ? itemCard(id, true) : chooseQuick(i), 'item-slot'); if (id) append(b, productImage(id), el('small', String(s.inventory[id] || 0))); append(b, el('kbd', String(i + 1))); b.title = id ? M.PRODUCTS[id].name : 'Назначить предмет'; b.setAttribute('aria-label', 'Быстрый слот ' + (i + 1) + ': ' + (id ? M.PRODUCTS[id].name : 'пусто')); quick.append(b); });
    const skills = el('div', undefined, 'skillbar');
    ['F1', 'F2', 'F3', 'F4', 'F5'].forEach((key, i) => skills.append(icon('IMG_Flat_Skill', 'Навык ' + (i + 1), event => castSkill(i, key), key)));
    const attack = el('div', undefined, 'attack-controls');
    append(attack, button('◎ Цель', () => notify('Выбрана демонстрационная цель.')), button('ЗАДАНИЕ', openQuests), button('⚔', () => castSkill(5, 'F'), 'attack'));
    const bottom = el('div', undefined, 'level'); append(bottom, el('strong', String(c.level)), el('span', c.name + '\nОпыт ' + fmt(s.experience)), button('Выйти', () => transition('characters')));
    const route = el('div', undefined, 'route-controls');
    if (s.target) append(route, el('p', 'Выбрана точка карты'), button('Идти пешком · демо', () => { if (action('map-arrive')) notify('Маркер перемещён в демо. Проходимость маршрута не проверялась.'); }));
    append(hud, health, currencies(), top, mapTools, quests, left, quick, skills, attack, bottom, route); mapState();
  }
  const cooldowns = new Map();
  function castSkill(i, key) {
    const until = cooldowns.get(i) || 0;
    if (until > Date.now()) { notify('Перезарядка: ' + Math.ceil((until - Date.now()) / 1000) + ' с.'); return; }
    cooldowns.set(i, Date.now() + 3000); notify((i === 5 ? 'Атака' : 'Навык ' + (i + 1)) + ' · демонстрация, клавиша ' + key);
  }
  function productImage(id) {
    const icons = { blade: 'IMG_Weapon_BloodSword_Rare_03', helm: 'IMG_Armor_Helmet_Common_01', armor: 'IMG_Armor_Armor_Common_01', blessing: 'IMG_Item_Subscription_01', book: 'IMG_MatrixEnchantMaterial_02' };
    return image(icons[id] || sourceItems.find(x => /Potion/.test(x.icon))?.icon || M.PRODUCTS[id].icon, 'product-icon');
  }
  function itemSlot(id, fn) { const b = button('', fn || (() => itemCard(id)), 'item-slot'); b.title = M.PRODUCTS[id].name; b.setAttribute('aria-label', b.title); append(b, productImage(id), el('small', String(state().inventory[id] || 0))); return b; }
  function chooseQuick(slot) { modal('Быстрый слот ' + (slot + 1), (body, d) => { for (const [id, item] of Object.entries(M.PRODUCTS)) body.append(button(item.name, () => { if (action('quick', { slot, id })) closeDialog(d); })); }); }
  function itemCard(id, use = false) {
    const p = M.PRODUCTS[id];
    modal(p.name, (body, d) => {
      append(body, productImage(id), el('p', p.description), el('p', 'В сумке: ' + (state().inventory[id] || 0)), el('small', 'Название и механика — демо; иллюстрация из извлечённого каталога.'));
      if (p.slot) body.append(button('Экипировать', () => { if (action('equip', { id })) { closeDialog(d); notify('Предмет экипирован.'); } }, 'primary', !state().inventory[id]));
      if (p.kind === 'consumable') body.append(button('Использовать', () => { if (action('use', { id })) notify('Предмет использован.'); }, 'primary', !state().inventory[id]));
      body.append(button('На панель быстрого доступа', () => modal('Выберите слот', (n, pick) => { for (let i = 0; i < 5; i++) n.append(button(String(i + 1), () => { if (action('quick', { slot: i, id })) closeDialog(pick); })); })));
      if (!use) body.append(button('Найти в магазине', () => purchase(id)));
    }, 'item-card');
  }
  function openBag() {
    let category = 'Все', query = '';
    const draw = body => {
      body.append(tabs(['Все', 'Снаряжение', 'Расходники', 'Материалы'], category, value => { category = value; renderers.get(dialog)(); }));
      const search = input('search', 'Поиск предмета'); search.value = query;
      search.oninput = () => { query = search.value; fill(); }; body.append(search);
      const grid = el('div', undefined, 'bag-grid');
      const fill = () => { grid.replaceChildren(); for (const [id, p] of Object.entries(M.PRODUCTS)) if (state().inventory[id] && p.name.toLowerCase().includes(query.toLowerCase()) && (category === 'Все' || p.kind === ({ 'Снаряжение': 'equipment', 'Расходники': 'consumable', 'Материалы': 'material' }[category]))) grid.append(itemSlot(id)); };
      fill(); append(body, grid, el('p', 'Занято: ' + Object.values(state().inventory).filter(n => n > 0).length + '/116'), button('Экипировка', () => openSection('Персонаж')),
        button('Массовый разбор', () => info('Массовый разбор', 'Правила разбора и наград пока не восстановлены. Предметы сохранены.')));
    };
    const dialog = modal('Сумка', draw, 'inventory-window');
  }
  function openShop() {
    let category = 'Алмаз', section = 'Обмен';
    const draw = body => {
      append(body, currencies(), tabs(['Товар', 'Особый призыв', 'Обмен', 'Склад'], section, value => { section = value; renderers.get(dialog)(); }));
      const layout = el('div', undefined, 'shop-layout'), nav = el('nav', undefined, 'shop-categories'), grid = el('div', undefined, 'shop-grid');
      ['Алмаз', 'Золото', 'Снаряжение', 'Материалы'].forEach(name => nav.append(button(name, () => { category = name; renderers.get(dialog)(); }, category === name ? 'active' : '')));
      if (section === 'Особый призыв') grid.append(el('p', 'Стоимость и результат призыва не подтверждены. Сценарий остаётся в очереди.'));
      else for (const [id, p] of Object.entries(M.PRODUCTS)) {
        if (category === 'Золото' && p.currency !== 'gold' || category === 'Снаряжение' && p.kind !== 'equipment' || category === 'Материалы' && p.kind !== 'material') continue;
        const card = button('', () => section === 'Склад' ? itemCard(id) : purchase(id), 'shop-card');
        append(card, el('h3', p.name), el('small', 'Демонстрационный товар'), productImage(id), currency(p.currency, p.price)); grid.append(card);
      }
      append(layout, nav, grid); body.append(layout);
    };
    const dialog = modal('Магазин', draw, 'full-window');
  }
  function purchase(id) {
    const p = M.PRODUCTS[id]; let count = 1;
    modal(p.name, (body, d) => {
      const layout = el('div', undefined, 'purchase-layout'), art = el('div', undefined, 'product-art'), details = el('div');
      append(art, productImage(id), el('small', 'Локальная демонстрация · игровые условия не подтверждены'));
      const quantity = input('number'); quantity.min = 1; quantity.max = 99; quantity.value = count; quantity.setAttribute('aria-label', 'Количество');
      const buy = nativeButton(button('', () => { count = Number(quantity.value); if (action('buy', { id, count })) { closeDialog(d); notify('Покупка добавлена в сумку.'); } }, 'primary'), 'purchase-buy');
      const update = () => { buy.replaceChildren(el('span', 'Купить за '), currency(p.currency, p.price * Number(quantity.value))); }; quantity.oninput = () => { count = Number(quantity.value); update(); }; update();
      append(details, el('h3', 'Содержимое товара'), button(p.name, () => itemCard(id)), el('p', p.description), field('Количество', quantity), el('p', 'Доступные ресурсы: ' + fmt(state()[p.currency])), buy);
      append(layout, art, details); body.append(layout);
    }, 'purchase-window');
  }
  function openQuests() {
    modal('Задания', body => {
      append(body, el('h3', 'Предвестник войны'), el('p', 'Исследуйте Тропу испытаний. Демонстрационные этапы: прибытие, взаимодействие, завершение.'), el('p', 'Прогресс: ' + state().quest.progress + '/3'),
        button(state().quest.auto ? '☑ Автовыполнение' : '☐ Автовыполнение', () => action('quest-auto')),
        button('Выполнить следующий шаг · демо', () => action('quest-step'), '', state().quest.progress === 3),
        button(state().quest.claimed ? 'Награда получена' : 'Получить награду', () => { if (action('quest-claim')) info('Награда', 'Получено 500 золота и 100 опыта в демо.'); }, 'primary', state().quest.progress < 3 || state().quest.claimed));
    }, 'side-window');
  }
  function openWorldMap() {
    modal('Карта мира', body => {
      append(body, el('p', 'Карта находится под игровым интерфейсом. Закройте окно и выберите точку для демонстрационного маршрута.'),
        button('Приблизить', () => sendMap('zoom', 1)), button('Отдалить', () => sendMap('zoom', -1)), button('Вся карта', () => sendMap('fit')),
        button('К персонажу', () => sendMap('focus')), button(state().follow ? 'Отключить слежение' : 'Следовать за персонажем', () => action('follow')));
    });
  }
  function openSettings() {
    modal('Настройки', body => {
      body.append(field('Масштаб интерфейса', select([['80', '80%'], ['90', '90%'], ['100', '100%'], ['110', '110%'], ['120', '120%']], String(state().settings.scale), value => action('settings', { scale: Number(value) }))));
      const check = input('checkbox'); check.checked = state().settings.labels; check.onchange = () => action('settings', { labels: check.checked }); body.append(field('Названия мест на карте', check));
      body.append(button('Сбросить демонстрацию', () => confirm('Сброс демо', 'Удалить только локальные демонстрационные данные?', resetDemo)));
    });
  }
  function resetDemo() {
    try { localStorage.removeItem(storageKey); storageBlocked = false; storageIssue = null; }
    catch { storageBlocked = true; storageIssue = 'Хранилище недоступно. Сброшено только состояние текущей страницы.'; }
    setAdapter(M.initial()); persist(state()); transition('auth');
  }
  function openMenu() {
    modal('Меню', body => {
      const grid = el('div', undefined, 'menu-grid');
      [['Character', 'Персонаж'], ['Inventory', 'Сумка'], ['Skill', 'Навыки'], ['Quest', 'Задания'], ['ItemCollection', 'Коллекции'], ['Shop', 'Магазин'], ['ItemCraft', 'Создание'], ['Pet', 'Питомцы'], ['Post', 'Почта'], ['Setting', 'Настройки'], ['Achievement', 'Достижения'], ['Community', 'Сообщество']].forEach(([name, title]) => grid.append(icon('IMG_Flat_' + name, title, () => openSection(title))));
      append(body, grid, button('Все восстановленные ресурсы', openInspector), button('Выбор персонажа', () => transition('characters')));
    }, 'menu-window');
  }
  function catalogLink(body, title, url) {
    const link = el('a', title); link.href = url; link.target = '_blank'; link.rel = 'noopener'; body.append(link);
  }
  function openSection(title) {
    const handlers = { 'Сумка': openBag, 'Магазин': openShop, 'Задания': openQuests, 'Настройки': openSettings, 'Карта': openWorldMap };
    if (handlers[title]) return handlers[title]();
    return modal(title, body => {
      if (title === 'Персонаж') {
        const c = currentCharacter(); append(body, portrait(c?.appearance), el('h3', c?.name || 'Демоперсонаж'), el('p', className(c?.appearance.classId || 'Reaper')));
        const stats = M.stats(state()); append(body, el('p', 'Атака: ' + stats.attack + ' · Защита: ' + stats.defense));
        for (const [slot, name] of [['weapon', 'Оружие'], ['head', 'Голова'], ['body', 'Доспех']]) {
          const id = state().equipped[slot]; append(body, el('p', name + ': ' + (id ? M.PRODUCTS[id].name : 'пусто'))); if (id) body.append(button('Снять ' + name.toLowerCase(), () => action('unequip', { slot })));
        } body.append(button('Открыть сумку', openBag));
      } else if (title === 'Коллекции') {
        append(body, el('h3', 'Наследие ночи'), el('p', state().collection ? 'Коллекция заполнена' : 'Требуется: Книга гравировки ×1'), button('Добавить предмет', () => confirm('Коллекция', 'Потратить одну книгу в демо?', () => action('collection')), 'primary', state().collection));
        catalogLink(body, 'Полный справочник коллекций', '/maps/collections/index.html');
      } else if (title === 'Навыки') {
        for (let i = 0; i < 5; i++) body.append(button('Навык ' + (i + 1) + ' · применить', () => castSkill(i, 'F' + (i + 1))));
        catalogLink(body, 'Изученные навыки и эффекты', '/maps/atlas/skills.html');
      } else if (title === 'Почта') {
        append(body, el('h3', 'Добро пожаловать'), el('p', 'Демонстрационный подарок: 5 зелий.'), button(state().mailClaimed ? 'Получено' : 'Получить подарок', () => action('mail-claim'), 'primary', state().mailClaimed));
      } else if (title === 'Чат') {
        const log = el('div', 'Система: добро пожаловать в локальную демонстрацию.', 'chat-log'), form = el('form'), text = input('text', 'Сообщение'); text.maxLength = 300; text.required = true;
        const send = el('button', 'Отправить'); send.type = 'submit'; append(form, text, send); form.onsubmit = e => { e.preventDefault(); if (text.value.trim()) log.append(el('p', (currentCharacter()?.name || 'Демо') + ': ' + text.value)); text.value = ''; }; append(body, log, form);
      } else if (title === 'Уведомления') {
        append(body, el('p', 'Активен локальный демонстрационный режим.'), el('p', 'Серверное состояние не загружается.'), button('Обучение', () => info('Обучение', 'Откройте сумку, выберите меч и нажмите «Экипировать». Затем проверьте характеристики персонажа.')));
      } else {
        append(body, el('p', 'Окно включено в прототип. Игровая логика раздела ещё не восстановлена.'), button('Проверить ресурс окна', () => openInspector(title)));
        if (title === 'Создание') catalogLink(body, 'Справочник предметов и источников', '/maps/loot/items.html');
      }
    }, 'side-window');
  }
  async function openSharedElements() {
    try {
      const response = await fetch('shared-elements.json');
      if (!response.ok) throw Error(response.status);
      const shared = await response.json();
      modal('Общие элементы', body => {
        append(body, el('p', 'Исторические оригиналы. Привязки к текущему клиенту и области владения валютами требуют проверки.'), el('p', shared.unknown.join(' ')));
        const selectKind = select(['Валюты', 'Кнопки', 'Иконки и оформление'], 'Валюты', draw);
        const search = input('search', 'Название или путь'); search.setAttribute('aria-label', 'Поиск общего элемента');
        const list = el('div', undefined, 'registry-list');
        function draw() {
          list.replaceChildren(); const query = search.value.toLowerCase();
          const rows = selectKind.value === 'Валюты' ? shared.currencies : selectKind.value === 'Кнопки' ? shared.buttons : shared.textures;
          const matches = rows.filter(row => JSON.stringify(row).toLowerCase().includes(query));
          list.append(el('p', 'Найдено: ' + matches.length + ' · показано до 60. Уточните поиск.'));
          matches.slice(0, 60).forEach(row => {
            const card = el('div', undefined, 'resource-control');
            if (row.value !== undefined) append(card, image(row.texture_candidates[0]), el('strong', row.id + ' · ' + (row.symbol || 'неизвестно') + ' · ' + (row.name_en || '')), el('p', 'OwnerType: ' + row.data.OwnerType + ' · MaxValue: ' + row.data.MaxValue));
            else if (row.normal) append(card, image(row.normal), row.pressed ? image(row.pressed) : null, el('p', row.normal + ' / ' + (row.pressed || 'нажатие неизвестно') + ' · hover / disabled неизвестны'));
            else append(card, image(row.asset_path), el('p', row.asset_path));
            append(card, button('Источник и SHA256', () => info('Происхождение элемента', JSON.stringify(row, null, 2)))); list.append(card);
          });
        }
        search.oninput = draw; append(body, selectKind, search, list); draw();
      }, 'catalog-window');
    } catch (error) { info('Ошибка общих элементов', error.message); }
  }
  function openInspector(initial = '') {
    let query = '', kind = 'Все';
    const dialog = modal('Каталог проверки', body => {
      append(body, el('p', manifest.registry_count + ' записей каталога: ' + manifest.named_resource_count + ' ресурсных путей и ' + manifest.unresolved_root_count + ' классов без установленного пути; ' + manifest.variant_count + ' вариантов. Структура не подтверждает игровую логику.'), button('Версии и обновления', openVersions), button('Общие элементы', openSharedElements));
      const search = input('search', 'Имя окна или путь'); search.value = query; search.setAttribute('aria-label', 'Поиск ресурса');
      const list = el('div', undefined, 'registry-list'), count = el('p');
      const filter = select(['Все', 'Попапы', 'Компоненты и окна'], kind, v => { kind = v; fill(); });
      const fill = () => {
        list.replaceChildren(); const matches = registry.filter(x => (kind === 'Все' || x.popup === (kind === 'Попапы')) && (x.name + x.path).toLowerCase().includes(query.toLowerCase()));
        count.textContent = 'Найдено: ' + matches.length;
        let limit = 60;
        const more = () => {
          list.querySelector('.load-more')?.remove();
          matches.slice(limit - 60, limit).forEach(row => {
            const b = button('', () => openResource(row.id), 'registry-row'); append(b, el('strong', row.name), el('small', row.controls + ' контролов · ' + row.variants + ' вариантов · только структура'), el('small', row.path)); list.append(b);
          });
          if (matches.length > limit) list.append(button('Ещё 60', () => { limit += 60; more(); }, 'load-more'));
        }; more();
      };
      search.oninput = () => { query = search.value; fill(); }; append(body, search, filter, count, list); fill();
      if (initial) body.prepend(el('p', 'Раздел: ' + initial + '. Точное соответствие ищите по имени и пути ресурса.'));
    }, 'catalog-window'); return dialog;
  }
  async function openResource(id) {
    try {
      if (!registry.some(x => x.id === id)) throw Error('Неизвестный ресурс.');
      const row = await fetchJSON('windows/' + id + '.json'); let variant = 0;
      const draw = body => {
        const v = row.variants[variant];
        append(body, el('p', row.path), el('small', 'Историческая структура · активный вариант и поведение не подтверждены'),
          field('Вариант архива', select(row.variants.map((x, i) => [String(i), x.file]), String(variant), value => { variant = Number(value); renderers.get(dialog)(); })),
          button('Источник и геометрия', () => modal('Происхождение ресурса', b => b.append(el('pre', JSON.stringify({ ...v, controls: undefined }, null, 2))))));
        const area = el('section', undefined, 'resource-controls');
        for (const control of v.controls) {
          if (/Button|CheckBox/.test(control.type || '')) area.append(button(control.name, () => info(control.name, 'Действие и переход этого контрола ещё не подтверждены. Export: ' + control.export)));
          else if (/Slider/.test(control.type || '')) { const range = input('range'); range.setAttribute('aria-label', control.name); area.append(field(control.name, range)); }
          else if (/EditableText/.test(control.type || '')) area.append(field(control.name, input('text')));
          else area.append(el('div', control.name + ' · ' + control.type, 'resource-control'));
        }
        append(body, el('p', 'Просмотр контролов для исследования; это не восстановленный игровой экран.'), area);
      };
      const dialog = modal(row.name, draw, 'catalog-window');
    } catch (error) { info('Ошибка каталога', error.message); }
  }
  function openVersions() {
    modal('Версии и обновления', body => {
      append(body, el('p', 'Набор интерфейса: ' + manifest.id), el('p', 'Дата сборки: ' + manifest.built_at), el('p', 'Клиент SHA256: ' + (manifest.client.sha256 || 'недоступен')), el('p', 'Совместимость с клиентом: не подтверждена'), el('p', 'Каталог UI SHA256: ' + manifest.inputs['ui-catalog/index.json']), el('p', 'Демосохранение: схема ' + M.SCHEMA), el('p', storageIssue || 'Хранилище доступно.'), el('p', layouts.limits));
      body.append(button('Размещение окон: источники', () => modal('Размещение окон', b => b.append(el('pre', JSON.stringify(layouts, null, 2))), 'catalog-window')));
      body.append(button('Расположение кнопок: источники', () => modal('Расположение кнопок', b => b.append(el('pre', JSON.stringify(buttonLayouts, null, 2))), 'catalog-window')));
      append(body, el('p', 'Окно бота: ' + profile + ' · экономичный режим: ' + (economy ? 'включён' : 'выключен')), el('p', 'Для отдельного окна используйте ?bot=demo-02 … ?bot=demo-50. Тяжёлые данные каталога загружаются по запросу.'));
      manifest.limits.forEach(text => body.append(el('p', text)));
      body.append(button('Сбросить локальное демо', () => confirm('Сброс демо', 'Сохранённое демосостояние будет удалено. Реальные профили не затрагиваются.', resetDemo)));
    }, 'catalog-window');
  }
  function setAdapter(initial) {
    adapter = M.adapter(initial, (value, type) => {
      persist(value); document.documentElement.style.setProperty('--user-scale', value.settings.scale / 100);
      updateButtonGeometry();
      if (screen === 'game') refreshHud();
      // Changes redraw view-only dialogs. Preserve forms and controls being edited.
      for (const d of [...dialogs]) if (d.open && !d.contains(document.activeElement?.closest('input,select'))) renderers.get(d)?.();
    });
  }
  async function fetchJSON(url) { const r = await fetch(url); if (!r.ok) throw Error(url + ': HTTP ' + r.status); return r.json(); }
  addEventListener('message', event => {
    if (event.origin !== location.origin || event.source !== gameFrame()?.contentWindow || event.data?.source !== 'vampir-demo-map') return;
    const { type, payload } = event.data;
    if (type === 'ready') mapState();
    if (type === 'target') action('map-target', payload);
    if (type === 'position' && !state().position) action('map-position', payload);
  });
  addEventListener('visibilitychange', updateMapActivity);
  addEventListener('resize', updateButtonGeometry);
  addEventListener('visibilitychange', () => { if (!document.hidden) updateButtonGeometry(); });
  addEventListener('focus', updateMapActivity);
  addEventListener('blur', () => { if (document.activeElement?.tagName !== 'IFRAME') updateMapActivity(); });
  addEventListener('keydown', event => {
    if (screen !== 'game' || dialogs.length || /INPUT|TEXTAREA|SELECT/.test(event.target.tagName)) return;
    if (/^F[1-5]$/.test(event.key)) { event.preventDefault(); castSkill(Number(event.key.slice(1)) - 1, event.key); }
    if (/^[1-5]$/.test(event.key)) { const id = state().quick[Number(event.key) - 1]; if (id) itemCard(id, true); }
    if (event.key.toLowerCase() === 'i') openBag();
    if (event.key.toLowerCase() === 'm') openWorldMap();
    if (event.key === 'Enter') openSection('Чат');
  });
  Promise.all(['textures.json', 'manifest.json', 'registry-index.json', 'items.json', 'placement-evidence.json', 'button-evidence.json'].map(fetchJSON)).then(([t, m, r, items, placement, nativeControls]) => {
    textures = t; manifest = m; registry = r; sourceItems = items; layouts = placement; buttonLayouts = nativeControls;
    if (manifest.state_schema !== M.SCHEMA) throw Error('Версия модели не соответствует manifest этой сборки.');
    let loaded;
    try { loaded = M.load(localStorage, manifest.data_id || manifest.id, profile); }
    catch { loaded = { state: M.initial(), issue: 'Хранилище недоступно. Работа продолжается без сохранения.' }; }
    storageIssue = loaded.issue; storageBlocked = !!storageIssue; setAdapter(loaded.state);
    document.title = 'Vampir · ' + profile;
    for (const [key, name] of [['title-bg', 'BG_Title'], ['scene-bg', 'BG_PAC'], ['button-bg', 'BTN_ConfirmRed256'], ['button-press', 'BTN_ConfirmRed256_Press'], ['normal-bg', 'BTN_ConfirmBlack256'], ['normal-press', 'BTN_ConfirmBlack256_Press']]) if (textures[name]) document.documentElement.style.setProperty('--' + key, 'url("' + textures[name].url + '")');
    document.getElementById('inspector').onclick = () => openInspector(); render();
    geometryObserver.observe(app);
    if (storageIssue) info('Демосохранение требует проверки', storageIssue);
  }).catch(error => { app.replaceChildren(el('h1', 'Не удалось загрузить интерфейс'), el('p', error.message), button('Повторить', () => location.reload())); });
})();
