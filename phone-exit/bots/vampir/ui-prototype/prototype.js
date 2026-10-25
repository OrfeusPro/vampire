/* Interactive offline shell; unknown game behavior is exposed in the inspector. */
(() => {
  'use strict';
  const M = VampirDemo, app = document.getElementById('app'), windows = document.getElementById('windows');
  const requestedProfile = new URLSearchParams(location.search).get('bot') || 'demo-01';
  const profile = /^[a-zA-Z0-9_-]{1,48}$/.test(requestedProfile) ? requestedProfile : 'demo-01';
  const storageKey = M.profileKey(profile);
  let lockManager;
  try { lockManager = navigator.locks; } catch { /* Ownership stays unavailable. */ }
  const profileLease = VampirProfileLease.create(lockManager, 'vampir-ui-writer:' + storageKey);
  let resourcesReady = false, pageActive = true, activationRevision = 0, flowRevision = 0, releasing = Promise.resolve();
  const economy = new URLSearchParams(location.search).get('economy') !== 'off';
  let skillSources, textures, manifest, registry, sourceItems, layouts, buttonLayouts, components, componentDefinitions, adapter, storageIssue, storageBlocked = false;
  let screen = 'auth', draft = M.appearance(), undo = [], redo = [], createTab = 'Пресет', toastTimer, busy = false, hudStatusView;
  const dialogs = [], renderers = new Map(); let characterName = '';
  let entryDialog = null, nextEntryScenario = 'success';
  const entryFlow = VampirEntryFlow.create({ onChange: entryChanged });
  const state = () => adapter.state;
  const el = (tag, text, className) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; };
  const append = (parent, ...children) => { parent.append(...children.filter(Boolean)); return parent; };
  const fmt = n => Number(n).toLocaleString('ru-RU');
  function button(text, fn, className = '', disabled = false) { const b = el('button', text, className + ((!className || className === 'primary') ? ' original-button' : '')); b.type = 'button'; b.disabled = disabled; b.onclick = event => { b.focus({ preventScroll: true }); fn?.(event); }; return b; }
  let geometryFrame;
  function updateButtonGeometry() {
    cancelAnimationFrame(geometryFrame);
    geometryFrame = requestAnimationFrame(() => {
      if (!buttonLayouts) return;
      if (profileLease.owned && adapter) document.documentElement.style.setProperty('--ui-component-unit', VampirGeometry.referenceScale({ width: document.documentElement.clientWidth, height: document.documentElement.clientHeight }, { reference_width: 2400, reference_height: 1350 }, state().settings.scale / 100) + 'px');
      for (const node of document.querySelectorAll('[data-native-button]')) {
        const binding = buttonLayouts.bindings[node.dataset.nativeButton], parent = node.tagName === 'DIALOG' ? app : node.closest('dialog') || app;
        if (!binding || !parent.clientWidth || !parent.clientHeight) continue;
        const scale = VampirGeometry.referenceScale({ width: parent.clientWidth, height: parent.clientHeight }, binding, state().settings.scale / 100);
        if (node.dataset.nativeButton.startsWith('collection-')) parent.style.setProperty('--collection-unit', scale + 'px');
        const desired = {}, measuredAssumptions = []; let measurementIssue;
        for (const [index, tree] of Object.entries(binding.desired_trees || {})) {
          const measurement = VampirGeometry.desiredTree(tree);
          if (measurement.unknown) { measurementIssue = measurement.unknown; break; }
          desired[index] = { width: measurement.width, height: measurement.height }; measuredAssumptions.push(...measurement.assumptions);
        }
        const result = measurementIssue ? { unknown: measurementIssue } : VampirGeometry.chain(binding, VampirGeometry.rect(0, 0, parent.clientWidth / scale, parent.clientHeight / scale), desired);
        if (!result.unknown) result.assumptions.push(...measuredAssumptions);
        if (!result.unknown && binding.root_frame_assumption) result.assumptions.push(binding.root_frame_assumption);
        node.dataset.geometryState = result.unknown ? 'unresolved' : result.assumptions.length ? 'allocated-frame-assumption' : 'canvas-calculation';
        if (result.unknown) { node.dataset.geometryUnknown = result.unknown; continue; }
        delete node.dataset.geometryUnknown; node.dataset.geometryAssumptions = result.assumptions.join('\n');
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
  function action(type, payload) { if (!profileLease.owned) { showOwnershipGate({ status: 'released' }); return false; } try { adapter.dispatch(type, payload); return true; } catch (error) { info('Действие недоступно', error.message); return false; } }
  function persist(value) {
    if (storageBlocked || !profileLease.owned) return;
    try { localStorage.setItem(storageKey, JSON.stringify({ dataset: manifest.data_id || manifest.id, state: M.serialize(value) })); }
    catch { storageBlocked = true; storageIssue = 'Не удалось сохранить демо. Текущее состояние доступно до закрытия страницы.'; notify(storageIssue); }
  }
  function currentCharacter() { return state().characters.find(c => c.id === state().selected); }
  function className(id) { return M.CLASSES.find(x => x[0] === id)?.[1] || id; }
  function portrait(a = M.appearance(), full = false) { return image(full ? 'IMG_Class_' + a.classId + '_' + a.gender : 'IMG_Customize_Preset_' + a.gender + '_' + String(a.preset).padStart(2, '0'), full ? 'character-image' : 'portrait'); }
  function currency(key, value) { return components.currency(key, value); }
  function currencies(value = state()) { return components.wallets(value); }

  function field(label, input) {
    const direct = /^(INPUT|SELECT|TEXTAREA)$/.test(input.tagName), n = el(direct ? 'label' : 'div', undefined, 'field'), text = el('span', label);
    if (!direct) { text.id = 'label-' + crypto.randomUUID(); input.setAttribute('role', 'group'); input.setAttribute('aria-labelledby', text.id); }
    append(n, text, input); return n;
  }
  function input(type, placeholder = '') { const n = document.createElement('input'); n.type = type; n.placeholder = placeholder; return n; }
  function select(values, value, fn) { const n = document.createElement('select'); values.forEach(x => { const option = el('option', typeof x === 'string' ? x : x[1]); option.value = typeof x === 'string' ? x : x[0]; n.append(option); }); n.value = value; n.onchange = () => fn(n.value); return n; }
  function tabs(names, current, fn) { const n = el('nav', undefined, 'tabs'); n.setAttribute('aria-label', 'Вкладки'); names.forEach(name => { const b = button(name, () => fn(name), name === current ? 'active' : ''); b.setAttribute('aria-pressed', String(name === current)); n.append(b); }); return n; }
  function closeDialog(dialog) { if (!dialog?.open) return; if (dialog === entryDialog && entryFlow.state.phase === 'loading') entryFlow.cancel(); if (dialog.open) dialog.close(); }
  function focusIdentity(node) {
    return node && node !== document.body ? { label: node.getAttribute('aria-label'), title: node.getAttribute('title'), text: node.textContent, tag: node.tagName } : null;
  }
  function restoreFocus(identity, scope) {
    if (!identity || !scope) return;
    const candidates = [...scope.querySelectorAll('button,input,select,a')];
    const match = candidates.find(n => n.tagName === identity.tag && !n.disabled &&
      (identity.label ? n.getAttribute('aria-label') === identity.label : identity.title ? n.getAttribute('title') === identity.title : n.textContent === identity.text));
    if (match) match.focus({ preventScroll: true });
    else if (scope.tagName === 'DIALOG') scope.querySelector('[data-window-close],button.close')?.focus({ preventScroll: true });
  }
  function modal(title, render, className = '') {
    const invoker = focusIdentity(document.activeElement);
    const dialog = el('dialog', undefined, className), heading = el('h2', title), body = el('div', undefined, 'dialog-body');
    const placement = layouts.profiles[className];
    if (placement) {
      const [x, y, w, h] = placement.rect;
      dialog.classList.add('placed-window'); dialog.dataset.layoutResource = placement.resource;
      Object.assign(dialog.style, { left: x * 100 + 'vw', top: y * 100 + 'dvh', width: w * 100 + 'vw', height: h * 100 + 'dvh', margin: '0', maxWidth: '100vw', maxHeight: '100dvh' });
      if (placement.native_frame) nativeButton(dialog, placement.native_frame);
    }
    heading.id = 'window-' + crypto.randomUUID(); dialog.setAttribute('aria-labelledby', heading.id);
    let sharedHeader;
    const header = placement?.shared_header ? (sharedHeader = components.titleBar({ heading, state: state(), character: currentCharacter(), onMenu: openMenu, onClose: () => closeDialog(dialog), onCharacter: () => openSection('Персонаж') })).node : el('header', undefined, 'window-heading');
    if (!sharedHeader) {
      append(header, heading, button('', () => closeDialog(dialog), 'close'));
      header.lastChild.setAttribute('aria-label', 'Закрыть ' + title); header.lastChild.dataset.windowClose = 'true';
      if (className === 'item-card') nativeButton(header.lastChild, 'item-close');
    }
    append(dialog, header, body); windows.append(dialog); dialogs.push(dialog);
    const redraw = () => { const focused = dialog.contains(document.activeElement) ? focusIdentity(document.activeElement) : null; sharedHeader?.update(state(), currentCharacter()); body.replaceChildren(); render(body, dialog); restoreFocus(focused, dialog); updateButtonGeometry(); };
    renderers.set(dialog, redraw);
    dialog.addEventListener('close', () => { sharedHeader?.dispose(); geometryObserver.unobserve(dialog); renderers.delete(dialog); const at = dialogs.indexOf(dialog); if (at >= 0) dialogs.splice(at, 1); dialog.remove(); restoreFocus(invoker, dialogs.filter(d => d.open).at(-1) || app); });
    redraw(); dialog.showModal(); geometryObserver.observe(dialog); updateButtonGeometry(); return dialog;
  }
  function info(title, message) { return modal(title, body => append(body, el('p', message), button('Понятно', () => closeDialog(dialogs.at(-1)), 'primary'))); }
  function confirm(title, message, fn, className = '') {
    return modal(title, (body, dialog) => {
      const actions = el('div', undefined, 'actions');
      append(actions, button('Отмена', () => closeDialog(dialog)), button('Подтвердить', () => { closeDialog(dialog); fn(); }, 'primary'));
      append(body, el('p', message), actions);
    }, className);
  }
  function transition(next) { if (!profileLease.owned) return; entryFlow.cancel(); flowRevision++; dialogs.slice().reverse().forEach(closeDialog); clearTimeout(toastTimer); document.getElementById('toast').hidden = true; clearTimeout(skillTimer); screen = next; render(); }
  function pageTitle(text, back) { const n = el('header', undefined, 'page-title'); append(n, button('❮', back, 'back'), el('h1', text)); return n; }
  function footerNote() { return el('small', 'Демонстрационный режим · игровые команды не отправляются', 'demo-note'); }
  function render() {
    hudStatusView?.dispose(); hudStatusView = null;
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
      password.value = ''; const revision = flowRevision; setTimeout(() => { if (revision !== flowRevision || !profileLease.owned) return; busy = false; transition('servers'); }, 350);
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
    const enter = button('Пожалуйста, коснитесь экрана.', startEntry, 'enter-game');
    enter.title = 'Войти на сервер';
    append(center, el('div', 'VAMPIR', 'wordmark'), enter, el('p', '◎ ' + state().region), button(state().server + '  ⟳', () => transition('servers'), 'server-choice'));
    append(app, tools, center);
  }
  function setEntryBusy(value) {
    busy = value;
    const enter = app.querySelector('.enter-game');
    if (enter) { enter.disabled = value; enter.textContent = value ? 'Вход на сервер…' : 'Пожалуйста, коснитесь экрана.'; }
  }
  function bindEntryDialog(dialog) {
    entryDialog = dialog;
    dialog.addEventListener('cancel', event => {
      if (entryDialog === dialog && entryFlow.state.phase === 'loading') { event.preventDefault(); entryFlow.cancel(); }
    });
    dialog.addEventListener('close', () => {
      if (entryDialog === dialog) { entryDialog = null; entryFlow.cancel(); setEntryBusy(false); }
    });
  }
  function startEntry() {
    if (!profileLease.owned) { showOwnershipGate({ status: 'released' }); return; }
    if (entryFlow.state.phase === 'loading') return;
    const previous = entryDialog; entryDialog = null; if (previous) closeDialog(previous);
    const context = { profile, server: state().server, region: state().region }, scenario = nextEntryScenario;
    nextEntryScenario = 'success';
    bindEntryDialog(modal('Вход на сервер', body => {
      const value = entryFlow.state, current = value.phase === 'loading' ? value.step : 0, total = VampirEntryFlow.STEPS.length;
      append(body, el('p', context.server + ' · ' + context.region));
      const spinner = el('div', undefined, 'entry-spinner'); spinner.setAttribute('aria-hidden', 'true');
      const message = el('p', VampirEntryFlow.STEPS[Math.min(current, total - 1)], 'entry-status'); message.setAttribute('role', 'status'); message.dataset.entryMessage = 'true';
      const progress = el('progress'); progress.max = total; progress.value = current; progress.setAttribute('aria-label', 'Этапы демовхода'); progress.dataset.entryProgress = 'true';
      append(body, spinner, message, progress, el('small', 'Локальные этапы демонстрации; сетевых запросов нет.'), button('Отмена входа', () => entryFlow.cancel()));
    }, 'entry-loading-window'));
    setEntryBusy(true); entryFlow.start(context, scenario);
  }
  function updateEntryPresentation(value) {
    if (!entryDialog?.open || document.hidden) return;
    const message = entryDialog.querySelector('[data-entry-message]'), progress = entryDialog.querySelector('[data-entry-progress]');
    if (message) message.textContent = VampirEntryFlow.STEPS[Math.min(value.step, VampirEntryFlow.STEPS.length - 1)];
    if (progress) progress.value = value.step;
  }
  function entryChanged(value) {
    if (value.phase === 'loading') { updateEntryPresentation(value); return; }
    setEntryBusy(false);
    const previous = entryDialog; entryDialog = null;
    if (previous) closeDialog(previous);
    if (value.phase === 'ready') {
      if (profileLease.owned && screen === 'title' && value.context.profile === profile && value.context.server === state().server && value.context.region === state().region) transition('characters');
    } else if (value.phase === 'failed' && profileLease.owned && screen === 'title') {
      app.querySelector('.enter-game')?.focus({ preventScroll: true });
      bindEntryDialog(modal('Не удалось войти', (body, dialog) => {
        const message = el('p', value.error.message, 'form-error'); message.setAttribute('role', 'alert');
        append(body, el('p', value.context.server + ' · попытка ' + value.attempt), message,
          el('small', 'Тестовый код: ' + value.error.code + '. Игровой сервер не опрашивался.'));
        const actions = el('div', undefined, 'actions');
        append(actions, button('Повторить вход', startEntry, 'primary'), button('Выбрать другой сервер', () => transition('servers')), button('Закрыть', () => closeDialog(dialog)));
        body.append(actions);
      }, 'entry-error-window'));
    }
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
    const holder = document.getElementById('map-holder'); if (!holder || !profileLease.owned) return;
    const active = !document.hidden && (!economy || document.hasFocus());
    if (!active) {
      if (gameFrame() || !holder.firstChild) holder.replaceChildren(button('Карта приостановлена · активируйте окно', () => { window.focus(); mountMap(); }, 'map-paused'));
    } else if (!gameFrame()) mountMap();
  }
  function mountMap() {
    const holder = document.getElementById('map-holder'); if (!holder || !profileLease.owned || gameFrame()) return;
    const frame = el('iframe'); frame.id = 'world'; frame.title = '2D-карта игрового мира'; frame.src = 'map.html'; frame.onload = mapState; holder.replaceChildren(frame);
  }
  function refreshHud() {
    const hud = document.getElementById('hud'); if (!hud) return; hud.replaceChildren();
    hudStatusView?.dispose(); hudStatusView = null;
    const s = state(), c = currentCharacter(); if (!c) { transition('characters'); return; }
    hudStatusView = components.playerStatus({ state: s, character: c, onOpen: () => openSection('Персонаж') });
    const health = hudStatusView.node; health.classList.add('health');
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
    s.skills.slots.forEach((id, i) => {
      const key = 'F' + (i + 1), skill = M.SKILLS[id];
      const b = icon(skillSources[id]?.icon || 'IMG_Flat_Skill', skill ? skill.name + ' · ' + key : 'Пустой слот ' + key, () => skill ? castSkill(i, key) : chooseSkillSlot(i), key);
      if (skill) { const remaining = el('small', '', 'skill-cooldown'); remaining.dataset.skillCooldown = id; append(b, remaining); }
      skills.append(b);
    });
    const attack = el('div', undefined, 'attack-controls');
    append(attack, button('◎ Цель', () => notify('Выбрана демонстрационная цель.')), button('ЗАДАНИЕ', openQuests), button('⚔', () => castSkill(5, 'F'), 'attack'));
    const bottom = el('div', undefined, 'level'); append(bottom, el('strong', String(c.level)), el('span', c.name + '\nОпыт ' + fmt(s.experience)), button('Выйти', () => transition('characters')));
    const route = el('div', undefined, 'route-controls');
    if (s.target) append(route, el('p', 'Выбрана точка карты'), button('Идти пешком · демо', () => { if (action('map-arrive')) notify('Маркер перемещён в демо. Проходимость маршрута не проверялась.'); }));
    append(hud, health, currencies(), top, mapTools, quests, left, quick, skills, attack, bottom, route); mapState(); updateSkillCooldowns();
  }
  let skillTimer;
  function updateSkillCooldowns() {
    clearTimeout(skillTimer);
    if (document.hidden || screen !== 'game') return;
    const ready = state().skills.readyAt, now = Date.now(); let pending = false;
    document.querySelectorAll('[data-skill-cooldown]').forEach(n => {
      const seconds = Math.max(0, Math.ceil(((ready[n.dataset.skillCooldown] || 0) - now) / 1000));
      n.textContent = seconds ? seconds + ' с.' : ''; pending ||= seconds > 0;
    });
    if (pending) skillTimer = setTimeout(updateSkillCooldowns, 1000);
  }
  function castSkill(i, key) {
    if (i === 5) { notify('Базовая атака · локальная демонстрация'); return; }
    const id = state().skills.slots[i];
    if (!id) { chooseSkillSlot(i); return; }
    if (action('skill-cast', { id, now: Date.now() })) notify(M.SKILLS[id].name + ' · демо, клавиша ' + key);
  }
  function chooseSkillSlot(slot) {
    modal('Назначить навык · F' + (slot + 1), (body, d) => {
      for (const id of Object.keys(state().skills.levels)) body.append(button(M.SKILLS[id].name, () => { if (action('skill-slot', { slot, id })) closeDialog(d); }));
      body.append(button('Очистить слот', () => { if (action('skill-slot', { slot, id: null })) closeDialog(d); }));
    });
  }
  function skillArt(id) { return image(skillSources[id]?.icon || 'IMG_Flat_Skill', 'skill-art'); }
  function skillDetails(body, id) {
    const skill = M.SKILLS[id], s = state(), level = s.skills.levels[id] || 0;
    append(body, skillArt(id), el('h3', skill.name), el('p', level ? 'Изучен · уровень ' + level + '/' + skill.maxLevel : 'Не изучен'),
      el('p', 'Демо: MP ' + skill.mp + ' · перезарядка ' + skill.cooldown / 1000 + ' с.'),
      el('small', 'Название переведено для прототипа. Обучение, улучшение и применение используют локальные правила; урон и серверные эффекты не рассчитываются.'));
    if (!level) body.append(button('Изучить · ' + skill.learnCost + ' золота', () => confirm('Изучение навыка', 'Потратить ' + skill.learnCost + ' золота в демо?', () => action('skill-learn', { id })), 'primary', s.gold < skill.learnCost));
    else {
      body.append(button(level >= skill.maxLevel ? 'Максимальный уровень' : 'Повысить · ' + level * 100 + ' золота', () => action('skill-upgrade', { id }), 'primary', level >= skill.maxLevel || s.gold < level * 100));
      body.append(button('Применить · демо', () => { if (action('skill-cast', { id, now: Date.now() })) notify(skill.name + ' · локальное применение'); }));
      const auto = input('checkbox'); auto.checked = s.skills.auto.includes(id); auto.onchange = () => action('skill-auto', { id });
      append(body, field('Автоприменение · настройка демо', auto), el('small', 'Настройка сохраняется; автоматический бой не запускается.'));
      const slots = el('div', undefined, 'skill-assign');
      for (let i = 0; i < 5; i++) slots.append(button('F' + (i + 1), () => action('skill-slot', { slot: i, id }), s.skills.slots[i] === id ? 'selected' : ''));
      append(body, el('p', 'Назначить в слот · занятые навыки меняются местами'), slots);
    }
    body.append(button('Исходные данные навыка', async () => {
      try { const source = await fetchJSON('skills-evidence.json'); info('Источник навыка ' + id, JSON.stringify(source[id], null, 2)); }
      catch (error) { info('Ошибка источника', error.message); }
    }));
  }
  function openSkillInfo(id) { modal('Навык: ' + M.SKILLS[id].name, body => skillDetails(body, id), 'skill-info-window'); }
  function openSkills() {
    if (!currentCharacter()) return info('Навыки', 'Сначала выберите персонажа.');
    let selected = M.skillsForClass(currentCharacter().appearance.classId)[0].id, filter = 'Все', query = '';
    modal('Навыки', (body, d) => {
      append(body, el('p', 'Класс: ' + className(currentCharacter().appearance.classId) + ' · локальная демонстрация'), currencies());
      const layout = el('div', undefined, 'skills-layout'), list = el('div', undefined, 'skills-list'), detail = el('section', undefined, 'skill-details');
      const search = input('search', 'Название навыка'); search.value = query; search.setAttribute('aria-label', 'Поиск навыка');
      const fill = () => {
        list.replaceChildren();
        const rows = M.skillsForClass(currentCharacter().appearance.classId).filter(skill => skill.name.toLowerCase().includes(query.toLowerCase()) && (filter === 'Все' || Boolean(state().skills.levels[skill.id]) === (filter === 'Изученные')));
        if (!rows.length) list.append(el('p', 'Навыки не найдены.'));
        if (!rows.some(skill => skill.id === selected)) selected = rows[0]?.id || null;
        rows.forEach(skill => {
          const level = state().skills.levels[skill.id] || 0;
          const card = button('', () => { selected = skill.id; renderers.get(d)(); }, 'skill-card' + (selected === skill.id ? ' selected' : ''));
          card.setAttribute('aria-pressed', String(selected === skill.id));
          append(card, skillArt(skill.id), el('strong', skill.name), el('small', level ? 'Уровень ' + level : 'Не изучен')); list.append(card);
        });
        detail.replaceChildren();
        if (selected) { skillDetails(detail, selected); detail.append(button('Открыть карточку навыка', () => openSkillInfo(selected))); }
        else detail.append(el('p', 'Выберите навык из списка.'));
      };
      search.oninput = () => { query = search.value; fill(); };
      append(body, tabs(['Все', 'Изученные', 'Неизученные'], filter, value => { filter = value; renderers.get(d)(); }), search);
      fill();
      append(layout, list, detail); body.append(layout);
      const slots = el('div', undefined, 'skill-quick-settings');
      state().skills.slots.forEach((id, i) => slots.append(button('F' + (i + 1) + ': ' + (M.SKILLS[id]?.name || 'пусто'), () => chooseSkillSlot(i))));
      append(body, el('h3', 'Панель способностей'), slots, button('Геометрия и контролы источника', () => openInspector('WBP_SkillSettingPopup')));
      catalogLink(body, 'Полный справочник навыков', '/maps/atlas/skills.html');
    }, 'skills-window');
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
      body.append(tabs(['Все', 'Снаряжение', 'Расходники', 'Материалы', 'Коллекционные'], category, value => { category = value; renderers.get(dialog)(); }));
      const search = input('search', 'Поиск предмета'); search.value = query;
      search.oninput = () => { query = search.value; fill(); }; body.append(search);
      const grid = el('div', undefined, 'bag-grid');
      const fill = () => {
        grid.replaceChildren();
        for (const [id, p] of Object.entries(M.PRODUCTS)) if (state().inventory[id] && p.name.toLowerCase().includes(query.toLowerCase()) && (category === 'Все' || p.kind === ({ 'Снаряжение': 'equipment', 'Расходники': 'consumable', 'Материалы': 'material' }[category]))) grid.append(itemSlot(id));
        if (category === 'Все' || category === 'Коллекционные') for (const [key, item] of Object.entries(state().collections.items)) if (item.count > 0 && (item.name + ' ' + item.itemId).toLowerCase().includes(query.toLowerCase())) {
          const name = item.name + ' +' + item.enchant, slot = button('', () => openCollectionBagItem(key), 'item-slot'); slot.title = name; slot.setAttribute('aria-label', name);
          append(slot, collectionItemImage(item), el('small', String(item.count))); grid.append(slot);
        }
      };
      const occupied = Object.values(state().inventory).filter(n => n > 0).length + Object.values(state().collections.items).filter(item => item.count > 0).length;
      fill(); append(body, grid, el('p', 'Занято в демо: ' + occupied + ' · ёмкость 116 не ограничивает учебную выдачу'), button('Экипировка', () => openSection('Персонаж')),
        button('Массовый разбор', () => info('Массовый разбор', 'Правила разбора и наград пока не восстановлены. Предметы сохранены.')));
    };
    const dialog = modal('Сумка', draw, 'inventory-window');
  }
  function openShop() {
    let category = 'Алмаз', section = 'Обмен';
    const draw = body => {
      append(body, tabs(['Товар', 'Особый призыв', 'Обмен', 'Склад'], section, value => { section = value; renderers.get(dialog)(); }));
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
    if (!profileLease.owned) { showOwnershipGate({ status: 'released' }); return; }
    try { localStorage.removeItem(storageKey); storageBlocked = false; storageIssue = null; }
    catch { storageBlocked = true; storageIssue = 'Хранилище недоступно. Сброшено только состояние текущей страницы.'; }
    setAdapter(M.initial()); persist(state()); transition('auth');
  }
  function openMenu() {
    const existing = dialogs.find(dialog => dialog.open && dialog.classList.contains('menu-window'));
    if (existing && dialogs.filter(dialog => dialog.open).at(-1) === existing) { existing.querySelector('[data-window-close]')?.focus(); return existing; }
    if (existing) closeDialog(existing);
    modal('Меню', body => {
      body.append(components.mainMenu({ onSelect: entry => {
        if (entry.control === 'ButtonCharacterSelect') transition('characters');
        else openSection(entry.label);
      } }));
    }, 'menu-window');
  }
  function catalogLink(body, title, url) {
    const link = el('a', title); link.href = url; link.target = '_blank'; link.rel = 'noopener'; body.append(link);
  }
  function openCollections() {
    const catalog = VampirCollectionCatalog.create();
    let meta, issue, query = '', tab = '', rarity = '', page = 0, favorites = false, listRevision = 0;
    const scope = { server: state().server, character: state().selected };
    const refresh = () => { if (dialog.open) renderers.get(dialog)?.(); };
    const load = async () => {
      issue = null;
      try { meta = await catalog.index(); } catch (error) { if (error.name !== 'AbortError') issue = error.message; }
      refresh();
    };
    const dialog = modal('Коллекции', body => {
      const current = state();
      if (!meta) {
        append(body, el('p', issue || 'Загрузка каталога…'), issue && button('Повторить загрузку', load)); return;
      }
      const nav = el('nav', undefined, 'tabs collection-main-tabs'); nav.setAttribute('aria-label', 'Разделы коллекций'); nativeButton(nav, 'collection-tabs-frame');
      for (const group of meta.tabs.slice(0, 4)) { const b = button(group.name, () => { tab = group.id; favorites = false; page = 0; refresh(); }, !favorites && tab === group.id ? 'active' : ''); b.setAttribute('aria-pressed', String(!favorites && tab === group.id)); nav.append(b); }
      nav.append(button('Избранное', () => { favorites = !favorites; page = 0; refresh(); }, favorites ? 'active' : '')); body.append(nav);
      const filters = el('div', undefined, 'collection-filters'), search = input('search', 'Название или ID коллекции'); search.value = query;
      const grades = [...new Map(meta.entries.map(row => [row.rarity_id, row.rarity])).entries()];
      search.oninput = () => { query = search.value; page = 0; fill(); };
      const searchFrame = nativeButton(append(el('div', undefined, 'collection-search-field'), search, image('/Game/RED/UI/Resource/Texture/Image/IMG_Flat_Search', 'collection-search-symbol')), 'collection-search-frame');
      const filterButton = nativeButton(icon('/Game/RED/UI/Resource/Texture/Image/IMG_Flat_Filter', 'Фильтры', () => {
        let chosenTab = tab, chosenGrade = rarity;
        modal('Фильтры коллекций', (n, d) => append(n,
          field('Исходный раздел', select([['', 'Все разделы'], ...meta.tabs.map(row => [row.id, row.name])], chosenTab, value => chosenTab = value)),
          field('Редкость', select([['', 'Любая редкость'], ...grades], chosenGrade, value => chosenGrade = value)),
          el('small', 'Названия Krvna / Poenari / Kicel / Bezdan сохранены из таблиц. Соответствие русским вкладкам кадра ещё не установлено.'),
          button('Применить фильтры', () => { tab = chosenTab; rarity = chosenGrade; favorites = false; page = 0; closeDialog(d); refresh(); }, 'primary')));
      }), 'collection-filter-button');
      const resetButton = nativeButton(icon('/Game/RED/UI/Resource/Texture/Image/IMG_Flat_Refresh', 'Сбросить фильтры', () => { query = ''; tab = ''; rarity = ''; favorites = false; page = 0; refresh(); }), 'collection-refresh-button');
      filterButton.setAttribute('aria-pressed', String(!!tab || !!rarity));
      append(filters, searchFrame, filterButton, resetButton); body.append(filters);
      const status = el('p'), list = nativeButton(el('div', undefined, 'collection-list'), 'collection-list-frame'), pager = el('div', undefined, 'actions collection-footer');
      status.setAttribute('role', 'status');
      const fill = () => {
        const revision = ++listRevision, bank = state().collections;
        const rows = VampirCollectionCatalog.select(meta, { query, tab, rarity }).filter(row => !favorites || bank.entries[row.id]?.favorite), result = VampirCollectionCatalog.page(rows, page); page = result.number;
        status.textContent = 'Найдено: ' + rows.length + ' / ' + meta.entries.length + ' · страница ' + (page + 1) + ' / ' + result.count;
        list.replaceChildren();
        for (const row of result.rows) {
          const card = el('article', undefined, 'collection-row'), progress = bank.entries[row.id], flags = el('div', undefined, 'collection-flags'), slots = el('div', undefined, 'collection-row-items');
          let bundle;
          const favorite = button('', () => action('collection-favorite', { bundle, scope }), 'collection-flag', true), lock = button('', () => action('collection-lock', { bundle, scope }), 'collection-flag', true);
          favorite.append(image(progress?.favorite ? 'IMG_Flat_Favorite_On' : 'IMG_Flat_Favorite_Off')); lock.append(image(progress?.locked ? 'IMG_Flat_Lock' : 'IMG_Flat_UnLock'));
          favorite.setAttribute('aria-label', 'Избранное: ' + row.name); favorite.setAttribute('aria-pressed', String(!!progress?.favorite)); lock.setAttribute('aria-label', 'Блокировка регистрации: ' + row.name); lock.setAttribute('aria-pressed', String(!!progress?.locked));
          append(flags, favorite, lock);
          const title = button('', () => openCollectionDetail(catalog, row.id, meta), 'collection-row-title'), bonusText = el('span', 'Загрузка бонусов…');
          append(title, el('strong', row.name + ' (' + (progress?.registered.length || 0) + '/' + row.requirements + ')'), bonusText, el('small', 'ID ' + row.id + ' · ' + row.rarity)); append(card, flags, title, slots); list.append(card);
          catalog.entry(row.id).then(data => {
            if (!dialog.open || revision !== listRevision || !card.isConnected) return;
            bundle = M.COLLECTIONS.normalize(data, meta.source.sha256); favorite.disabled = false; lock.disabled = false;
            bonusText.textContent = data.entry.bonuses.map(b => (b.name?.Name || b.row.Type) + ' ' + b.row.Min + (b.row.Max === b.row.Min ? '' : '–' + b.row.Max)).join(' · ');
            for (const requirement of data.entry.requirements) {
              const source = bundle.items[M.COLLECTIONS.key(requirement.item_id, Number(requirement.row.EnchantLevel))], slot = button('', () => openCollectionDetail(catalog, row.id, meta), 'item-slot collection-row-slot');
              slot.setAttribute('aria-label', source.name + ' · коллекция ' + row.id);
              append(slot, collectionItemImage(source), el('small', '+' + requirement.row.EnchantLevel));
              if (progress?.registered.includes(requirement.row.Id)) slot.append(image('IMG_Flat_Check', 'collection-registered-mark'));
              slots.append(slot);
            }
          }).catch(error => { if (revision === listRevision && card.isConnected && error.name !== 'AbortError') bonusText.textContent = 'Не удалось загрузить состав. Откройте карточку для повтора.'; });
        }
        if (!rows.length) list.append(el('p', 'Совпадений нет. Измените фильтры.'));
        pager.replaceChildren(button('Предыдущая страница', () => { page--; fill(); }, '', page === 0), button('Следующая страница', () => { page++; fill(); }, '', page + 1 === result.count));
      };
      const sidebar = nativeButton(el('aside', undefined, 'collection-effects'), 'collection-effects-frame'), completed = Object.values(current.collections.entries).filter(M.COLLECTIONS.complete).length, percent = completed / meta.entries.length * 100, progressBar = document.createElement('progress'); progressBar.max = meta.entries.length; progressBar.value = completed;
      append(sidebar, el('h3', 'Прогресс коллекции · демо'), el('p', percent.toFixed(2) + '% · ' + completed + '/' + meta.entries.length), progressBar, el('h3', 'Эффект коллекции'));
      const totals = M.COLLECTIONS.bonuses(current.collections);
      if (!totals.length) sidebar.append(el('p', 'Завершённых коллекций пока нет.'));
      for (const bonus of totals) sidebar.append(el('p', bonus.name + ' ' + bonus.min + (bonus.min === bonus.max ? '' : '–' + bonus.max)));
      append(sidebar, button('Все эффекты', () => openSection('Персонаж')), el('small', 'Исторические данные; серверные условия не проверены.'), button('Учебная коллекция', () => modal('Наследие ночи · демо', n => append(n, el('p', 'Отдельный учебный сценарий с книгой; не игровая коллекция.'), button('Добавить книгу · демо', () => confirm('Учебная коллекция', 'Списать одну книгу в демо?', () => action('collection')), 'primary', state().collection)))));
      const footer = el('div', undefined, 'collection-status-footer'); append(footer, status, pager, button('Сумка', openBag)); append(body, list, sidebar, footer);
      fill();
    }, 'collections-window');
    dialog.addEventListener('close', () => catalog.close(), { once: true });
    load(); return dialog;
  }
  function collectionItemImage(item) {
    if (!item.icon) return el('span', 'Иконка не определена', 'missing-icon');
    const img = document.createElement('img'); img.src = item.icon.url; img.alt = item.name; img.loading = 'lazy'; img.width = 72; img.height = 72; img.className = 'product-icon'; return img;
  }
  function openCollectionBagItem(key) {
    modal('Коллекционный предмет · демо', body => {
      const item = state().collections.items[key];
      if (!item) { body.append(el('p', 'Предмет отсутствует у выбранного персонажа.')); return; }
      append(body, collectionItemImage(item), el('h3', item.name), el('p', 'ID ' + item.itemId + ' · усиление ' + item.enchant + ' · в сумке: ' + item.count),
        el('p', 'Предмет выдан для локальной проверки коллекций. Экипировка, продажа и применение этого типа предмета ещё не восстановлены.'),
        button('Открыть коллекции', openCollections), el('pre', JSON.stringify({ catalog_sha256: state().collections.source, icon: item.icon }, null, 2)));
    }, 'collection-source-window');
  }
  function openCollectionDetail(catalog, id, meta) {
    let data, issue, bundle, bundleIssue;
    const scope = { server: state().server, character: state().selected };
    const load = async () => {
      issue = null;
      try {
        data = await catalog.entry(id);
        try { bundle = M.COLLECTIONS.normalize(data, meta.source.sha256); } catch (error) { bundleIssue = error.message; }
      } catch (error) { if (error.name !== 'AbortError') issue = error.message; }
      if (dialog.open) renderers.get(dialog)?.();
    };
    const dialog = modal('Состав коллекции · ' + id, body => {
      if (!data) { append(body, el('p', issue || 'Загрузка состава…'), issue && button('Повторить загрузку', load)); return; }
      const entry = data.entry;
      const progress = state().collections.entries[id], registered = progress?.registered || [];
      const status = el('p', 'Демо: зарегистрировано ' + registered.length + '/' + entry.requirements.length + (progress && M.COLLECTIONS.complete(progress) ? ' · коллекция завершена' : '')); status.setAttribute('role', 'status');
      append(body, el('h3', entry.name), el('p', 'Локальная регистрация по историческим требованиям. Усиление должно точно совпасть. Серверная доступность и область действия бонусов не подтверждены.', 'catalog-notice'), status);
      if (bundleIssue) body.append(el('p', 'Регистрация недоступна: ' + bundleIssue));
      body.append(button('Выдать недостающие предметы · демо', () => confirm('Тестовый набор коллекции', 'Добавить недостающие предметы в общую демосумку? Один набор на коллекцию; игровые команды не отправляются.', () => action('collection-supply', { bundle, scope })), '', !bundle || progress?.supplied || (progress && M.COLLECTIONS.complete(progress))));
      const grid = el('div', undefined, 'collection-requirements');
      for (const requirement of entry.requirements) {
        const item = data.items[requirement.item_id], row = requirement.row, card = el('div', undefined, 'collection-requirement');
        const variants = item.icon?.images || [];
        if (variants.length === 1) { const img = document.createElement('img'); img.src = variants[0].url; img.alt = item.name; img.loading = 'lazy'; img.width = 72; img.height = 72; card.append(img); }
        else card.append(el('span', variants.length ? 'Неоднозначная иконка' : 'Иконка не извлечена'));
        append(card, el('strong', item.name), el('small', 'ID ' + item.id + ' · ×' + row.Count + ' · усиление ' + row.EnchantLevel),
          button('Источник предмета ' + item.id, () => modal('Предмет коллекции · ' + item.id, n => {
            append(n, el('h3', item.name), el('p', 'Исходный тип требования: ' + (requirement.collect_type?.name || row.CollectType)), el('pre', JSON.stringify({ item: item.provenance, requirement: row, icon: item.icon }, null, 2)));
          }, 'collection-source-window')));
        const owned = state().collections.items[M.COLLECTIONS.key(item.id, Number(row.EnchantLevel))]?.count || 0, done = registered.includes(row.Id);
        append(card, el('small', 'В сумке с этим усилением: ' + owned), button(done ? 'Зарегистрировано' : 'Зарегистрировать ' + item.name, () => confirm('Регистрация предмета', 'Списать из демосумки ' + item.name + ' ×' + row.Count + ' с усилением ' + row.EnchantLevel + '? Предмет будет зарегистрирован только в коллекцию ' + id + '.', () => {
          if (action('collection-enroll', { bundle, scope, requirementId: row.Id })) {
            (dialog.querySelector('.collection-enroll:not(:disabled)') || dialog.querySelector('button.close'))?.focus();
            notify('Предмет зарегистрирован в локальной коллекции.');
          }
        }, 'collection-enroll-window'), 'primary original-button collection-enroll', !bundle || progress?.locked || done || owned < Number(row.Count)));
        grid.append(card);
      }
      body.append(grid, el('h3', 'Бонусы из источника'));
      for (const bonus of entry.bonuses) body.append(el('p', (bonus.name?.Name || bonus.enum?.name || bonus.row.Type) + ': Min ' + bonus.row.Min + ' / Max ' + bonus.row.Max + ' · тип ' + bonus.row.Type + ' · IsPercentage ' + (bonus.display?.IsPercentage ?? 'неизвестно')));
      const provenance = el('details'); provenance.append(el('summary', 'Происхождение и ограничения'), el('pre', JSON.stringify({ source: meta.source, definition: entry.row, name: entry.name_source, bonuses: entry.bonuses }, null, 2))); body.append(provenance);
      append(body, button('Проверить сумку', openBag), button('Проверить характеристики', () => openSection('Персонаж')));
    }, 'collection-detail-window');
    load(); return dialog;
  }
  function openSection(title) {
    const handlers = { 'Сумка': openBag, 'Магазин': openShop, 'Задания': openQuests, 'Настройки': openSettings, 'Карта': openWorldMap, 'Навыки': openSkills, 'Коллекции': openCollections };
    if (handlers[title]) return handlers[title]();
    return modal(title, body => {
      if (title === 'Персонаж') {
        const c = currentCharacter(); append(body, portrait(c?.appearance), el('h3', c?.name || 'Демоперсонаж'), el('p', className(c?.appearance.classId || 'Reaper')));
        const stats = M.stats(state()); append(body, el('p', 'Атака: ' + stats.attack + ' · Защита: ' + stats.defense));
        const collectionBonuses = M.COLLECTIONS.bonuses(state().collections);
        body.append(el('h3', 'Бонусы завершённых коллекций · демо'));
        if (!collectionBonuses.length) body.append(el('p', 'Завершённых коллекций нет.'));
        else {
          body.append(el('small', 'Сумма исходных значений Min / Max по типу параметра; игровая формула и область действия не подтверждены.'));
          for (const bonus of collectionBonuses) body.append(el('p', bonus.name + ' · тип ' + bonus.type + ': ' + bonus.min + (bonus.min === bonus.max ? '' : '–' + bonus.max) + ' · IsPercentage ' + (bonus.percentage ?? 'неизвестно') + ' · коллекций ' + bonus.collections));
        }
        for (const [slot, name] of [['weapon', 'Оружие'], ['head', 'Голова'], ['body', 'Доспех']]) {
          const id = state().equipped[slot]; append(body, el('p', name + ': ' + (id ? M.PRODUCTS[id].name : 'пусто'))); if (id) body.append(button('Снять ' + name.toLowerCase(), () => action('unequip', { slot })));
        } body.append(button('Открыть сумку', openBag));
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
      const skinRoles = await fetchJSON('skin-evidence.json');
      modal('Общие элементы', body => {
        append(body, el('p', 'Исторические оригиналы. Привязки к текущему клиенту и области владения валютами требуют проверки.'), el('p', shared.unknown.join(' ')));
        const selectKind = select(['Валюты', 'Кнопки', 'Иконки и оформление', 'Привязки оформления'], 'Валюты', draw);
        const search = input('search', 'Название или путь'); search.setAttribute('aria-label', 'Поиск общего элемента');
        const list = el('div', undefined, 'registry-list');
        function draw() {
          list.replaceChildren(); const query = search.value.toLowerCase();
          const rows = selectKind.value === 'Валюты' ? shared.currencies : selectKind.value === 'Кнопки' ? shared.buttons : selectKind.value === 'Привязки оформления' ? Object.entries(skinRoles.roles).map(([id, row]) => ({ id, ...row })) : shared.textures;
          const matches = rows.filter(row => JSON.stringify(row).toLowerCase().includes(query));
          list.append(el('p', 'Найдено: ' + matches.length + ' · показано до 60. Уточните поиск.'));
          matches.slice(0, 60).forEach(row => {
            const card = el('div', undefined, 'resource-control');
            if (row.value !== undefined) append(card, image(row.texture_candidates[0]), el('strong', row.id + ' · ' + (row.symbol || 'неизвестно') + ' · ' + (row.name_en || '')), el('p', 'OwnerType: ' + row.data.OwnerType + ' · MaxValue: ' + row.data.MaxValue));
            else if (row.normal) append(card, image(row.normal), row.pressed ? image(row.pressed) : null, el('p', row.normal + ' / ' + (row.pressed || 'нажатие неизвестно') + ' · hover / disabled неизвестны'));
            else append(card, image(row.asset_path), el('p', row.category ? row.id + ' · ' + row.category : row.asset_path), row.category ? el('small', row.resource + ' · ссылка в пакете подтверждена; brush binding не проверен') : null);
            append(card, button('Источник и SHA256', () => info('Происхождение элемента', JSON.stringify(row, null, 2)))); list.append(card);
          });
        }
        search.oninput = draw; append(body, selectKind, search, list); draw();
      }, 'catalog-window');
    } catch (error) { info('Ошибка общих элементов', error.message); }
  }
  function openInspector(initial = '') {
    let query = '', kind = 'Все', scope = 'all';
    const dialog = modal('Каталог проверки', body => {
      append(body, el('p', manifest.registry_count + ' записей каталога: ' + manifest.named_resource_count + ' ресурсных путей и ' + manifest.unresolved_root_count + ' классов без установленного пути; ' + manifest.variant_count + ' вариантов. Структура не подтверждает игровую логику.'), button('Версии и обновления', openVersions), button('Общие элементы', openSharedElements));
      if (manifest.generation_policy?.mode === 'incremental_verified_rules') {
        const policy = manifest.generation_policy;
        body.append(el('p', 'Поэтапная сборка. Подтверждено правил анализа: ' + policy.confirmed_analysis_rules.length + '; новых правил отображения применено: ' + policy.applied_renderer_rules.length + '.'));
        const descriptions = {
          'Active resource variants and runtime roots': 'активные варианты ресурсов и корни видимых окон',
          'Inherited defaults and dynamic bindings': 'наследуемые значения и динамические привязки',
          'Brush/style/state contracts and event handlers': 'оформление, состояния и обработчики событий',
          'Per-consumer runtime layout and DPI': 'размещение каждого подключения и DPI'
        };
        (policy.limits || []).forEach(text => body.append(el('p', 'Остаётся проверить: ' + (descriptions[text] || text))));
      }
      const search = input('search', 'Имя окна или путь'); search.value = query; search.setAttribute('aria-label', 'Поиск ресурса');
      const list = el('div', undefined, 'registry-list'), count = el('p');
      const filter = select(['Все', 'Попапы', 'Компоненты и окна'], kind, v => { kind = v; fill(); });
      filter.setAttribute('aria-label', 'Тип ресурса');
      const scopeSelect = select([['all', 'Имя и путь'], ['name', 'Только имя'], ['ui-name', 'Заглавные UI в имени']], scope, v => { scope = v; fill(); });
      scopeSelect.setAttribute('aria-label', 'Область поиска');
      const scopeNote = el('p');
      const uiOnly = button('Пройти имена с UI', () => { scope = 'ui-name'; scopeSelect.value = scope; query = ''; search.value = ''; kind = 'Все'; filter.value = kind; fill(); });
      const fill = () => {
        list.replaceChildren(); const matches = VampirCatalogQuery.filter(registry, { query, scope, kind: kind === 'Все' ? 'all' : kind === 'Попапы' ? 'popup' : 'other' });
        scopeNote.textContent = scope === 'ui-name' ? 'Отбор: точные заглавные UI в имени ресурса или класса. Тип окна, активный вариант и связи требуют проверки.' : scope === 'name' ? 'Поиск по имени ресурса или класса.' : 'Поиск по имени и полному пути, включая названия каталогов.';
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
      search.oninput = () => { query = search.value; fill(); }; append(body, search, scopeSelect, filter, uiOnly, scopeNote, count, list); fill();
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
    const dialog = modal('Версии и обновления', body => {
      body.append(button('Прочитанные настройки экрана', async () => {
        try { const data = await fetchJSON('display-settings.json'); if (profileLease.owned && dialog.open) modal('Настройки экрана клиента', b => append(b, el('p', 'Прочитано автоматически при сборке. Сохранённые значения не подтверждают активный UI Scale; коэффициент демо пока отдельный.'), el('pre', JSON.stringify(data, null, 2))), 'catalog-window'); }
        catch (error) { if (profileLease.owned && dialog.open) info('Ошибка чтения настроек', error.message); }
      }));
      append(body, el('p', 'Набор интерфейса: ' + manifest.id), el('p', 'Дата сборки: ' + manifest.built_at), el('p', 'Клиент SHA256: ' + (manifest.client.sha256 || 'недоступен')), el('p', 'Совместимость с клиентом: не подтверждена'), el('p', 'Каталог UI SHA256: ' + manifest.inputs['ui-catalog/index.json']), el('p', 'Демосохранение: схема ' + M.SCHEMA), el('p', storageIssue || 'Хранилище доступно.'), el('p', layouts.limits));
      body.append(button('Размещение окон: источники', () => modal('Размещение окон', b => b.append(el('pre', JSON.stringify(layouts, null, 2))), 'catalog-window')));
      body.append(button('Расположение кнопок: источники', () => modal('Расположение кнопок', b => b.append(el('pre', JSON.stringify(buttonLayouts, null, 2))), 'catalog-window')));
      append(body, el('p', 'Владение ID: ' + (profileLease.owned ? 'это окно' : 'отсутствует')), el('p', 'Окно бота: ' + profile + ' · экономичный режим: ' + (economy ? 'включён' : 'выключен')), el('p', 'Для отдельного окна используйте ?bot=demo-02 … ?bot=demo-50. Тяжёлые данные каталога загружаются по запросу.'));
      const scenarios = [['success', 'Успех'], ['rejected', 'Тестовый отказ'], ['timeout', 'Тестовый таймаут']];
      append(body, field('Сценарий следующего демовхода', select(scenarios, nextEntryScenario, value => nextEntryScenario = value)),
        el('small', 'Сценарий применяется один раз. Повтор по умолчанию успешен; реальные настройки не меняются.'),
        el('p', 'Демовход: ' + entryFlow.state.phase + ' · попыток ' + entryFlow.state.attempt));
      body.append(button('Освободить ID бота', releaseProfile));
      manifest.limits.forEach(text => body.append(el('p', text)));
      body.append(button('Сбросить локальное демо', () => confirm('Сброс демо', 'Сохранённое демосостояние будет удалено. Реальные профили не затрагиваются.', resetDemo)));
    }, 'catalog-window');
  }
  function setAdapter(initial) {
    const local = M.adapter(initial, (value, type) => {
      if (type === 'server') entryFlow.cancel();
      persist(value); document.documentElement.style.setProperty('--user-scale', value.settings.scale / 100);
      updateButtonGeometry();
      if (screen === 'game') refreshHud();
      // Changes redraw view-only dialogs. Preserve forms and controls being edited.
      for (const d of [...dialogs]) if (d.open && !d.contains(document.activeElement?.closest('input,select'))) renderers.get(d)?.();
    });
    adapter = { get state() { return local.state; }, dispatch(type, payload) {
      if (!profileLease.owned) throw Error('ID бота не принадлежит этому окну. Получите управление заново.');
      return local.dispatch(type, payload);
    } };
  }
  function showOwnershipGate(result) {
    hudStatusView?.dispose(); hudStatusView = null;
    entryFlow.cancel();
    activationRevision++; flowRevision++; busy = false; screen = 'ownership';
    clearTimeout(toastTimer); clearTimeout(skillTimer); cancelAnimationFrame(geometryFrame);
    document.getElementById('toast').hidden = true;
    dialogs.slice().reverse().forEach(closeDialog);
    adapter = null;
    document.getElementById('inspector').hidden = true;
    app.className = 'screen screen-auth';
    const panel = el('section', undefined, 'auth-panel ownership-panel');
    const occupied = result.status === 'occupied', released = result.status === 'released';
    append(panel, el('h1', occupied ? 'ID бота уже открыт' : released ? 'Управление освобождено' : 'Владение ID недоступно'),
      el('p', 'ID окна: ' + profile),
      el('p', occupied ? 'Другое окно управляет этим ID. Здесь демосостояние не загружается и не изменяется.' : released ? 'Это окно не изменяет демосостояние. Для продолжения получите управление и загрузите актуальное сохранение.' : 'Браузер не предоставил Web Locks. Одновременная безопасная запись недоступна; интерфейс демо не запущен.'),
      button('Получить управление', activateProfile, 'primary'),
      el('small', 'Для другого бота откройте страницу с отдельным ?bot=demo-02 … ?bot=demo-50. Проверка владения повторяется только по нажатию.'));
    app.replaceChildren(panel);
  }
  function releaseProfile() {
    releasing = profileLease.release();
    showOwnershipGate({ status: 'released' });
  }
  async function activateProfile() {
    if (!resourcesReady || !pageActive) return;
    const revision = ++activationRevision;
    const retry = app.querySelector('.auth-panel button'); if (retry) retry.disabled = true;
    await releasing;
    if (!pageActive || revision !== activationRevision) return;
    const result = await profileLease.acquire();
    if (!pageActive || revision !== activationRevision) return;
    if (result.status !== 'owned') { showOwnershipGate(result); return; }
    let loaded;
    try { loaded = M.load(localStorage, manifest.data_id || manifest.id, profile); }
    catch { loaded = { state: M.initial(), issue: 'Хранилище недоступно. Работа продолжается без сохранения.' }; }
    storageIssue = loaded.issue; storageBlocked = !!storageIssue; setAdapter(loaded.state);
    document.documentElement.style.setProperty('--user-scale', loaded.state.settings.scale / 100);
    document.getElementById('inspector').hidden = false;
    transition('auth');
    if (storageIssue) info('Демосохранение требует проверки', storageIssue);
  }
  async function fetchJSON(url) { const r = await fetch(url); if (!r.ok) throw Error(url + ': HTTP ' + r.status); return r.json(); }
  addEventListener('message', event => {
    if (event.origin !== location.origin || event.source !== gameFrame()?.contentWindow || event.data?.source !== 'vampir-demo-map') return;
    const { type, payload } = event.data;
    if (type === 'ready') mapState();
    if (type === 'target') action('map-target', payload);
    if (type === 'position' && !state().position) action('map-position', payload);
  });
  function updateEntryActivity() {
    document.documentElement.dataset.uiHidden = String(document.hidden);
    if (!document.hidden && entryFlow.state.phase === 'loading') updateEntryPresentation(entryFlow.state);
  }
  addEventListener('visibilitychange', updateEntryActivity); updateEntryActivity();
  addEventListener('visibilitychange', updateMapActivity);
  addEventListener('visibilitychange', updateSkillCooldowns);
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
  document.getElementById('inspector').hidden = true;
  addEventListener('pagehide', () => { pageActive = false; releaseProfile(); });
  addEventListener('pageshow', event => { pageActive = true; if (event.persisted) activateProfile(); });
  Promise.all(['textures.json', 'manifest.json', 'registry-index.json', 'items.json', 'placement-evidence.json', 'button-evidence.json', 'skills-index.json', 'skin-tokens.json', 'components.json', 'component-layouts.json'].map(fetchJSON)).then(async ([t, m, r, items, placement, nativeControls, skills, skinTokens, sharedComponents, componentLayouts]) => {
    skillSources = skills; textures = t; manifest = m; registry = r; sourceItems = items; layouts = placement; buttonLayouts = nativeControls;
    componentDefinitions = sharedComponents;
    const statusSchema = await fetchJSON(componentLayouts.player_status.file);
    if (statusSchema.source.catalog_file !== sharedComponents.modules.player_status.catalog_file || statusSchema.source.catalog_sha256 !== componentLayouts.player_status.source_sha256) throw Error('Схема статуса относится к другому источнику.');
    components = VampirUiComponents.create({ el, append, image, portrait, button, icon, fmt, vitals: M.vitals, geometry: VampirGeometry, definitions: componentDefinitions, schemas: { player_status: statusSchema } });
    if (manifest.state_schema !== M.SCHEMA) throw Error('Версия модели не соответствует manifest этой сборки.');
    document.title = 'Vampir · ' + profile;
    for (const [key, name] of [['title-bg', 'BG_Title'], ['scene-bg', 'BG_PAC'], ['button-bg', 'BTN_ConfirmRed256'], ['button-press', 'BTN_ConfirmRed256_Press'], ['normal-bg', 'BTN_ConfirmBlack256'], ['normal-press', 'BTN_ConfirmBlack256_Press']]) if (textures[name]) document.documentElement.style.setProperty('--' + key, 'url("' + textures[name].url + '")');
    for (const [key, token] of Object.entries(skinTokens)) document.documentElement.style.setProperty('--' + key, 'url("' + token.url + '")');
    document.getElementById('inspector').onclick = () => openInspector();
    geometryObserver.observe(app); resourcesReady = true;
    return activateProfile();
  }).catch(error => { app.replaceChildren(el('h1', 'Не удалось загрузить интерфейс'), el('p', error.message), button('Повторить', () => location.reload())); });
})();
