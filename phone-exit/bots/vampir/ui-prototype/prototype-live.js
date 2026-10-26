/* Main prototype live controller. One session adapter feeds passive components. */
(function(root) {
  'use strict';
  function mount({app, windows, components, el, append, icon, button, profile}) {
    const params = new URLSearchParams(location.search), sessionId = params.get('session');
    const validId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,48}$/.test(value);
    const model = root.VampirPrototypeLiveModel;
    let snapshot = null, value = model.project(null), adapter, statusView, disposed = false, dialog, refreshDialog;
    let follow = false, logPaused = false, cursor = 0, gap = false;
    const rows = [];
    document.getElementById('inspector').hidden = true;
    if (!validId(profile) || !validId(sessionId)) {
      app.replaceChildren(el('p', 'Для живого режима нужны корректные bot и session в адресе окна.', 'live-error'));
      return {dispose() {}, resume() {}};
    }
    document.title = 'Vampir · ' + profile;
    const screen = el('section', undefined, 'screen live-prototype');
    screen.dataset.mode = 'live'; screen.dataset.geometryState = 'temporary-live-shell';
    const mapHolder = el('div', undefined, 'map-holder'), map = el('iframe');
    map.title = 'Карта персонажа · справочный атлас';
    map.src = 'map.html?mode=live&bot=' + encodeURIComponent(profile) + '&session=' + encodeURIComponent(sessionId);
    mapHolder.append(map);
    const hud = el('div', undefined, 'live-hud'), identity = el('strong', profile), connection = el('span', 'Ожидание данных…');
    connection.setAttribute('role', 'status');
    const statusHolder = el('div', undefined, 'live-status-holder');
    const summary = el('div', undefined, 'live-summary');
    const level = el('span'), power = el('span'), experience = el('span');
    append(summary, level, power, experience);
    append(hud, append(el('header', undefined, 'live-player'), identity, statusHolder, summary, connection));
    const toolbar = el('nav', undefined, 'live-toolbar'); toolbar.setAttribute('aria-label', 'Меню персонажа');
    const diagnostic = el('a', 'Диагностика');
    diagnostic.href = 'live.html?bot=' + encodeURIComponent(profile) + '&session=' + encodeURIComponent(sessionId);
    diagnostic.title = 'Открыть подробный журнал и управление сессией';
    const environmentButton = button('Окружение', () => openEnvironment(), 'live-log-button', true);
    append(toolbar, environmentButton, button('Журнал', () => openLog(), 'live-log-button'), icon('IMG_Flat_Menu', 'Меню', () => openMenu()));
    hud.append(toolbar);
    const quests = el('aside', undefined, 'quest-tracker live-quests');
    const questList = el('div'), questNotice = el('small', 'Следование по заданию ещё не подключено');
    append(quests, el('h3', 'Задания'), questList, questNotice); hud.append(quests);
    const mapInfo = el('footer', undefined, 'live-map-info'), world = el('span'), coords = el('span'), projection = el('span'), nearby = el('span');
    const center = button('К персонажу', () => sendMap('focus'), 'live-map-button', true);
    center.title = 'Доступно после получения подтверждённой проекции позиции';
    append(mapInfo, world, coords, projection, nearby, center, diagnostic); hud.append(mapInfo);
    const reference = el('span', 'Справочный атлас · совместимость с текущим миром проверяется', 'live-reference');
    append(screen, mapHolder, hud, reference); app.replaceChildren(screen);
    function sendMap(type = 'state') {
      map.contentWindow?.postMessage({source:'vampir-live-prototype', bot_id:profile, session_id:sessionId, type,
        payload:{position:value.position, world_id:value.person?.world_id ?? null, map_id:snapshot?.position?.map_id ?? null, follow, labels:true}}, location.origin);
    }
    function mapReady(event) {
      if (event.origin === location.origin && event.source === map.contentWindow
        && event.data?.source === 'vampir-live-map' && event.data.bot_id === profile
        && event.data.session_id === sessionId && event.data.type === 'ready') sendMap();
    }
    addEventListener('message', mapReady);
    function close() { if (dialog?.open) dialog.close(); }
    function open(title, className = '') {
      close();
      const invoker = document.activeElement;
      dialog = el('dialog', undefined, 'live-dialog ' + className);
      const heading = el('h2', title), body = el('div', undefined, 'dialog-body');
      heading.id = 'live-dialog-title'; dialog.setAttribute('aria-labelledby', heading.id);
      const current = dialog;
      append(dialog, append(el('header', undefined, 'window-heading'), heading, button('×', close, 'close')), body);
      dialog.addEventListener('close', () => {
        current.remove(); if (dialog === current) { dialog = null; refreshDialog = null; }
        if (invoker?.isConnected) invoker.focus({preventScroll:true});
      }, {once:true});
      windows.append(dialog); dialog.showModal(); return body;
    }
    function openMenu() {
      const body = open('Меню', 'menu-window live-menu');
      const menu = components.mainMenu({availability:entry => model.availability(entry.control, value),
        onSelect:entry => openSection(entry.control, entry.label)});
      body.append(menu); refreshDialog = () => menu.refreshAvailability();
    }
    function definitionList(entries) {
      const list = el('dl', undefined, 'live-data');
      for (const [key, data] of entries) append(list, el('dt', key), el('dd', data ?? '—'));
      return list;
    }
    function openSection(control, label) {
      if (!model.availability(control, value).enabled) return;
      const body = open(label);
      if (control === 'ButtonOptionSetting') {
        const input = el('input'); input.type = 'checkbox'; input.checked = follow;
        input.onchange = () => { follow = input.checked; sendMap(); };
        append(body, append(el('label', undefined, 'live-setting'), input, el('span', 'Держать серверную цель в центре карты')),
          el('p', 'Настройка действует только в этом окне и не меняет игру.'));
      } else if (control === 'ButtonShortcutKeySetting') {
        body.append(el('p', 'Escape — закрыть окно. Игровые команды клавиш пока не подключены.'));
      } else {
        let key;
        refreshDialog = () => {
          const next = JSON.stringify([control, value]); if (next === key) return; key = next;
          if (!model.availability(control, value).enabled) { body.replaceChildren(el('p', 'Текущие данные недоступны')); return; }
          if (control === 'ButtonCharacter') body.replaceChildren(definitionList([
            ['Имя', value.person?.name], ['Уровень', value.person?.level], ['HP', value.person?.hp], ['Максимум HP', value.person?.max_hp],
            ['MP', value.person?.mp], ['Максимум MP', value.person?.max_mp], ['Опыт', value.experience], ['Боевая мощь', value.power],
            ['Мир', value.person?.world_id], ['Золото', null], ['Алмазы', null]]));
          else if (control === 'ButtonCombatStats') {
            const table = el('table', undefined, 'live-stats');
            table.append(append(el('thead'), append(el('tr'), el('th', 'ID'), el('th', 'Параметр'), el('th', 'Wire значение'))));
            const rows = el('tbody');
            for (const stat of value.stats) rows.append(append(el('tr'), el('td', stat.id), el('td', stat.name ?? 'Неизвестно'), el('td', stat.value)));
            table.append(rows); body.replaceChildren(el('p', 'Исходные значения сервера; единицы большинства характеристик ещё проверяются.'), table);
          } else body.replaceChildren(...questNodes());
        };
        refreshDialog();
      }
    }
    function questNodes() {
      if (!value.questsKnown) return [el('p', 'Данные заданий ещё не получены')];
      if (!value.quests.length) return [el('p', 'Сервер передал пустой список заданий')];
      return value.quests.map(quest => {
        const node = button(quest.title, () => {
          const body = open('Задание');
          append(body, el('p', quest.title), button('Следовать по заданию', null, '', true), el('p', 'Действие ещё не подключено к адаптеру.'));
        }, 'live-quest'); node.dataset.questId = quest.id; return node;
      });
    }
    function openLog() {
      const body = open('Онлайн-журнал', 'live-log-dialog'), pause = button(logPaused ? 'Продолжить' : 'Пауза', () => {
        logPaused = !logPaused; pause.textContent = logPaused ? 'Продолжить' : 'Пауза'; refreshDialog?.();
      });
      const filter = el('input'); filter.type = 'search'; filter.placeholder = 'ID пакета'; filter.setAttribute('aria-label', 'Фильтр журнала по ID пакета');
      const output = el('pre', undefined, 'live-log'), note = el('small'), analysis = el('pre', undefined, 'live-analysis');
      append(body, append(el('div', undefined, 'live-log-tools'), pause, filter), note, output, el('h3', 'Локальный обработчик'), analysis);
      refreshDialog = () => {
        if (logPaused) return;
        const followLog = output.scrollHeight - output.clientHeight - output.scrollTop < 30;
        output.textContent = rows.filter(row => !filter.value || String(row.packet_id) === filter.value.trim()).map(row => {
          const {time_ms, seq, kind, ...fields} = row;
          return new Date(time_ms).toLocaleTimeString('ru-RU') + ' #' + seq + ' ' + kind + ' ' + JSON.stringify(fields);
        }).join('\n') || 'Событий пока нет';
        note.textContent = (gap ? 'Ранние события пропущены. ' : '') + 'До 256 событий в памяти окна. Пауза меняет только отображение.';
        analysis.textContent = snapshot?.analysis ? JSON.stringify(snapshot.analysis, null, 2) : 'Обработчик не подключён';
        if (followLog) output.scrollTop = output.scrollHeight;
      };
      filter.oninput = () => refreshDialog?.(); refreshDialog();
    }
    function openEnvironment() {
      const body = open('Наблюдаемые объекты'); let previous;
      refreshDialog = () => {
          const key = JSON.stringify([value.entitiesKnown, value.entities, value.entityPage, value.entityRows]); if (key === previous) return; previous = key;
        if (!value.entitiesKnown) { body.replaceChildren(el('p', 'Текущие данные окружения недоступны')); return; }
        const table = el('table', undefined, 'live-stats'), rows = el('tbody');
        table.append(append(el('thead'), append(el('tr'), el('th', 'Тип / ключ'), el('th', 'Имя / код NPC'), el('th', 'Уровень'), el('th', 'HP / MaxHP · MP / MaxMP'), el('th', 'XYZ при получении'))));
        for (const entity of value.entityRows) rows.append(append(el('tr'), el('td', (entity.kind === 'player' ? 'Игрок' : 'NPC') + ' · ' + entity.key),
          el('td', entity.kind === 'player' ? (entity.name || '—') + (entity.name_truncated ? '…' : '') : entity.wire_id ?? '—'), el('td', entity.level ?? '—'),
          append(el('td'), el('div', 'HP ' + (entity.hp ?? '—') + ' / ' + (entity.max_hp ?? '—')), el('div', 'MP ' + (entity.mp ?? '—') + ' / ' + (entity.max_mp ?? '—'))),
          el('td', entity.position && ['x','y','z'].every(k => Number.isFinite(entity.position[k])) ? ['x','y','z'].map(k => entity.position[k].toFixed(1)).join(' / ') : '—')));
          const pages = el('div', undefined, 'live-pagination');
          append(pages, button('Назад', () => adapter.setEntityPage(0), 'live-map-button', value.entityPage === 0),
            el('span', 'Показано ' + value.entityRows.length + ' из ' + value.entities + ' · страница ' + (value.entityPage + 1)),
            button('Далее', () => adapter.setEntityPage(1), 'live-map-button', value.entityPage !== 0 || value.entities <= 256));
          table.append(rows); body.replaceChildren(el('p', (snapshot?.mode === 'fixture' ? 'Тестовые данные · без игрового соединения. ' : '') + 'Неполные данные из SightEnter, NPC create и sight leave. NPC и игроки разделены; собственный персонаж исключается по ключу. Код NPC пока не связан с названием монстра. Характеристики и XYZ записаны при получении сведений; последующие изменения и движение ещё не подключены.'), pages, table);
      }; refreshDialog();
    }
    let questKey;
    function update(next) {
      snapshot = next; value = model.project(next); statusView?.updateLive(next);
      identity.textContent = value.person?.name || profile;
      level.textContent = 'Уровень ' + (value.person?.level ?? '—');
      power.textContent = 'БМ ' + (value.power ?? '—'); experience.textContent = 'Опыт ' + (value.experience ?? '—');
      connection.textContent = next?.mode === 'fixture' ? 'Тестовые данные · без игрового соединения' : next?.state === 'connected'
        ? 'Онлайн · ' + profile : next?.state === 'connecting' ? 'Вход в игру…' : 'Нет текущих данных сессии';
      world.textContent = 'Мир ' + (value.person?.world_id ?? '—');
      coords.textContent = value.xyz ? 'Серверная цель XYZ: ' + ['x','y','z'].map(k => value.xyz[k].toFixed(1)).join(' / ') : 'Серверная цель XYZ: —';
      projection.textContent = value.position ? 'Маркер: серверная цель до коррекции клиента' : 'Позиция на карте: проекция ещё не подтверждена';
      nearby.textContent = value.entitiesPartial ? 'Наблюдалось объектов: ' + value.entities + ' · данные неполные' : 'Объекты рядом: ' + (value.entitiesKnown ? value.entities : '—');
      environmentButton.disabled = !value.entitiesKnown; center.disabled = !value.position;
      const nextQuestKey = JSON.stringify([value.questsKnown, value.quests]);
      if (nextQuestKey !== questKey) { questKey = nextQuestKey; questList.replaceChildren(...questNodes()); }
      if (Array.isArray(next?.journal)) {
        const fresh = next.journal.filter(row => Number.isSafeInteger(row.seq) && row.seq > cursor);
        if (fresh.length && fresh[0].seq > cursor + 1) gap = true;
        rows.push(...fresh); if (rows.length > 256) { rows.splice(0, rows.length - 256); gap = true; }
        if (fresh.length) cursor = fresh[fresh.length - 1].seq;
      }
      sendMap(); refreshDialog?.();
    }
    function resize() {
      // Temporary shell scale; native runtime DPI is still unknown.
      document.documentElement.style.setProperty('--ui-component-unit', Math.max(.55, Math.min(innerWidth / 2400, innerHeight / 1350)) + 'px');
    }
    addEventListener('resize', resize); resize();
    function connect() {
      disposed = false; statusView = components.playerStatus({state:{}, character:null,
        onOpen:() => openSection('ButtonCharacter', 'Персонаж')});
      statusHolder.replaceChildren(statusView.node); update(null);
      adapter = root.VampirLiveState.create({botId:profile, sessionId, onChange:update});
    }
    connect();
    return {dispose() {
      if (disposed) return; disposed = true; close(); adapter?.dispose(); statusView?.dispose();
      removeEventListener('resize', resize); removeEventListener('message', mapReady);
    }, resume() {
      if (!disposed) return;
      addEventListener('resize', resize); addEventListener('message', mapReady); resize(); connect();
    }};
  }
  root.VampirPrototypeLive = {mount};
})(window);
