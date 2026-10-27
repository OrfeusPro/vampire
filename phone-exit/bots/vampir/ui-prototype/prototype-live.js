/* Main prototype live controller. One session adapter feeds passive components. */
(function(root) {
  'use strict';
  function mount({app, windows, components, el, append, icon, button, profile}) {
    const params = new URLSearchParams(location.search), sessionId = params.get('session');
    const validId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,48}$/.test(value);
    const model = root.VampirPrototypeLiveModel;
    let snapshot = null, value = model.project(null), adapter, statusView, disposed = false, dialog, refreshDialog;
    let follow = false, logPaused = false, cursor = 0, gap = false, interaction;
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
    const questList = el('div'), questNotice = el('small', 'Управление заданиями пока недоступно');
    const policies=el('div',undefined,'live-policies'),messageList=el('div',undefined,'live-messages'),actionStatus=el('p');
    actionStatus.setAttribute('role','status');
    const skipLabel=el('label',undefined,'live-setting'),skipCheck=el('input');skipCheck.type='checkbox';
    const autoLabel=el('label',undefined,'live-setting'),autoCheck=el('input');autoCheck.type='checkbox';
    append(skipLabel,skipCheck,el('span','Пропускать диалоги'));
    append(autoLabel,autoCheck,el('span','Автовыполнение квестов'));append(policies,skipLabel,autoLabel);
    append(quests,el('h3','Задания'),policies,questList,questNotice,el('h3','Сообщения'),messageList,actionStatus);hud.append(quests);
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
      if (!value.quests.length) return [el('p', value.questsObserved ? 'Полученное сообщение не содержит записей квестов' : 'Сервер передал пустой список заданий')];
      const nodes = value.quests.map(quest => {
        const node = button(quest.title, () => {
          const actionId=interaction?.questAction(quest.id);
          if(interaction?.policy.auto_quests&&actionId&&interaction.available(actionId)){void interaction.perform(actionId);return;}
          const body = open('Задание');
          append(body,el('p',quest.title),button(interaction?.policy.auto_quests?'Запустить автовыполнение':'Продолжить задание',
            ()=>interaction?.perform(actionId),'',!actionId||!interaction?.available(actionId)));
          if(!actionId)append(body,el('p',interaction?.view.automation?.state==='waiting_npc'
            ? 'Подойдите к NPC'+(interaction.view.automation.npc_label?': '+interaction.view.automation.npc_label:'')
            : 'Управление заданием в этой сессии ещё недоступно.'));
          if (quest.objective) append(body,el('p',quest.objective));
          if (value.questsObserved) append(body, el('p', 'Последнее сообщение сервера; активный шаг ещё не установлен.'),
            el('pre', JSON.stringify({group:quest.group,state:quest.state,progress:quest.progress},null,2), 'live-analysis'));
        }, 'live-quest'); node.dataset.questId = quest.id; return node;
      });
      return value.questsObserved ? [el('small', 'Полученные задания. Активный этап ещё уточняется.'), ...nodes] : nodes;
    }
    let interactionKey;
    function renderInteraction() {
      if(!interaction)return;
      const view=interaction.view,policy=interaction.policy;
      skipCheck.checked=policy.skip_dialogues;autoCheck.checked=policy.auto_quests;
      skipCheck.disabled=interaction.policyBusy;autoCheck.disabled=interaction.policyBusy;
      actionStatus.textContent=interaction.status;
      const automation=view.automation;
      questNotice.textContent=automation?.state==='waiting_npc'?'Подойдите к NPC'+(automation.npc_label?': '+automation.npc_label:'')
        :automation?.state==='running'?'Выполняется выбранное задание':!view.ready?'Управление заданиями пока недоступно'
        :policy.auto_quests?'Нажмите на квест, чтобы начать автовыполнение':'Выберите задание для ручного продолжения';
      const key=JSON.stringify([view.messages,view.actions.map(a=>[a.id,interaction.available(a.id)]),view.known,view.messagesKnown]);
      if(key===interactionKey)return;interactionKey=key;
      if(!view.messages.length){messageList.replaceChildren(el('p',view.messagesKnown?'Нет новых сообщений':'Текстовые сообщения ещё не получены'));return;}
      messageList.replaceChildren(...view.messages.map(message=>{
        const article=el('article',undefined,'live-message');
        if(message.speaker)article.append(el('strong',message.speaker));
        article.append(el('p',message.text));
        for(const choice of message.choices)article.append(button(choice.text,()=>interaction.perform(choice.action_id),
          'live-message-choice',!message.active||!interaction.available(choice.action_id)));
        if(message.skip_action_id)article.append(button('Пропустить',()=>interaction.perform(message.skip_action_id),
          'live-message-skip',!message.active||!interaction.available(message.skip_action_id)));
        return article;
      }));
    }
    skipCheck.addEventListener('change',()=>interaction?.setPolicy('skip_dialogues',skipCheck.checked));
    autoCheck.addEventListener('change',()=>interaction?.setPolicy('auto_quests',autoCheck.checked));
    function openLog() {
      const body = open('Онлайн-журнал', 'live-log-dialog'), pause = button(logPaused ? 'Продолжить' : 'Пауза', () => {
        logPaused = !logPaused; pause.textContent = logPaused ? 'Продолжить' : 'Пауза'; refreshDialog?.();
      });
      const filter = el('input'); filter.type = 'search'; filter.placeholder = 'ID пакета'; filter.setAttribute('aria-label', 'Фильтр журнала по ID пакета');
      const output = el('pre', undefined, 'live-log'), note = el('small'), analysis = el('pre', undefined, 'live-analysis');
      const tutorial = el('pre', undefined, 'live-analysis'); tutorial.setAttribute('aria-label', 'Полученное сообщение обучения');
      append(body, append(el('div', undefined, 'live-log-tools'), pause, filter), note, output,
        el('h3', 'Полученное сообщение обучения'),
        el('p', 'Последнее сообщение сервера, до 64 записей. Это не активный локальный шаг; значения raw-полей ещё проверяются.'), tutorial,
        el('h3', 'Локальный обработчик'), analysis);
      refreshDialog = () => {
        if (logPaused) return;
        const followLog = output.scrollHeight - output.clientHeight - output.scrollTop < 30;
        output.textContent = rows.filter(row => !filter.value || String(row.packet_id) === filter.value.trim()).map(row => {
          const {time_ms, seq, kind, ...fields} = row;
          return new Date(time_ms).toLocaleTimeString('ru-RU') + ' #' + seq + ' ' + kind + ' ' + JSON.stringify(fields);
        }).join('\n') || 'Событий пока нет';
        note.textContent = (gap ? 'Ранние события пропущены. ' : '') + 'До 256 событий в памяти окна. Пауза меняет только отображение.';
        analysis.textContent = snapshot?.analysis ? JSON.stringify(snapshot.analysis, null, 2) : 'Обработчик не подключён';
        tutorial.textContent = value.tutorial ? 'ID 9905 · записей ' + value.tutorial.records.length
          + ' · flag ' + String(value.tutorial.flag) + '\nraw08 | raw0c | raw10 | state\n'
          + value.tutorial.records.map(r => [r.raw08,r.raw0c,r.raw10,r.state].join(' | ')).join('\n')
          : 'Данные обучения ещё не получены или недоступны';
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
      interaction?.observe(next);
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
      const nextQuestKey = JSON.stringify([value.questsKnown, value.questsObserved, value.quests]);
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
      interaction?.dispose();interactionKey=undefined;
      interaction=root.VampirLiveInteraction.create({botId:profile,sessionId,dispatch:payload=>adapter.action(payload),
        configurePolicy:policy=>adapter.policy(policy),onChange:renderInteraction});
      disposed = false; statusView = components.playerStatus({state:{}, character:null,
        onOpen:() => openSection('ButtonCharacter', 'Персонаж')});
      statusHolder.replaceChildren(statusView.node); update(null);
      adapter = root.VampirLiveState.create({botId:profile, sessionId, onChange:update});
    }
    connect();
    return {dispose() {
      if (disposed) return; disposed = true; close(); interaction?.dispose(); adapter?.dispose(); statusView?.dispose();
      removeEventListener('resize', resize); removeEventListener('message', mapReady);
    }, resume() {
      if (!disposed) return;
      addEventListener('resize', resize); addEventListener('message', mapReady); resize(); connect();
    }};
  }
  root.VampirPrototypeLive = {mount};
})(window);
