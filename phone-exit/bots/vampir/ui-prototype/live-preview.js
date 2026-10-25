/* Explicit session viewer: one adapter, existing components, no demo model/storage. */
(() => {
  'use strict';
  const params = new URLSearchParams(location.search), botId = params.get('bot');
  let sessionId = params.get('session'), adapter, view, components, statKey, disposed = false, stopping = false;
  const id = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,48}$/.test(value);
  const status = document.getElementById('connection'), stop = document.getElementById('stop');
  const el = (tag, text, className) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; };
  const append = (parent, ...children) => { parent.append(...children.filter(Boolean)); return parent; };
  let logPaused = false, logCursor = 0, logGap = false, analysisKey;
  const logRows = [], filter = document.getElementById('log-filter'), pause = document.getElementById('log-pause');
  const eventNames = { session_created:'Сессия создана', source_bound:'Источник привязан', packet_received:'Получен пакет', stats_received:'Получены характеристики', vitals_changed:'HP / MP / уровень изменены', stat_decode_error:'Ошибка разбора характеристик', world_ready:'Вход в мир', stop_requested:'Запрошена остановка', session_closed:'Сессия закрыта', trace_configured:'Захват настроен', trace_expired:'Срок захвата истёк', analysis_updated:'Обработчик обновлён', analysis_expired:'Наблюдатель перестал обновлять данные' };
  function renderLog(forceFollow = false) {
    if (logPaused) return;
    const output = document.getElementById('live-log');
    const follow = forceFollow || output.scrollHeight - output.clientHeight - output.scrollTop < 24;
    const packet = filter.value.trim(), valid = !packet || /^\d{1,5}$/.test(packet);
    filter.setCustomValidity(valid ? '' : 'Укажите числовой ID пакета');
    output.textContent = logRows.filter(row => !packet || String(row.packet_id) === packet).map(row => {
      const { seq, time_ms, kind, ...fields } = row;
      return new Date(time_ms).toLocaleTimeString('ru-RU') + ' #' + seq + ' ' + (eventNames[kind] || kind) + ' ' + JSON.stringify(fields);
    }).join('\n') || 'Событий пока нет';
    if (follow) output.scrollTop = output.scrollHeight;
    document.getElementById('log-gap').textContent = logGap ? 'Часть ранних событий пропущена: журнал ограничен и хранится только в памяти.' : 'Журнал хранится только в памяти; показаны последние 256 событий.';
  }
  filter.oninput = () => renderLog(true);
  pause.onclick = () => { logPaused = !logPaused; pause.textContent = logPaused ? 'Продолжить журнал' : 'Пауза журнала'; renderLog(true); };
  async function json(url, options = {}) {
    const response = await fetch(url, { cache: 'force-cache', ...options, signal: AbortSignal.timeout(3000) });
    if (!response.ok) throw Error('Ответ сервиса: ' + response.status);
    const text = await response.text(); if (text.length > 1048576) throw Error('Превышен лимит ответа.'); return JSON.parse(text);
  }
  function update(snapshot) {
    view?.updateLive(snapshot);
    if (Array.isArray(snapshot?.journal)) {
      const fresh = snapshot.journal.filter(row => Number.isSafeInteger(row.seq) && row.seq > logCursor);
      if (fresh.length && fresh[0].seq > logCursor + 1) logGap = true;
      logRows.push(...fresh); if (logRows.length > 256) { logRows.splice(0, logRows.length - 256); logGap = true; }
      if (fresh.length) logCursor = fresh[fresh.length - 1].seq;
      renderLog();
    }
    const analysis = snapshot?.analysis, nextAnalysis = JSON.stringify(analysis);
    if (analysisKey !== nextAnalysis) {
      analysisKey = nextAnalysis;
      document.getElementById('analysis-revision').textContent = analysis ? 'Ревизия ' + analysis.revision + (analysis.error ? ' · ошибка ' + analysis.error : ' · обработан текущий поток') : 'Обработчик не подключён';
      document.getElementById('analysis-values').textContent = analysis ? JSON.stringify(analysis.values, null, 2) : '—';
    }
    document.getElementById('trace-status').textContent = snapshot?.trace?.packet_ids?.length ? 'Временный захват пакетов: ' + snapshot.trace.packet_ids.join(', ') + ' · ' + snapshot.trace.sample_bytes + ' байт в памяти' : 'Захват содержимого пакетов выключен';
    const person = snapshot?.state === 'connected' ? snapshot.character : null;
    document.getElementById('identity').textContent = person?.name || botId;
    document.getElementById('level').textContent = person?.level ?? '—';
    document.getElementById('world').textContent = person?.world_id ?? '—';
    document.getElementById('heartbeat').textContent = snapshot?.heartbeat ? snapshot.heartbeat.received + ' / ' + snapshot.heartbeat.sent : '—';
    if (!stopping) status.textContent = snapshot?.mode === 'fixture' ? 'Тестовые данные · без игрового соединения' : snapshot?.state === 'connected' ? 'Соединение активно · ' + botId : snapshot?.state === 'connecting' ? 'Вход в игру…' : snapshot?.state === 'disconnected' ? 'Сессия отключена' : 'Нет текущих данных сессии';
    stop.disabled = stopping || !snapshot || snapshot.state === 'disconnected';
    const stats = Array.isArray(person?.stats) && person.stats.length <= 1024 ? person.stats : [];
    const key = JSON.stringify(stats);
    if (key === statKey) return; statKey = key;
    document.getElementById('stat-count').textContent = stats.length ? '· ' + stats.length : '';
    const rows = stats.map(stat => append(el('tr'), el('td', stat.id), el('td', stat.name ?? 'Неизвестно'), el('td', stat.value)));
    document.getElementById('stats').replaceChildren(...rows);
  }
  function connect() {
    if (disposed || !components) return;
    const main = document.getElementById('main-prototype');
    main.href = 'index.html?mode=live&bot=' + encodeURIComponent(botId) + '&session=' + encodeURIComponent(sessionId); main.hidden = false;
    adapter?.dispose(); view?.dispose(); statKey = undefined;
    view = components.playerStatus({ state: {}, character: null });
    view.updateLive(null); document.getElementById('player-status').replaceChildren(view.node);
    adapter = VampirLiveState.create({ botId, sessionId, onChange: update });
  }
  stop.onclick = async () => {
    if (stopping || stop.disabled) return;
    stopping = true; stop.disabled = true; status.textContent = 'Остановка сессии…';
    const base = 'http://127.0.0.1:17947/bots/' + encodeURIComponent(botId);
    try {
      const control = await json(base + '/control', { cache: 'no-store' });
      if (control.bot_id !== botId || control.session_id !== sessionId || typeof control.token !== 'string') throw Error('Сессия изменилась.');
      await json(base + '/stop', { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-Session-Token': control.token }, body: JSON.stringify({ bot_id: botId, session_id: sessionId }) });
      status.textContent = 'Запрос остановки принят';
    } catch { status.textContent = 'Результат остановки неизвестен. Проверьте состояние сессии.'; }
    // No automatic repeat after an uncertain result.
  };
  addEventListener('pagehide', () => { disposed = true; adapter?.dispose(); view?.dispose(); });
  addEventListener('pageshow', event => { if (event.persisted) { disposed = false; connect(); } });
  (async () => {
    if (!id(botId) || (sessionId !== null && !id(sessionId))) throw Error('Укажите корректные bot и session в адресе окна.');
    if (sessionId === null) {
      const list = await json('http://127.0.0.1:17947/sessions', { cache: 'no-store' });
      const matches = list.sessions?.filter(item => item.bot_id === botId) || [];
      if (matches.length !== 1 || !id(matches[0].session_id)) throw Error('Сессия этого бота не найдена.');
      sessionId = matches[0].session_id;
    }
    const [textures, definitions, layouts, skin] = await Promise.all(['textures.json', 'components.json', 'component-layouts.json', 'status-skin.json'].map(path => json(path)));
    const [player, portrait] = await Promise.all([layouts.player_status.file, layouts.player_portrait.file].map(path => json(path)));
    if (player.source.catalog_sha256 !== layouts.player_status.source_sha256 || portrait.source.catalog_sha256 !== layouts.player_portrait.source_sha256) throw Error('Источники компонентов не совпадают.');
    const image = (name, className = '') => { const value = textures[name]; if (!value) return el('span', '', className); const node = el('img', undefined, className); node.src = value.url; node.alt = ''; return node; };
    components = VampirUiComponents.create({ el, append, image, fmt: String, vitals: () => [], geometry: VampirGeometry, definitions, schemas: { player_status: player, player_portrait: portrait }, statusSkin: skin });
    document.title = 'Vampir · ' + botId; connect();
  })().catch(error => { status.textContent = error.message; stop.disabled = true; });
})();
