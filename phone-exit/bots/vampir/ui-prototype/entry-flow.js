/* Cancellable local entry simulation; no network or persistent profile writes. */
(function(root) {
  'use strict';
  const STEPS = ['Подготовка демосессии', 'Проверка демосостояния', 'Чтение списка персонажей'];
  const SCENARIOS = ['success', 'rejected', 'timeout'];
  function create({ onChange, schedule = setTimeout, unschedule = clearTimeout, delay = 400 } = {}) {
    if (!Number.isFinite(delay) || delay < 0 || delay > 60000) throw Error('Некорректная задержка демовхода.');
    let revision = 0, timer = null, attempt = 0;
    let value = { phase: 'idle', step: 0, total: STEPS.length, context: null, error: null, attempt };
    const copy = () => JSON.parse(JSON.stringify(value));
    const emit = () => onChange?.(copy());
    const clear = () => { if (timer !== null) unschedule(timer); timer = null; };
    function start(context, scenario = 'success') {
      if (value.phase === 'loading') throw Error('Вход уже выполняется.');
      if (!context || typeof context.profile !== 'string' || !/^[a-zA-Z0-9_-]{1,48}$/.test(context.profile) ||
          typeof context.server !== 'string' || !context.server.trim() || context.server.length > 80 ||
          typeof context.region !== 'string' || context.region.length > 80 || !SCENARIOS.includes(scenario)) throw Error('Некорректный сценарий демовхода.');
      clear(); const token = ++revision;
      value = { phase: 'loading', step: 0, total: STEPS.length, context: { profile: context.profile, server: context.server, region: context.region }, error: null, attempt: ++attempt };
      function queue() {
        if (token !== revision || value.phase !== 'loading') return;
        timer = schedule(() => {
          if (token !== revision || value.phase !== 'loading') return;
          timer = null;
          value.step++;
          if (value.step === STEPS.length) {
            value.phase = scenario === 'success' ? 'ready' : 'failed';
            value.error = scenario === 'success' ? null : scenario === 'timeout'
              ? { code: 'DEMO_TIMEOUT', message: 'Время ожидания истекло в тестовом сценарии.' }
              : { code: 'DEMO_REJECTED', message: 'Вход отклонён в тестовом сценарии.' };
          }
          emit(); queue();
        }, delay);
      }
      emit(); queue(); return copy();
    }
    function cancel() {
      if (value.phase !== 'loading') return false;
      revision++; clear(); value.phase = 'cancelled'; value.error = null; emit(); return true;
    }
    return { start, cancel, get state() { return copy(); } };
  }
  const api = { STEPS, SCENARIOS, create };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirEntryFlow = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
