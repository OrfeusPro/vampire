/* Same-origin bridge for the offline atlas. Does not enable the live session layer. */
(() => {
  'use strict';
  const origin = location.origin;
  // Atlas navigation replaces its query before this script can finish loading.
  // The owning iframe retains the explicit mode and session identity.
  const params = new URLSearchParams(frameElement ? new URL(frameElement.src).search : location.search), live = params.get('mode') === 'live';
  const botId = params.get('bot'), sessionId = params.get('session');
  if (live && typeof types !== 'undefined') {
    // Historical spawn / quest definitions are not live nearby actors.
    for (const type of [...types]) if (type !== 'Area') types.delete(type);
    if (typeof update === 'function') update();
  }
  let demo = { position: null, target: null, follow: false }, previousKey = '', timer, liveScaleReady = false;
  const overlay = document.createElement('canvas'); overlay.id = 'demoOverlay'; document.body.append(overlay);
  overlay.dataset.stateSource = live ? 'live' : 'demo';
  const context = overlay.getContext('2d');
  function notify(type, payload) { parent.postMessage({ source: live ? 'vampir-live-map' : 'vampir-demo-map',
    ...(live ? {bot_id:botId,session_id:sessionId} : {}), type, payload }, origin); }
  addEventListener('message', event => {
    if (event.origin !== origin || event.source !== parent || event.data?.source !== (live ? 'vampir-live-prototype' : 'vampir-demo')) return;
    if (live && (event.data.bot_id !== botId || event.data.session_id !== sessionId)) return;
    if (event.data.type === 'state') {
      if (live) {
        const payload = event.data.payload, p = payload?.position;
        demo = {position:p && Number.isFinite(p.x) && Number.isFinite(p.y) ? {x:p.x,y:p.y} : null,
          target:null,follow:payload?.follow === true,labels:payload?.labels === true};
      } else demo = event.data.payload;
      if (typeof $ === 'function') { $('labels').checked = demo.labels !== false; if (typeof schedule === 'function') schedule(); }
    }
    if (event.data.type === 'zoom' && typeof view !== 'undefined') {
      view.s *= event.data.payload > 0 ? 1.3 : 1 / 1.3; schedule();
    }
    if (event.data.type === 'fit' && typeof fitPoints === 'function' && typeof visible !== 'undefined') fitPoints(visible, true);
    if (event.data.type === 'focus' && demo.position && typeof view !== 'undefined') { view.x = demo.position.x; view.y = demo.position.y; schedule(); }
  });
  let start;
  const mapCanvas = document.getElementById('canvas');
  mapCanvas.addEventListener('pointerdown', event => { start = [event.clientX, event.clientY]; });
  mapCanvas.addEventListener('pointerup', event => {
    if (live) { start = null; return; }
    if (!start || Math.hypot(event.clientX - start[0], event.clientY - start[1]) > 6 || typeof view === 'undefined') return;
    const box = mapCanvas.getBoundingClientRect();
    const p = { x: (event.clientX - box.left - box.width / 2) / view.s + view.x, y: (event.clientY - box.top - box.height / 2) / view.s + view.y };
    notify('target', p); start = null;
  });
  function draw() {
    if (document.hidden) return;
    timer = setTimeout(draw, 100);
    if (typeof view === 'undefined' || typeof scene === 'undefined' || !scene) return;
    const width = innerWidth, height = innerHeight;
    if (live && !liveScaleReady) { view.s = Math.max(width, height) / 615000; liveScaleReady = true; schedule(); }
    if (overlay.width !== width || overlay.height !== height) { overlay.width = width; overlay.height = height; }
    if (!demo.position) { context.clearRect(0, 0, width, height); previousKey = ''; if (!live) notify('position', { x: view.x, y: view.y }); return; }
    if (demo.follow && !demo.target && (view.x !== demo.position.x || view.y !== demo.position.y)) { view.x = demo.position.x; view.y = demo.position.y; schedule(); }
    const key = JSON.stringify([view, width, height, demo]);
    if (key === previousKey) return;
    previousKey = key; context.clearRect(0, 0, width, height);
    const screen = p => ({ x: (p.x - view.x) * view.s + width / 2, y: (p.y - view.y) * view.s + height / 2 });
    const p = screen(demo.position);
    if (demo.target) {
      const t = screen(demo.target); context.strokeStyle = '#e5c68a'; context.lineWidth = 2; context.setLineDash([8, 6]); context.beginPath(); context.moveTo(p.x, p.y); context.lineTo(t.x, t.y); context.stroke(); context.setLineDash([]);
      context.strokeRect(t.x - 9, t.y - 9, 18, 18);
    }
    context.fillStyle = '#f0d99a'; context.shadowColor = '#df792e'; context.shadowBlur = 12; context.beginPath(); context.moveTo(p.x, p.y - 14); context.lineTo(p.x + 10, p.y + 10); context.lineTo(p.x, p.y + 5); context.lineTo(p.x - 10, p.y + 10); context.closePath(); context.fill(); context.shadowBlur = 0;
  }
  addEventListener('visibilitychange', () => { clearTimeout(timer); if (!document.hidden) draw(); });
  addEventListener('pagehide', () => clearTimeout(timer));
  notify('ready'); draw();
})();
