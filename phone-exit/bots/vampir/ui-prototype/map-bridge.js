/* Same-origin bridge for the offline atlas. Does not enable the live session layer. */
(() => {
  'use strict';
  const origin = location.origin;
  let demo = { position: null, target: null, follow: false }, previousKey = '', timer;
  const overlay = document.createElement('canvas'); overlay.id = 'demoOverlay'; document.body.append(overlay);
  const context = overlay.getContext('2d');
  function notify(type, payload) { parent.postMessage({ source: 'vampir-demo-map', type, payload }, origin); }
  addEventListener('message', event => {
    if (event.origin !== origin || event.source !== parent || event.data?.source !== 'vampir-demo') return;
    if (event.data.type === 'state') {
      demo = event.data.payload;
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
    if (overlay.width !== width || overlay.height !== height) { overlay.width = width; overlay.height = height; }
    if (!demo.position) { notify('position', { x: view.x, y: view.y }); return; }
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
