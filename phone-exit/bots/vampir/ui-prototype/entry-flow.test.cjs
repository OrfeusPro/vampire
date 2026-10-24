'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const E = require('./entry-flow.js');
const context = { profile: 'demo-01', server: 'Franz 2', region: 'Весь мир' };
function clock() {
  const jobs = new Map(); let id = 0;
  return { jobs, schedule(fn) { jobs.set(++id, fn); return id; }, unschedule(id) { jobs.delete(id); },
    tick() { const row = jobs.entries().next().value; if (!row) return; jobs.delete(row[0]); row[1](); },
    run() { for (let i = 0; jobs.size && i < 1000; i++) this.tick(); assert.equal(jobs.size, 0); } };
}
test('success emits bounded stages, one terminal result and no idle timers', () => {
  const c = clock(), events = [], flow = E.create({ ...c, onChange: value => events.push(value) });
  flow.start(context); assert.equal(c.jobs.size, 1);
  assert.throws(() => flow.start(context), /уже/);
  c.run(); assert.deepEqual(events.map(e => e.phase), ['loading', 'loading', 'loading', 'ready']);
  assert.deepEqual(events.map(e => e.step), [0, 1, 2, 3]);
  assert.equal(flow.cancel(), false); assert.equal(c.jobs.size, 0);
  events[0].context.server = 'changed'; assert.equal(flow.state.context.server, 'Franz 2');
});
test('rejection and timeout allow an explicit fresh successful attempt', () => {
  for (const scenario of ['rejected', 'timeout']) {
    const c = clock(), flow = E.create(c);
    flow.start(context, scenario); c.run();
    assert.equal(flow.state.phase, 'failed'); assert.equal(flow.state.error.code, 'DEMO_' + scenario.toUpperCase());
    assert.equal(c.jobs.size, 0); flow.start(context); c.run();
    assert.equal(flow.state.phase, 'ready'); assert.equal(flow.state.attempt, 2); assert.equal(flow.state.error, null);
  }
});
test('cancellation and a late old callback cannot advance a new server attempt', () => {
  const c = clock(), events = [], flow = E.create({ ...c, onChange: e => events.push(e) });
  flow.start(context); const late = [...c.jobs.values()][0];
  assert.equal(flow.cancel(), true); assert.equal(c.jobs.size, 0);
  flow.start({ ...context, server: 'Kurzel 1' });
  const before = flow.state; late(); assert.deepEqual(flow.state, before);
  c.run(); assert.equal(flow.state.context.server, 'Kurzel 1');
  assert.equal(events.filter(e => e.phase === 'ready').length, 1);
});
test('cancelling inside a subscriber does not schedule a stray callback', () => {
  const c = clock(); let flow;
  flow = E.create({ ...c, onChange: e => { if (e.phase === 'loading') flow.cancel(); } });
  flow.start(context); assert.equal(flow.state.phase, 'cancelled'); assert.equal(c.jobs.size, 0);
});
test('50 entry controllers keep contexts independent and remove their timers', () => {
  const c = clock(), flows = Array.from({ length: 50 }, (_, i) => {
    const flow = E.create(c); flow.start({ ...context, profile: 'demo-' + i }, i % 2 ? 'timeout' : 'success'); return flow;
  });
  assert.equal(c.jobs.size, 50); c.run();
  flows.forEach((flow, i) => { assert.equal(flow.state.context.profile, 'demo-' + i); assert.equal(flow.state.phase, i % 2 ? 'failed' : 'ready'); });
});
test('invalid contexts and scenarios do not start work', () => {
  const c = clock(), flow = E.create(c);
  for (const data of [null, {}, { ...context, profile: '../real' }, { ...context, server: '' }]) assert.throws(() => flow.start(data));
  assert.throws(() => flow.start(context, 'unknown')); assert.equal(c.jobs.size, 0); assert.equal(flow.state.phase, 'idle');
});
