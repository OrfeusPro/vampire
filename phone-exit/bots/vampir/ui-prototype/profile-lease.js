/* One writer per demo profile in the same browser storage partition. No polling. */
(function(root) {
  'use strict';
  function create(manager, name) {
    let owned = false, pending = null, task = Promise.resolve(), unlock = null, revision = 0;
    function acquire() {
      if (owned) return Promise.resolve({ status: 'owned' });
      if (pending) return pending;
      if (!manager || typeof manager.request !== 'function') return Promise.resolve({ status: 'unsupported' });
      const token = ++revision;
      let finish, settled = false;
      const ready = new Promise(resolve => { finish = resolve; });
      pending = ready;
      const done = value => {
        if (settled) return;
        settled = true;
        if (pending === ready) pending = null;
        finish(value);
      };
      try {
        task = Promise.resolve(manager.request(name, { mode: 'exclusive', ifAvailable: true }, lock => {
          if (token !== revision) { done({ status: 'cancelled' }); return; }
          if (!lock) { done({ status: 'occupied' }); return; }
          owned = true;
          return new Promise(resolve => {
            unlock = resolve;
            done({ status: 'owned' });
          });
        })).catch(() => {
          if (token === revision) { owned = false; unlock = null; }
          done({ status: 'unavailable' });
        });
      } catch {
        done({ status: 'unavailable' });
      }
      return ready;
    }
    function release() {
      revision++;
      owned = false;
      const finish = unlock;
      unlock = null;
      finish?.();
      return task;
    }
    return { acquire, release, get owned() { return owned; } };
  }
  const api = { create };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.VampirProfileLease = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
