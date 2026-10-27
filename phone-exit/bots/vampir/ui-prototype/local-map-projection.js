/* Local atlas view only. Never changes owner data or sends game actions. */
(function(root) {
  'use strict';
  const source = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c';
  const archive = '15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4';
  const evidence = '0b26af0a29fcf9f968e9d6f01fd7b3bc198a2e15d944007d93915b34a662c677';
  let pending;
  function valid(spec) {
    return spec?.schema === 1 && spec.kind === 'local_atlas' && spec.formula === 'centered_positive_xy_v1'
      && spec.archive_data_verified === true && spec.current_native_widget_math_verified === false
      && spec.client_context_sha256 === source && spec.archive_sha256 === archive && spec.data_evidence?.sha256 === evidence
      && Array.isArray(spec.size) && spec.size.length === 2 && spec.size.every(n => Number.isFinite(n) && n > 0)
      && Array.isArray(spec.center) && spec.center.length === 2 && spec.center.every(Number.isFinite)
      && Number.isFinite(spec.ground_distance) && spec.ground_distance > 0
      && Array.isArray(spec.map_ids) && spec.map_ids.length > 0 && spec.map_ids.every(id => ['10','11'].includes(id))
      && spec.worlds && Object.getPrototypeOf(spec.worlds) === Object.prototype
      && Object.keys(spec.worlds).length > 0 && Object.entries(spec.worlds).every(([id,map]) => /^\d{1,20}$/.test(id) && spec.map_ids.includes(map));
  }
  function project(snapshot, spec) {
    if (!valid(spec) || snapshot?.state !== 'connected') return null;
    const person = snapshot.character, position = person?.position, world = String(person?.world_id ?? '');
    const map = Object.hasOwn(spec.worlds,world) ? spec.worlds[world] : null;
    if (!map || !/^\d{1,20}$/.test(world) || !position || !['x','y','z'].every(k => Number.isFinite(position[k]))
      || position.semantics !== 'server_target_before_engine_correction'
      || (position.world_id != null && String(position.world_id) !== world)
      || (position.map_id != null && position.map_id !== map)) return null;
    const pixel_x = (position.x-spec.center[0])*spec.size[0]/spec.ground_distance+spec.size[0]/2;
    const pixel_y = (position.y-spec.center[1])*spec.size[1]/spec.ground_distance+spec.size[1]/2;
    if (![pixel_x,pixel_y].every(Number.isFinite)) return null;
    return {x:position.x,y:position.y,z:position.z,world_id:person.world_id,map_id:map,pixel_x,pixel_y,
      inside:pixel_x >= 0 && pixel_x <= spec.size[0] && pixel_y >= 0 && pixel_y <= spec.size[1],
      semantics:position.semantics,origin:'local_atlas',current_native_widget_math_verified:false};
  }
  function load({fetchImpl=root.fetch} = {}) {
    if (!pending) pending = (async () => {
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(),5000);
      try {
        const response = await fetchImpl('local-map-projection.json',{cache:'no-store',signal:controller.signal});
        if (!response.ok) return null;
        const raw = await response.text(); if (raw.length > 65536) return null;
        const spec = JSON.parse(raw);
        function freeze(value) {
          if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
          return value;
        }
        return valid(spec) ? freeze(spec) : null;
      } catch { return null; } finally { clearTimeout(timer); }
    })();
    return pending;
  }
  const api = {project,load,valid}; root.VampirLocalMapProjection = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
