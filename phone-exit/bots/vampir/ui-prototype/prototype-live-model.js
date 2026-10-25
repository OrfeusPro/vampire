/* View projection only. The shared live adapter owns network and identity. */
(function(root) {
  'use strict';
  function project(snapshot) {
    const person = snapshot?.state === 'connected' ? snapshot.character : null;
    const stats = Array.isArray(person?.stats) ? person.stats : [];
    const raw = id => stats.find(row => row.id === id)?.value ?? null;
    const position = snapshot?.position;
    const verifiedPosition = person && /^\d{1,20}$/.test(String(person.world_id)) && position && position.world_id === person.world_id && ['10','11'].includes(position.map_id)
      && [position.x,position.y,position.z,position.pixel_x,position.pixel_y].every(Number.isFinite)
      && ['server_target_before_engine_correction','server_target_xy_retained_z'].includes(position.semantics);
    const questsKnown = !!person && snapshot.coverage?.quests === 'received' && Array.isArray(snapshot.quests);
    const quests = questsKnown && Array.isArray(snapshot.quests) ? snapshot.quests.slice(0,128).filter(q => q
      && typeof q.id === 'string' && /^\d{1,20}$/.test(q.id) && typeof q.title === 'string' && q.title.length <= 256) : [];
    let power = null;
    if (person?.stats_semantics === 'wire_stat_i64' && /^-?\d{1,20}$/.test(raw(134) ?? '')) power = String(BigInt(raw(134)) / 100n);
    return { person, stats, experience:raw(1), power, quests, questsKnown,
      position:verifiedPosition ? { x:position.x,y:position.y } : null,
      xyz:person?.position && ['x','y','z'].every(k => Number.isFinite(person.position[k])) ? person.position : null,
      entitiesKnown:!!person && snapshot.coverage?.entities === 'received' && Array.isArray(snapshot.entities),
      entities:person && snapshot?.coverage?.entities === 'received' && Array.isArray(snapshot.entities) ? snapshot.entities.length : null };
  }
  function availability(control, value) {
    const supported = { ButtonCharacter:!!value.person, ButtonCombatStats:value.stats.length > 0,
      ButtonQuest:value.questsKnown, ButtonOptionSetting:true, ButtonShortcutKeySetting:true };
    return { enabled:supported[control] === true, reason:control in supported ? 'Данные раздела ещё не получены' : 'Данные и действия раздела ещё не подключены' };
  }
  const api = { project, availability }; root.VampirPrototypeLiveModel = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
