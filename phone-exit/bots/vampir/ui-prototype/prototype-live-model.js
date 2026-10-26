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
    const questContext = snapshot?.quest_snapshot;
    const questsObserved = !!person && snapshot.coverage?.quests === 'last_received_message'
      && questContext?.semantics === 'last_received_message' && questContext.applied_to_local_task === false
      && questContext.character_key === person.key && questContext.world_id === person.world_id
      && Array.isArray(snapshot.quests) && snapshot.quests.length <= 128
      && snapshot.quests.every(q => q && typeof q.id === 'string' && /^\d{1,20}$/.test(q.id)
        && Number.isInteger(q.group) && q.group >= 0 && q.group <= 12 && Number.isInteger(q.state) && q.state >= 0 && q.state <= 6);
    const questsKnown = questsObserved || (!!person && snapshot.coverage?.quests === 'received' && Array.isArray(snapshot.quests));
    const quests = questsObserved ? snapshot.quests.map(q => {
      const label = root.VampirQuestNamesRu?.get(q.id,questContext.source_sha256);
      return {...q,title:label?.title || 'Квест ' + q.id,objective:label?.objective || null,
        progress:q.progress && {...q.progress}};
    })
      : questsKnown ? snapshot.quests.slice(0,128).filter(q => q
      && typeof q.id === 'string' && /^\d{1,20}$/.test(q.id) && typeof q.title === 'string' && q.title.length <= 256) : [];
    const receivedTutorial = snapshot?.tutorial;
    const u32 = n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
    const tutorial = person && snapshot.coverage?.tutorial === 'last_received_message'
      && receivedTutorial?.semantics === 'last_received_message' && receivedTutorial.applied_to_local_task === false
      && typeof receivedTutorial.flag === 'boolean' && Array.isArray(receivedTutorial.records) && receivedTutorial.records.length <= 64
      && (receivedTutorial.character_key === null || receivedTutorial.character_key === person.key)
      && receivedTutorial.records.every(r => r && [r.raw08,r.raw0c,r.raw10].every(u32) && Number.isInteger(r.state) && r.state >= 0 && r.state <= 3)
      ? {flag:receivedTutorial.flag, records:receivedTutorial.records.map(r => ({raw08:r.raw08,raw0c:r.raw0c,raw10:r.raw10,state:r.state}))} : null;
    let power = null;
    const entityRows = person && ['received','partial'].includes(snapshot.coverage?.entities) && Array.isArray(snapshot.entities) ? snapshot.entities : [];
    if (person?.stats_semantics === 'wire_stat_i64' && /^-?\d{1,20}$/.test(raw(134) ?? '')) power = String(BigInt(raw(134)) / 100n);
    return { person, stats, experience:raw(1), power, quests, questsKnown, questsObserved, tutorial,
      position:verifiedPosition ? { x:position.x,y:position.y } : null,
      xyz:person?.position && ['x','y','z'].every(k => Number.isFinite(person.position[k])) ? person.position : null,
      entitiesKnown:!!person && ['received','partial'].includes(snapshot.coverage?.entities) && Array.isArray(snapshot.entities),
      entitiesPartial:!!person && snapshot.coverage?.entities === 'partial',entityRows,
      entityPage:[0,1].includes(snapshot?.environment?.entity_page) ? snapshot.environment.entity_page : 0,
      entities:person && ['received','partial'].includes(snapshot.coverage?.entities) && Array.isArray(snapshot.entities)
        ? Number.isSafeInteger(snapshot.environment?.known_count) && snapshot.environment.known_count >= entityRows.length && snapshot.environment.known_count <= 512 ? snapshot.environment.known_count : entityRows.length : null };
  }
  function availability(control, value) {
    const supported = { ButtonCharacter:!!value.person, ButtonCombatStats:value.stats.length > 0,
      ButtonQuest:value.questsKnown, ButtonOptionSetting:true, ButtonShortcutKeySetting:true };
    return { enabled:supported[control] === true, reason:control in supported ? 'Данные раздела ещё не получены' : 'Данные и действия раздела ещё не подключены' };
  }
  const api = { project, availability }; root.VampirPrototypeLiveModel = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
