/* Pure scene queries and screen clusters. No runtime visibility or path inference. */
(function (root) {
  'use strict';
  function filter(points, options) {
    const query = (options.query || '').trim().toLowerCase();
    return points.filter(p => (options.world === 'all' || p.world_id === options.world)
      && options.types.has(p.type)
      && (!options.directLootOnly || (p.type === 'NpcSpawn' && p.loot_count > 0))
      && (!options.npcs || (p.type === 'NpcSpawn' && options.npcs.has(p.npc_id)))
      && (!options.areas || (p.type === 'Area' && options.areas.has(p.id)))
      && (!options.skillNpcs || (p.type === 'NpcSpawn' && options.skillNpcs.has(p.npc_id)))
      && (!query || (p.search || [p.label, p.id, p.npc_id, p.quest_id, p.world_id].join(' ')).toLowerCase().includes(query)));
  }
  function screen(p, view, width, height) {
    return [(p.x - view.x) * view.s + width / 2, (p.y - view.y) * view.s + height / 2];
  }
  function clusters(points, view, width, height, cell = 24) {
    const result = new Map();
    for (const p of points) {
      const [x, y] = screen(p, view, width, height);
      if (x < -30 || y < -30 || x > width + 30 || y > height + 30) continue;
      const key = p.type === 'Area' ? p.key : p.type + ':' + Math.floor(x / cell) + ':' + Math.floor(y / cell);
      let g = result.get(key);
      if (!g) { g = { key, type: p.type, x: 0, y: 0, points: [] }; result.set(key, g); }
      g.x += x; g.y += y; g.points.push(p);
    }
    for (const g of result.values()) { g.x /= g.points.length; g.y /= g.points.length; }
    return [...result.values()];
  }
  function extent(points, fallback) {
    if (!points.length) return fallback;
    return [Math.min(...points.map(p => p.x)), Math.min(...points.map(p => p.y)),
      Math.max(...points.map(p => p.x)), Math.max(...points.map(p => p.y))];
  }
  function itemsForNpc(scene, npcId) {
    return (scene.npcs[npcId]?.loot || []).map(link => ({ ...link, item: scene.items[link.item_id] }));
  }
  function portalDestination(scene, point) {
    return scene.portal_links.filter(link => link.source_key === point.key);
  }
  function tileRect(rect) {
    // assemble-nocturne.py writes [left, top, right, bottom], never [x, y, width, height].
    const [left, top, right, bottom] = rect;
    if (![left, top, right, bottom].every(Number.isFinite) || right <= left || bottom <= top) throw Error('Invalid tile bounds');
    return { x: left, y: top, width: right - left, height: bottom - top };
  }
  function dropAmounts(chains) {
    return [...new Set(chains.map(c => {
      const min = c.min_count, max = c.max_count;
      if (min == null || max == null || min === '' || max === '') return 'не указано';
      return min === max ? String(min) : min + '–' + max;
    }))];
  }
  function monsterChoices(points) {
    const byId = new Map();
    for (const p of points) {
      if (p.type !== 'NpcSpawn') continue;
      if (!byId.has(p.npc_id)) byId.set(p.npc_id, []);
      byId.get(p.npc_id).push(p);
    }
    return [...byId].map(([npc_id, points]) => ({ npc_id, points }));
  }
  function npcSummaries(points) {
    return monsterChoices(points).map(group=>({ ...group,
      labels:[...new Set(group.points.map(p=>p.label).filter(Boolean))],
      worlds:[...new Set(group.points.map(p=>p.world_id))].sort((a,b)=>String(a).localeCompare(String(b),'en',{numeric:true}))
    })).sort((a,b)=>(a.labels[0]||a.npc_id).localeCompare(b.labels[0]||b.npc_id,'ru')
      ||String(a.npc_id).localeCompare(String(b.npc_id),'en',{numeric:true}));
  }
  function areaCandidate(detail, point) {
    return point.area_id && detail?.area_candidates?.[point.area_id] || null;
  }
  function clientRewardScope(point) {
    if (point.type !== 'NpcSpawn' || point.area_id == null) return null;
    const id = String(point.area_id).trim();
    if (id === '' || /^0+$/.test(id)) return 'npc';
    return /^\d+$/.test(id) ? 'area' : null;
  }
  function cooldownValue(value, unit) {
    const raw = String(value ?? '').trim();
    if (!raw) return '—';
    if (unit !== 'milliseconds' || !/^-?\d+$/.test(raw)) return raw;
    const negative = raw.startsWith('-'), n = BigInt(raw);
    const absolute = n < 0n ? -n : n;
    const fraction = String(absolute % 1000n).padStart(3, '0').replace(/0+$/, '');
    return (negative && n !== 0n ? '−' : '') + String(absolute / 1000n)
      + (fraction ? ',' + fraction : '') + ' с';
  }
  function skillCooldownAtLevel(skill, level) {
    if(!Number.isInteger(level)||level<0||level>32767)throw Error('Уровень должен быть целым числом от 0 до 32767.');
    const overrides=skill.level_overrides;
    if(overrides?.cooldown_replacement_verified!==true)throw Error('Правило изменения перезарядки по уровню не подтверждено.');
    const selected=overrides.records.find(row=>row.SkillInfoId===skill.record.Id
      &&Number(row.MinLevel)<=level&&level<=Number(row.MaxLevel));
    const values={},origins={};
    for(const field of ['MinCoolTime','MaxCoolTime']){
      const replacement='Change'+field,raw=selected?.[replacement];
      const useChange=raw!=null&&raw!==''&&BigInt(raw)!==0n;
      values[field]=useChange?raw:skill.record[field];
      origins[field]={table:useChange?'SkillLevel':'Skill',field:useChange?replacement:field,
        provenance:(useChange?selected:skill.record).provenance};
    }
    return {level,values,origins,selected_record:selected||null,runtime_cooldown_verified:false};
  }
  function skillValuesAtLevel(skill,level){
    const result=skillCooldownAtLevel(skill,level),selected=result.selected_record;
    for(const field of ['Resource','StackCount','MpMin','MpMax']){
      const flag={Resource:'resource_replacement_verified',StackCount:'stack_count_replacement_verified',MpMin:'mp_min_replacement_verified',MpMax:'mp_max_replacement_verified'}[field];
      if(skill.level_overrides[flag]!==true)continue;
      const key='Change'+field,raw=selected?.[key]??'';
      let use=raw!=='';
      if(field==='StackCount'&&use){
        if(!/^[0-9]+$/.test(raw)||BigInt(raw)>255n)throw Error('StackCount выходит за диапазон байта.');
        use=BigInt(raw)!==0n;
      }
      if((field==='MpMin'||field==='MpMax')&&use){
        if(!/^[0-9]+$/.test(raw)||BigInt(raw)>2147483647n)throw Error('Некорректное значение MP.');
        use=BigInt(raw)!==0n;
      }
      result.values[field]=use?raw:skill.record[field]??'';
      result.origins[field]={table:use?'SkillLevel':'Skill',field:use?key:field,
        provenance:(use?selected:skill.record).provenance};
    }
    return result;
  }
  function placeLabels(labels, width, height, obstacles = []) {
    const placed = [], gap = 4, edge = 4;
    const overlaps = (a, b) => a.x < b.x + b.width + gap && a.x + a.width + gap > b.x
      && a.y < b.y + b.height + gap && a.y + a.height + gap > b.y;
    const ordered = [...labels].sort((a, b) => Number(!!b.selected) - Number(!!a.selected)
      || a.x - b.x || a.y - b.y || String(a.key).localeCompare(String(b.key)));
    for (const label of ordered) {
      const radius = label.radius || 6, w = label.width, h = label.height || 22;
      const candidates = [];
      for(let offset=0;offset<=120;offset+=24){
        const distance=radius+gap+offset;
        candidates.push([label.x+distance,label.y-h/2],[label.x-distance-w,label.y-h/2],
          [label.x-w/2,label.y-distance-h],[label.x-w/2,label.y+distance]);
      }
      for (const [x, y] of candidates) {
        const box = {key:label.key, x, y, width:w, height:h};
        if (x < edge || y < edge || x + w > width - edge || y + h > height - edge) continue;
        if (placed.some(other => overlaps(box, other)) || obstacles.some(other => overlaps(box, other))) continue;
        placed.push(box);break;
      }
    }
    return placed;
  }
  const api = { filter, screen, clusters, extent, itemsForNpc, portalDestination, tileRect, dropAmounts, monsterChoices, npcSummaries, areaCandidate, clientRewardScope, cooldownValue, skillCooldownAtLevel, skillValuesAtLevel, placeLabels };
  root.WorldMapModel = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
