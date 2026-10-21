'use strict';
const $ = id => document.getElementById(id), model = WorldMapModel;
const canvas = $('canvas'), ctx = canvas.getContext('2d');
const colors = { NpcSpawn: '#84b9ef', Area: '#f4d48b', Waypoint: '#d7a7ff', GadgetSpawn: '#bda1e3', WorldSpot: '#62e7bc', QuestTask: '#ff8da5' };
const layerNames = { Area: 'Области и названия', Waypoint: 'Порталы', NpcSpawn: 'NPC и добыча', GadgetSpawn: 'Объекты', WorldSpot: 'Мировые точки', QuestTask: 'Цели квестов' };
const types = new Set(Object.keys(layerNames));
let scene, visible = [], groups = [], selected = null, npcFilter = null, itemId = '', resultLimit = 60;
let view = { x: 0, y: 0, s: .001 }, dimensions = { width: 900, height: 700 }, frame = 0, cardEpoch = 0;
const preview = new Image(), tileCache = new Map(), iconCache = new Map(), worldCache = new Map();
const worldById = new Map(), pointByKey = new Map();
let monsterManifest = null, areaRewardsPending = null, areaFilter = null;
let skillIndexPending=null, skillFilter=null, skillId='', skillEpoch=0;
const monsterCache = new Map();
let areaTaskIndex = new Map(), spotTaskIndex = new Map();
let liftPreview = null, selectedLift = null;
let navOverlay=null, navOverlayPending=null;
let selectedNavSpecial=null;
let sessionSnapshot=null,sessionTimer=null,sessionAbort=null,sessionEpoch=0;

function sessionMessage(text){$('sessionStatus').textContent=text;}
async function pollSession(epoch){
  if(epoch!==sessionEpoch||!$('sessionLayer').checked||document.hidden)return;
  sessionAbort=new AbortController();const abort=sessionAbort;
  const timeout=setTimeout(()=>abort.abort(),2000);
  try{
    const response=await fetch('http://127.0.0.1:17947/state',{cache:'no-store',signal:abort.signal});
    if(!response.ok)throw Error('HTTP '+response.status);
    const text=await response.text();if(text.length>4096)throw Error('Слишком большой ответ');
    const snapshot=MapSessionModel.validate(JSON.parse(text));
    if(epoch!==sessionEpoch)return;
    sessionSnapshot=snapshot;
    const p=snapshot.position;
    const labels={waiting:'Ожидание позиции',disconnected:'Сессия отключена',unsupported_world:'Для этого мира нет проверенной карты'};
    sessionMessage(p?'Серверная цель входа · мир '+p.world_id+' · высота '+Math.round(p.z)
      +(Date.now()-snapshot.updated_at_ms>5000?' · снимок позиции устарел':'')
      +(!p.inside?' · за границами атласа':''):labels[snapshot.state]);
    $('sessionFocus').disabled=!p||!p.inside||!worldById.has(String(p.world_id));
  }catch(error){
    if(epoch!==sessionEpoch)return;
    sessionSnapshot=null;$('sessionFocus').disabled=true;sessionMessage('Нет соединения с ботом');
  }finally{
    clearTimeout(timeout);if(sessionAbort===abort)sessionAbort=null;
    if(epoch===sessionEpoch){schedule();sessionTimer=setTimeout(()=>pollSession(epoch),1000);}
  }
}
function resetSessionPolling(){
  ++sessionEpoch;clearTimeout(sessionTimer);sessionAbort?.abort();sessionSnapshot=null;
  $('sessionFocus').disabled=true;schedule();
  if($('sessionLayer').checked&&!document.hidden)pollSession(sessionEpoch);
  else sessionMessage($('sessionLayer').checked?'Вывод приостановлен в скрытой вкладке':'Вывод сессии выключен');
}
$('sessionLayer').onchange=resetSessionPolling;
document.addEventListener('visibilitychange',resetSessionPolling);
$('sessionFocus').onclick=()=>{
  const p=sessionSnapshot?.position;if(!p||!p.inside||!worldById.has(String(p.world_id)))return;
  $('worlds').value=String(p.world_id);update();view={x:p.x,y:p.y,s:.008};schedule();
};
function drawSession(){
  if(!$('sessionLayer').checked)return;
  const p=MapSessionModel.marker(sessionSnapshot,$('worlds').value,Date.now());if(!p)return;
  const [x,y]=pointScreen(p);ctx.save();ctx.strokeStyle=p.stale?'#b3bdc9':'#ffffff';
  ctx.fillStyle='#42e9bb';ctx.lineWidth=3;
  ctx.beginPath();ctx.arc(x,y,9,0,Math.PI*2);ctx.fill();ctx.stroke();
  ctx.fillStyle='#ffffff';ctx.font='bold 13px system-ui';ctx.fillText('Персонаж · цель входа',x+15,y-12);ctx.restore();
}

function fail(error) { $('error').textContent = 'Не удалось загрузить данные: ' + error.message; }
async function json(url, hash) {
  const response = await fetch(url, { cache: 'no-cache' });
  if (!response.ok) throw Error(url + ' · HTTP ' + response.status);
  const bytes = await response.arrayBuffer();
  if (hash) {
    const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(v => v.toString(16).padStart(2, '0')).join('');
    if (actual !== hash) throw Error('Изменился SHA256: ' + url);
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function link(text, href) { const node = el('a', text); node.href = href; return node; }
function schedule() { if (!frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); }
function fitPoints(points, full = false) {
  if (!scene) return;
  const b = full ? scene.projection.world_bounds : model.extent(points, scene.projection.world_bounds);
  dimensions = canvas.getBoundingClientRect();
  view = { x: (b[0] + b[2]) / 2, y: (b[1] + b[3]) / 2,
    s: Math.min((dimensions.width - 60) / Math.max(b[2] - b[0], 4000), (dimensions.height - 65) / Math.max(b[3] - b[1], 4000)) };
  schedule();
}
function options() { return { world: $('worlds').value, types: $('search').value.trim() && $('searchAll').checked ? new Set(Object.keys(layerNames)) : types, query: $('search').value, npcs: npcFilter, areas: areaFilter, skillNpcs:skillFilter, directLootOnly: $('directLootOnly').checked }; }
function update(fit = false) {
  if (!scene) return;
  visible = model.filter(scene.points, options());
  resultLimit = 60; renderList();
  $('status').textContent = ($('worlds').value === 'all' ? 'Вся Nocturne · 36 контекстов мира' : 'Мир ' + $('worlds').value)
    + ' · ' + visible.length.toLocaleString('ru') + ($('search').value.trim() && $('searchAll').checked ? ' результатов поиска во всех слоях' : ' записей в выбранных слоях')
    + (itemId ? ' · источники предмета ' + itemId : '');
  if (fit) fitPoints(visible); else schedule();
  updateUrl();
  if(skillId)$('skillStatus').textContent=skillFilter
    ? 'Фильтр NPC по навыку '+skillId+' · '+new Set(visible.filter(p=>p.type==='NpcSpawn').map(p=>p.npc_id)).size+' NPC / '+visible.length+' размещений с учётом остальных фильтров.'
    : 'Открыта карточка навыка '+skillId+'. Фильтр NPC выключен — карта показывает обычные слои.';
}
function updateUrl() {
  const params = new URLSearchParams();
  if ($('worlds').value !== 'all') params.set('world', $('worlds').value);
  if (itemId) params.set('item', itemId);
  if(skillId)params.set('skill',skillId);
  if(skillId&&skillFilter)params.set('skillNpc','1');
  if (areaFilter) params.set('rewardScope', 'area');
  if ($('directLootOnly').checked) params.set('npcLoot', '1');
  if (selected) { params.set('point', selected.key); if (selected.type === 'NpcSpawn') params.set('npc', selected.npc_id); }
  if (selectedLift && $('liftLayer').checked) params.set('lift', selectedLift.id);
  if(selectedNavSpecial&&$('navSpecialLayer')?.checked)params.set('navLink',selectedNavSpecial.id);
  history.replaceState(null, '', location.pathname + (params.size ? '?' + params : ''));
}
function renderList() {
  $('results').replaceChildren();
  $('separateSpawnsLabel').style.display=skillFilter?'flex':'none';
  if(skillFilter&&!$('separateSpawns').checked){
    const npcs=model.npcSummaries(visible);
    $('resultCount').textContent=npcs.length+' NPC · '+visible.length+' размещений · в списке '+Math.min(resultLimit,npcs.length);
    for(const group of npcs.slice(0,resultLimit)){
      const button=el('button',group.labels.join(' / ')||'NPC '+group.npc_id);
      button.append(el('small','Ур. '+(scene.npcs[group.npc_id]?.level||'—')+' · NPC '+group.npc_id),el('small',group.points.length+' размещений · миры '+group.worlds.join(', ')));
      button.style.borderLeft='3px solid '+colors.NpcSpawn;
      button.onclick=()=>{focus(group.points[0]);fitPoints(group.points);};
      $('results').append(button);
    }
    $('more').hidden=resultLimit>=npcs.length;
    return;
  }
  // Areas and portals lead the overview list; searching still reaches every record.
  const ordered = [...visible].sort((a, b) => priority(a.type) - priority(b.type));
  $('resultCount').textContent = visible.length.toLocaleString('ru') + ' записей · в списке ' + Math.min(resultLimit, visible.length);
  for (const p of ordered.slice(0, resultLimit)) {
    const button = el('button', p.label);
    button.append(el('small', layerNames[p.type] + ' · мир ' + p.world_id + ' · ' + p.id));
    if(p.type==='NpcSpawn')button.append(el('small','Уровень '+(scene.npcs[p.npc_id]?.level||'—')));
    if(p.type==='NpcSpawn' && p.loot_count>0)button.append(el('small','NpcReward · '+p.loot_count+' предметов · NPC '+p.npc_id));
    button.style.borderLeft = '3px solid ' + colors[p.type];
    button.onclick = () => focus(p); $('results').append(button);
  }
  $('more').hidden = resultLimit >= visible.length;
}
function priority(type) { return ['Area', 'Waypoint', 'GadgetSpawn', 'NpcSpawn', 'WorldSpot', 'QuestTask'].indexOf(type); }
function pointScreen(p) { return model.screen(p, view, dimensions.width, dimensions.height); }
function imageForIcon(id) {
  const images = scene.icons[id]?.images;
  if (images?.length !== 1) return null;
  const file = images[0].file;
  if (!iconCache.has(file)) {
    const image = new Image(); image.onload = schedule; image.src = '../../' + file; iconCache.set(file, image);
  }
  const image = iconCache.get(file);
  return image.complete && image.naturalWidth ? image : null;
}
function background() {
  const b = scene.projection.world_bounds, [x, y] = pointScreen({ x: b[0], y: b[1] });
  const extent = (b[2] - b[0]) * view.s;
  if (preview.complete && preview.naturalWidth) ctx.drawImage(preview, x, y, extent, extent);
  // At overview scale use the small image. Original tiles load only when their detail is needed.
  if (extent / 5 * Math.min(devicePixelRatio, 2) < 390) return;
  const needed = new Set();
  for (const tile of scene.background.tiles) {
    const { x: px, y: py, width, height } = model.tileRect(tile.atlas_rect);
    const tx = x + px / 10240 * extent, ty = y + py / 10240 * extent, tw = width / 10240 * extent, th = height / 10240 * extent;
    if (tx > dimensions.width || ty > dimensions.height || tx + tw < 0 || ty + th < 0) continue;
    needed.add(tile.file);
    let image = tileCache.get(tile.file);
    if (!image) { image = new Image(); image.onload = schedule; image.src = '../../' + tile.file; tileCache.set(tile.file, image); }
    if (image.complete && image.naturalWidth) ctx.drawImage(image, tx, ty, tw, th);
  }
  if (tileCache.size > 10) for (const [key] of tileCache) { if (!needed.has(key)) tileCache.delete(key); if (tileCache.size <= 10) break; }
}
function drawPolygons() {
  for (const polygon of scene.polygons) {
    if ($('worlds').value !== 'all' && polygon.world_id !== $('worlds').value) continue;
    if (polygon.type === 'World' ? !$('worldBounds').checked : !$('areaBounds').checked) continue;
    ctx.beginPath(); polygon.vertices.forEach((v, i) => { const [x, y] = pointScreen({ x: v[0], y: v[1] }); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.closePath();
    ctx.strokeStyle = polygon.type === 'World' ? '#62e7bc99' : '#f4d48b66';
    ctx.lineWidth = polygon.type === 'World' ? 1.6 : 1; ctx.stroke();
  }
}
function drawNavigation(){
  if(!navOverlay||!$('navLayer')?.checked)return;
  const tiles=NavOverlayModel.visible(navOverlay.tiles,view,dimensions.width,dimensions.height);
  ctx.save();ctx.strokeStyle='#bb9af0a6';ctx.fillStyle='#ad86ed24';ctx.lineWidth=.7;
  for(const tile of tiles){
    if(!NavOverlayModel.detailed(tile,view.s)){
      const [x,y]=pointScreen({x:tile.bounds[0],y:tile.bounds[1]});
      ctx.fillRect(x,y,(tile.bounds[2]-tile.bounds[0])*view.s,(tile.bounds[3]-tile.bounds[1])*view.s);
      continue;
    }
    const vertices=tile.vertices.map(v=>pointScreen({x:v[0],y:v[1]}));
    for(const face of tile.polygons){ctx.beginPath();face.forEach((id,i)=>{const [x,y]=vertices[id];i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.closePath();ctx.fill();ctx.stroke();}
  }
  ctx.restore();
  $('navStatus').textContent=navOverlay.stats.tiles.toLocaleString('ru')+' ячеек · '+navOverlay.stats.surface_polygons.toLocaleString('ru')+' полигонов · в окне '+tiles.length.toLocaleString('ru')+' ячеек.';
}
function drawSpecialNavigation(){
  if(!navOverlay||!$('navSpecialLayer')?.checked)return;
  ctx.save();ctx.strokeStyle='#f6c566';ctx.fillStyle='#f6c566';
  for(const p of navOverlay.special_links||[]){
    const [ax,ay]=pointScreen({x:p.start[0],y:p.start[1]}),[bx,by]=pointScreen({x:p.end[0],y:p.end[1]});
    ctx.lineWidth=p===selectedNavSpecial?3:1.7;ctx.setLineDash([6,5]);ctx.beginPath();ctx.moveTo(ax,ay);ctx.lineTo(bx,by);ctx.stroke();ctx.setLineDash([]);
    for(const [x,y] of [[ax,ay],[bx,by]]){ctx.beginPath();ctx.arc(x,y,p===selectedNavSpecial?6:4,0,Math.PI*2);ctx.stroke();}
    if(p===selectedNavSpecial){ctx.font='bold 13px system-ui';ctx.fillText('A',ax+10,ay-10);ctx.fillText('B',bx+10,by-10);}
  }
  ctx.restore();
}
function focusNavSpecial(p){
  if(!p)return;
  ++cardEpoch;selected=null;selectedLift=null;selectedNavSpecial=p;
  $('worlds').value='all';$('search').value='';update();$('navSpecialLayer').checked=true;$('navSpecialChoice').value=p.id;
  $('selection').hidden=false;const card=$('card'),fmt=v=>v.map(x=>x.toLocaleString('ru',{maximumFractionDigits:2})).join(' · ');
  card.replaceChildren(el('h2',p.label),el('p','Назначение и фактическая доступность перехода не подтверждены.','muted'));
  if(p.direction_gate_bypassed_by_flag&&navOverlay.special_direction_evidence){
    card.append(el('h3','Направление по флагам клиента'),el('p','Флаг клиента не запрещает движение A → B и B → A. Присоединение к сетке и остальные условия ещё требуют проверки.','muted'),link('Проверка флагов и кода клиента',navOverlay.special_direction_evidence.file));
  }else card.append(el('p','Направление перехода ещё не подтверждено.','muted'));
  if(p.surface_candidate_check&&navOverlay.special_nearest_evidence){
    const check=p.surface_candidate_check;
    const status=(found,matched)=>!found?'в этом режиме поверхность не найдена':matched?'найдена поверхность; точка совпадает с сохранённой вершиной':'найдена поверхность; точка отличается от сохранённой вершины';
    const detail=el('details');detail.append(el('summary','Упрощённая проверка поверхности'),
      el('p','A: '+status(check.start_found,check.start_matches_baked)),el('p','B: '+status(check.end_candidate_count>0,check.end_matches_baked)),
      el('p','Проверка использует упрощённый режим клиентского поиска. Фактическое присоединение и проходимость в игре не подтверждены.','muted'),
      link('Расчёт точек и ограничения проверки',navOverlay.special_nearest_evidence.file));card.append(detail);
  }
  if(p.native_attachment_scenario&&navOverlay.special_attachment_evidence){
    const check=p.native_attachment_scenario,detail=el('details');
    detail.append(el('summary','Воспроизведение присоединения · предварительно'),
      el('p',check.matches_baked?'Клиентский алгоритм создал обе связи и точно воспроизвёл сохранённые точки в исследовательском сценарии.':check.connected?'Клиентский алгоритм создал обе связи; координаты отличаются от сохранённых.':'В исследовательском сценарии связь не создана. Это не доказывает отсутствие перехода в игре.'),
      el('p','Настройки сценария подобраны при сравнении данных. Активные настройки игры, загрузка участков и фактическая проходимость ещё не подтверждены.','muted'),
      link('Сценарии, связи и условия проверки',navOverlay.special_attachment_evidence.file));card.append(detail);
    if(navOverlay.area_priority_evidence)detail.append(el('p','Приоритеты рассчитываются из значений игрового фильтра. Его активные значения пока не найдены.','muted'),link('Как клиент рассчитывает приоритеты',navOverlay.area_priority_evidence.file));
    if(navOverlay.navigation_filter_presets&&navOverlay.navigation_filter_evidence){
      const presets=el('details');presets.append(el('summary','Фильтры из ресурсов клиента'),el('p','Это сохранённые настройки фильтров клиента. Какой из них активен в игре сейчас, не подтверждено.','muted'));
      if(navOverlay.navigation_filter_application_evidence)presets.append(el('p','Стрелка показывает изменение сохранённого значения при применении переопределения клиентом. Стоимость прохода ограничивается минимумом 1, входа — минимумом 0.','muted'));
      for(const preset of navOverlay.navigation_filter_presets){
        presets.append(el('h3',preset.name.replace('BP_NavQuery_','')));
        for(const [index,area] of preset.areas.entries()){
          const name=(area.AreaClass||'Неизвестная область').split('.').pop().replace(/^NnNavArea_|^NavArea_/,'');
          const check=preset.application_check?.[index],shown=(raw,written)=>!Number.isFinite(raw)?'неизвестно':raw.toLocaleString('ru')+(Number.isFinite(written)&&written!==raw?' → '+written.toLocaleString('ru'):'');
          const values=[];if(area.bIsExcluded===true)values.push('флаг исключения');
          else{
            if(area.bOverrideTravelCost===true)values.push('проход: '+shown(area.TravelCostOverride,check?.travel_written));
            if(area.bOverrideEnteringCost===true)values.push('вход: '+shown(area.EnteringCostOverride,check?.entering_written));
          }
          presets.append(el('p',name+': '+(values.join(' · ')||'без явного переопределения'),'muted'));
        }
      }
      presets.append(link('Записи фильтров и источники',navOverlay.navigation_filter_evidence.file));detail.append(presets);
      if(navOverlay.navigation_filter_application_evidence)presets.append(el('p','Исключение пропускает переопределения стоимости той же записи. Проверка выполнена на локальном объекте фильтра; активное состояние игры не прочитано.','muted'),link('Проверка применения настроек',navOverlay.navigation_filter_application_evidence.file));
    }
  }
  card.append(el('h3','Сохранённые точки · X · Y · Z'),el('p','A: '+fmt(p.start)),el('p','B: '+fmt(p.end)),
    el('p','Разница высоты: '+(p.end[2]-p.start[2]).toLocaleString('ru',{maximumFractionDigits:2})+' ед. клиента'));
  if(p.spatial_lift_candidates.length){
    card.append(el('p','Координаты совпадают с предварительным расчётом лифта. Связь объектов по идентификатору не установлена.','muted'));
    for(const candidate of p.spatial_lift_candidates){const button=el('button','Посмотреть расчёт лифта #'+candidate.lift_id,'member');button.onclick=()=>focusLift(liftPreview?.lifts.find(l=>l.id===candidate.lift_id));card.append(button);}
  }
  const baked=el('details');baked.append(el('summary','Точки в сохранённом полигоне'),el('p','A: '+fmt(p.baked_start)),el('p','B: '+fmt(p.baked_end)),el('p','Уточнение концов на поверхности и условия перехода требуют проверки.','muted'));card.append(baked);
  if(navOverlay.special_source)card.append(link('Записи и источники специальных переходов',navOverlay.special_source.file));
  const bounds=model.extent([p.start,p.end].map(v=>({x:v[0],y:v[1]})),scene.projection.world_bounds),panel=$('selection').getBoundingClientRect().width,available=Math.max(300,dimensions.width-panel-40);
  view.s=Math.min((available-60)/Math.max(bounds[2]-bounds[0],12000),(dimensions.height-65)/Math.max(bounds[3]-bounds[1],12000));
  view.x=(bounds[0]+bounds[2])/2+(dimensions.width-available)/(2*view.s);view.y=(bounds[1]+bounds[3])/2;schedule();updateUrl();
}
function drawRelation() {
  if (!$('relations').checked || !selected) return;
  for (const edge of model.portalDestination(scene, selected)) {
    const d = edge.destination; if (!edge.destination_on_atlas || !d) continue;
    const [x, y] = pointScreen(selected), [dx, dy] = pointScreen({ x: +d.PosX, y: +d.PosY });
    ctx.save(); ctx.strokeStyle = '#edc6ff'; ctx.lineWidth = 2; ctx.setLineDash([7, 5]);
    ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(dx, dy); ctx.stroke(); ctx.restore();
    ctx.strokeStyle = '#edc6ff'; ctx.strokeRect(dx - 6, dy - 6, 12, 12);
  }
}
function liftPoints(lift) {
  const origin = lift.placement.RelativeLocation;
  return [origin, ...lift.calculated_links.flatMap(edge => [edge.left, edge.right])].filter(Boolean)
    .map(p => ({x:p[0], y:p[1], z:p[2]}));
}
function drawLiftPreview() {
  if (!liftPreview || !$('liftLayer').checked) return;
  ctx.save(); ctx.strokeStyle='#ffbb75'; ctx.fillStyle='#ffbb75'; ctx.lineWidth=2;
  for (const lift of liftPreview.lifts) {
    ctx.globalAlpha = selectedLift && selectedLift !== lift ? .45 : 1;
    ctx.lineWidth = selectedLift === lift ? 2.5 : 1.5;
    const points=liftPoints(lift); if (!points.length) continue;
    const [x,y]=pointScreen(points[0]);
    ctx.setLineDash([]); ctx.beginPath(); ctx.moveTo(x,y-5); ctx.lineTo(x+5,y);ctx.lineTo(x,y+5);ctx.lineTo(x-5,y);ctx.closePath();ctx.stroke();
    for (const edge of lift.calculated_links) {
      const [ax,ay]=pointScreen({x:edge.left[0],y:edge.left[1]}),[bx,by]=pointScreen({x:edge.right[0],y:edge.right[1]});
      ctx.setLineDash([6,5]);ctx.beginPath();ctx.moveTo(ax,ay);ctx.lineTo(bx,by);ctx.stroke();ctx.setLineDash([]);
      ctx.strokeRect(ax-4,ay-4,8,8);ctx.strokeRect(bx-4,by-4,8,8);
      if(selectedLift===lift){ctx.font='bold 12px system-ui';ctx.fillText('A',ax+14,ay-12);ctx.fillText('B',bx+14,by-12);}
    }
    if(selectedLift===lift){ctx.strokeStyle='#fff';ctx.beginPath();ctx.arc(x,y,11,0,Math.PI*2);ctx.stroke();ctx.strokeStyle='#ffbb75';}
  }
  ctx.restore();
}
function nearestLift(x,y) {
  if (!liftPreview || !$('liftLayer').checked) return null;
  let nearest=null, distance=12;
  for(const lift of liftPreview.lifts)for(const point of liftPoints(lift)){
    const [px,py]=pointScreen(point),d=Math.hypot(x-px,y-py);
    if(d<distance){nearest=lift;distance=d;}
  }
  return nearest;
}
function focusLift(lift) {
  if(!lift)return;
  selectedNavSpecial=null;
  ++cardEpoch;selected=null;$('worlds').value='all';update();
  selectedLift=lift;$('liftLayer').checked=true;$('liftChoice').value=lift.id;
  $('liftPanel').querySelector('details').open=true;
  $('selection').hidden=false;
  const card=$('card');card.replaceChildren(el('h2',lift.label));
  card.append(el('p','Предварительный расчёт · проходимость не проверена','badge'),el('p',lift.assumption,'muted'));
  if(Object.keys(lift.initial_fields||{}).length){const names={RelativeScale3D:'масштаб',PointLinks:'точки связи'};card.append(el('p','Из начальных настроек клиента: '+Object.keys(lift.initial_fields).map(name=>names[name]||name).join(', ')+'. Явные значения размещения имеют приоритет.','muted'),link('Источники начальных настроек','../navigation-study/lift-blueprints/initial-values.json'));}
  const fmt=p=>p.map(v=>Number(v).toLocaleString('ru',{maximumFractionDigits:2})).join(' · ');
  card.append(el('p','Позиция корня X · Y · Z: '+fmt(lift.placement.RelativeLocation)));
  if(!lift.calculated_links.length){const names={RelativeLocation:'позиция',RelativeRotation:'вращение',RelativeScale3D:'масштаб',PointLinks:'точки связи','PointLinks endpoints':'концы связи'};card.append(el('p','Связь не рассчитана. Не заданы явно: '+lift.missing.map(name=>names[name]||name).join(', ')+'. Для этих параметров начальные значения ещё не подтверждены.','muted'));}
  for(const edge of lift.calculated_links){
    card.append(el('h3','Расчётные точки A и B'),el('p','A · X · Y · Z: '+fmt(edge.left)),el('p','B · X · Y · Z: '+fmt(edge.right)),
      el('p','Разница высоты Z: '+(edge.right[2]-edge.left[2]).toLocaleString('ru',{maximumFractionDigits:2})+' ед. клиента'),
      el('p','Направление в данных: '+({0:'в обе стороны',1:'A → B',2:'B → A'}[edge.direction]||'не задано')+'. Условия включения лифта ещё не проверены.','muted'));
  }
  card.append(el('p','Класс: '+lift.class_name,'muted'),link('Расчёты и источники','lift-preview.json'));
  const raw=el('details');raw.append(el('summary','Исходные записи'),el('pre',JSON.stringify(lift,null,2)));card.append(raw);
  const points=liftPoints(lift);fitPoints(points);
  const panelWidth=$('selection').getBoundingClientRect().width,available=dimensions.width-panelWidth-40;
  if(available>300){
    const bounds=model.extent(points,scene.projection.world_bounds);
    view.s=Math.min((available-60)/Math.max(bounds[2]-bounds[0],4000),(dimensions.height-65)/Math.max(bounds[3]-bounds[1],4000));
    view.x=(bounds[0]+bounds[2])/2+(dimensions.width-available)/(2*view.s);
  }
  schedule();updateUrl();
}
function draw() {
  if (!scene) return;
  dimensions = canvas.getBoundingClientRect();
  const ratio = Math.min(devicePixelRatio || 1, 2);
  const width = Math.round(dimensions.width * ratio), height = Math.round(dimensions.height * ratio);
  if (canvas.width !== width || canvas.height !== height) { canvas.width = width; canvas.height = height; }
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0); ctx.clearRect(0, 0, dimensions.width, dimensions.height);
  background(); drawNavigation(); drawPolygons();
  groups = model.clusters(visible, view, dimensions.width, dimensions.height);
  groups.sort((a, b) => priority(b.type) - priority(a.type));
  const labels = [], obstacles = [];
  for (const g of groups) {
    const count = g.points.length, p = g.points[0], isSelected = g.points.includes(selected);
    const radius = count > 1 ? Math.min(14, 8 + Math.log10(count) * 2) : g.type === 'Area' ? 4 : 4.5;
    ctx.fillStyle = colors[g.type]; ctx.strokeStyle = '#0d1420'; ctx.lineWidth = 1.3;
    if (g.type === 'Waypoint' && count === 1) {
      const image = imageForIcon(p.icon_id);
      ctx.beginPath(); ctx.arc(g.x, g.y, 12, 0, Math.PI * 2); ctx.fillStyle = '#181423de'; ctx.fill();
      if (image) ctx.drawImage(image, g.x - 14, g.y - 14, 28, 28);
      else { ctx.strokeStyle = colors.Waypoint; ctx.strokeRect(g.x - 6, g.y - 6, 12, 12); }
    } else {
      ctx.globalAlpha = g.type === 'NpcSpawn' && count === 1 ? .78 : .96;
      ctx.beginPath(); ctx.arc(g.x, g.y, radius, 0, Math.PI * 2); ctx.fill(); ctx.stroke(); ctx.globalAlpha = 1;
      if (count > 1) { ctx.fillStyle = '#0c1725'; ctx.font = 'bold 10px system-ui'; ctx.textAlign = 'center'; ctx.fillText(count > 999 ? (count / 1000).toFixed(1) + 'k' : String(count), g.x, g.y + 3.5); ctx.textAlign = 'left'; }
    }
    if (isSelected) { ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(g.x, g.y, radius + 6, 0, Math.PI * 2); ctx.stroke(); }
    const markerRadius=g.type==='Waypoint'&&count===1?14:radius;
    obstacles.push({x:g.x-markerRadius,y:g.y-markerRadius,width:markerRadius*2,height:markerRadius*2});
    if (g.type === 'Area' && $('labels').checked) labels.push({group:g,radius:radius+4,selected:isSelected});
  }
  ctx.font = '12px system-ui';
  const candidates=labels.map(({group:g,radius,selected})=>{
    let text=g.points[0].label;
    if(ctx.measureText(text).width>245){while(text.length&&ctx.measureText(text+'…').width>245)text=text.slice(0,-1);text+='…';}
    return {key:g.points[0].key,x:g.x,y:g.y,width:ctx.measureText(text).width+12,height:22,text,radius,selected};
  });
  if(!$('selection').hidden){const card=$('selection').getBoundingClientRect();obstacles.push({x:card.left-dimensions.left,y:card.top-dimensions.top,width:card.width,height:card.height});}
  const placed=model.placeLabels(candidates,dimensions.width,dimensions.height,obstacles),byKey=new Map(candidates.map(label=>[label.key,label]));
  ctx.strokeStyle='#ffe7b577';ctx.lineWidth=1;
  for(const box of placed){
    const label=byKey.get(box.key),x=Math.max(box.x,Math.min(label.x,box.x+box.width)),y=Math.max(box.y,Math.min(label.y,box.y+box.height));
    if(Math.hypot(label.x-x,label.y-y)>20){ctx.beginPath();ctx.moveTo(label.x,label.y);ctx.lineTo(x,y);ctx.stroke();}
  }
  for(const box of placed){
    ctx.fillStyle='#151718ed';ctx.fillRect(box.x,box.y,box.width,box.height);
    ctx.fillStyle='#ffe7b5';ctx.fillText(byKey.get(box.key).text,box.x+6,box.y+15);
  }
  drawRelation(); drawLiftPreview(); drawSpecialNavigation(); drawSession();
  $('viewScale').textContent = 'Масштаб ' + Math.round(view.s / (dimensions.height / 615000) * 100) + '% · ' + groups.length + ' отметок в окне'+($('labels').checked?' · названий '+placed.length+' из '+candidates.length:'');
}
function focus(p) {
  selectedNavSpecial=null;
  selectedLift = null;
  if (!p) return;
  if($('directLootOnly').checked && !(p.type==='NpcSpawn' && p.loot_count>0)){$('directLootOnly').checked=false;update();}
  if ($('worlds').value !== 'all' && $('worlds').value !== p.world_id) $('worlds').value = p.world_id;
  if (!visible.includes(p)) { $('search').value = ''; if ((npcFilter && (p.type !== 'NpcSpawn' || !npcFilter.has(p.npc_id))) || (areaFilter && (p.type !== 'Area' || !areaFilter.has(p.id)))) { itemId = ''; npcFilter = null; areaFilter = null; $('lootItem').value = ''; $('lootStatus').textContent = 'Фильтр снят для просмотра связанной точки.'; } update(); }
  if (!types.has(p.type)) { types.add(p.type); document.querySelector('[data-layer="' + p.type + '"]').checked = true; update(); }
  selected = p; view.x = p.x; view.y = p.y;
  view.s = Math.max(view.s, Math.min(dimensions.width, dimensions.height) / 65000);
  showPoint(p).catch(fail); schedule(); updateUrl();
}
function rawWorld(id) {
  if (!worldCache.has(id)) { const w = worldById.get(id); worldCache.set(id, json(w.file, w.sha256)); }
  return worldCache.get(id);
}
function addTasks(card, p) {
  const tasks = p.type === 'Area' ? areaTaskIndex.get(p.id) : p.type === 'WorldSpot' ? spotTaskIndex.get(p.id) : null;
  if (!tasks?.length) return;
  const details = el('details'), title = el('summary', 'Связанные квестовые задачи · ' + tasks.length); details.append(title);
  let limit = 15;
  const list = el('div'); details.append(list);
  function render() {
    list.replaceChildren();
    for (const task of tasks.slice(0, limit)) {
      const button = el('button', task.label + ' · ' + task.task_label, 'member');
      button.onclick = () => { const target = pointByKey.get('QuestTask:' + task.id); if (target) focus(target); };
      button.disabled = !pointByKey.has('QuestTask:' + task.id); list.append(button);
    }
    if (limit < tasks.length) { const more = el('button', 'Ещё задачи'); more.onclick = () => { limit += 30; render(); }; list.append(more); }
  }
  render(); card.append(details);
}
async function monsterDetails(id) {
  if (!monsterManifest) monsterManifest = json('monster-manifest.json');
  const manifest = await monsterManifest, spec = manifest.files[id];
  if (!spec) return null;
  if (!monsterCache.has(id)) monsterCache.set(id, json(spec.file, spec.sha256));
  return monsterCache.get(id);
}
async function areaRewards() {
  if (!areaRewardsPending) areaRewardsPending = (async () => {
    if (!monsterManifest) monsterManifest = json('monster-manifest.json');
    const manifest = await monsterManifest;
    return json(manifest.area_file.file, manifest.area_file.sha256);
  })();
  return areaRewardsPending;
}
const renderMonsterFacts=MonsterCard.renderFacts;
let rewardTooltip;
function rewardHint(anchor, item, id, chains, areaCandidate) {
  let hideTimer, ownedTip;
  const label = item?.label || id;
  const text = [label, item?.rarity?.label, 'ID '+id,
    areaCandidate ? 'Награды области' : 'Личные записи NPC',
    'Количество: '+(chains.length ? model.dropAmounts(chains).join(' / ') : 'не установлено'),
    'Шанс в процентах не установлен.',
    item?.icon?.images?.some(image=>image.color_verified===false)?'Цвет иконки ещё не сверен с Android.':null].filter(Boolean).join('\n');
  anchor.setAttribute('aria-label', text);
  function hide(){clearTimeout(hideTimer);ownedTip?.remove();if(rewardTooltip===ownedTip)rewardTooltip=null;ownedTip=null;anchor.removeAttribute('aria-describedby');}
  function deferHide(){hideTimer=setTimeout(hide,120);}
  function show(){
    clearTimeout(hideTimer);
    rewardTooltip?.remove();
    const tip=el('div',undefined,'reward-tooltip');tip.id='reward-tooltip';tip.setAttribute('role','tooltip');
    tip.append(el('strong',label),el('p',text.split('\n').slice(1).join('\n')));
    if(chains.length){
      const source=el('details');source.append(el('summary','Исходные данные · JSON'),el('pre',JSON.stringify(chains,null,2)));tip.append(source);
    }
    if(!item?.icon?.images?.length)tip.append(el('p','Иконка не найдена'));
    if(item?.icon?.status==='ambiguous_paths')tip.append(el('p','Ресурс иконки неоднозначен'));
    document.body.append(tip);rewardTooltip=tip;ownedTip=tip;anchor.setAttribute('aria-describedby',tip.id);
    tip.addEventListener('mouseenter',()=>clearTimeout(hideTimer));tip.addEventListener('mouseleave',deferHide);
    tip.addEventListener('focusin',()=>clearTimeout(hideTimer));
    tip.addEventListener('focusout',event=>{if(!tip.contains(event.relatedTarget)&&event.relatedTarget!==anchor)deferHide();});
    tip.addEventListener('keydown',event=>{if(event.key==='Escape'){hide();anchor.focus();hide();}});
    const box=anchor.getBoundingClientRect(), width=tip.getBoundingClientRect().width;
    tip.style.left=Math.max(8,Math.min(box.left,innerWidth-width-8))+'px';
    const below=innerHeight-box.bottom-12, above=box.top-12;
    tip.style.maxHeight=Math.max(80,Math.min(360,Math.max(below,above)))+'px';
    if(below>=Math.min(240,above))tip.style.top=(box.bottom+6)+'px';else tip.style.bottom=(innerHeight-box.top+6)+'px';
  }
  anchor.addEventListener('mouseenter',show);anchor.addEventListener('mouseleave',deferHide);
  anchor.addEventListener('focus',show);anchor.addEventListener('blur',event=>{if(!ownedTip?.contains(event.relatedTarget))deferHide();});
  anchor.addEventListener('click',hide);anchor.addEventListener('keydown',event=>{if(event.key==='Escape')hide();});
}
function renderLoot(card, p, detail = null, areaCandidate = false, showNotice = true) {
  const links = areaCandidate ? Object.entries(detail.drops || {}).map(([item_id, chains]) => ({ item_id, chains: chains.length, item: scene.items[item_id] })) : model.itemsForNpc(scene, p.npc_id);
  links.sort((a, b) => ItemRarity.compare(a.item, b.item));
  if (!links.length) { const empty=el('p','Личные предметные награды не найдены.','muted');empty.title='В доступных клиентских строках предметы для этого NPC не найдены. Это не доказывает отсутствие дропа в игре.';card.append(empty);return; }
  const grid = el('div', undefined, 'reward-icons'); card.append(grid); let limit = 30;
  const more = el('button', 'Показать ещё предметы'); card.append(more);
  function render() {
    grid.replaceChildren();
    for (const row of links.slice(0, limit)) {
      const item = row.item;
      const a = link('', '../loot/items.html?item=' + row.item_id);a.className='reward-icon';
      for (const image of (item?.icon?.images || []).slice(0,1)) {
        const slot = el('span', undefined, 'item-icon'), img = el('img');
        const backgrounds = item?.rarity?.background?.images || [];
        if (backgrounds.length === 1) slot.style.backgroundImage = 'url("../../' + backgrounds[0].file + '")';
        img.src = '../../' + image.file; img.alt = item.label; img.loading = 'lazy'; slot.append(img); a.append(slot);
      }
      if(!item?.icon?.images?.length)a.append(el('span','?','reward-missing'));
      const chains = detail?.drops?.[row.item_id] || [];
      rewardHint(a,item,row.item_id,chains,areaCandidate);grid.append(a);
    }
    more.hidden = limit >= links.length;
  }
  more.onclick = () => { limit += 24; render(); }; render();
  if(showNotice)card.append(el('p', 'RewardRate / Rate — исходные единицы. Шанс в процентах не установлен.', 'muted'));
}
async function showPoint(p) {
  rewardTooltip?.remove(); rewardTooltip=null;
  const epoch = ++cardEpoch; $('selection').hidden = false;
  let monster = null;
  const card = $('card'); card.replaceChildren(el('h2', p.type === 'NpcSpawn' ? 'Ур. ' + (p.level || '—') + ' ' + p.label : p.label));
  if (p.type !== 'NpcSpawn') {
    card.append(el('p', layerNames[p.type] + ' · ' + p.id, 'muted'), el('p', 'Мир ' + p.world_id + ' · X ' + Math.round(p.x) + ' · Y ' + Math.round(p.y), 'muted'));
    card.append(link('Мир отдельно', 'world.html?world=' + p.world_id));
  }
  if (p.type === 'NpcSpawn') {
    card.append(el('p', 'NPC ' + p.npc_id + ' · мир ' + p.world_id, 'muted'));
    card.append(link('Открыть страницу NPC','monsters.html?npc='+encodeURIComponent(p.npc_id)));
    const loading = el('p', 'Загрузка дропа и характеристик…', 'muted'); card.append(loading);
    const detail = await monsterDetails(p.npc_id); if (epoch !== cardEpoch) return; loading.remove();
    monster = detail;
    MonsterCard.renderPortraits(card,detail.portraits,p.npc_id,p.label);
    renderMonsterFacts(card, detail, false, false, false);
    const candidate = model.areaCandidate(detail, p);
    const clientScope = detail.drop_ui_selection_verified ? model.clientRewardScope(p) : null;
    const personalCount = model.itemsForNpc(scene, p.npc_id).length;
    const rewardAmounts=el('div',undefined,'npc-reward-amounts');
    for(const [label,rewards] of [['Награды NPC',detail.rewards],['Награды области',candidate?.rewards]]){
      if(!rewards?.some(r=>r.type_name!=='ERewardType::Item'&&r.type_name!=='ERewardType::RewardGroup'))continue;
      const group=el('div');group.append(el('small',label));
      group.title=label==='Награды области'?(clientScope==='area'?'AreaReward: связь подтверждена кодом окна наград; серверная выдача не проверена.':'Совпадение ID области; применение к убийству не подтверждено.'):'NpcReward; серверная выдача не проверена.';
      renderMonsterFacts(group,{rewards},true,false);rewardAmounts.append(group);
    }
    card.insertBefore(rewardAmounts,card.querySelector('details'));
    const loot = el('div', undefined, 'npc-loot-block');
    if(personalCount)loot.append(el('h3', 'Дроп NPC · '+personalCount));
    renderLoot(loot, p, detail, false, false); card.append(loot);
    if (candidate) {
      const section = el('div', undefined, 'npc-loot-block'), sectionBody = el('div');
      const count = Object.keys(candidate.drops || {}).length;
      const heading=el('h3','Награды области · '+count);section.append(heading, sectionBody); card.append(section);
      const area = scene.points.find(point => point.type === 'Area' && point.id === p.area_id);
      heading.title=(area?.label || p.area_id)+(clientScope==='area'?' · AreaReward: связь подтверждена кодом окна наград.':' · совпадение ID области; применение к убийству не подтверждено.');
      renderLoot(sectionBody, p, candidate, true, false);
    }
    const notes = el('details', undefined, 'npc-fold'); notes.append(el('summary', 'Источники и ограничения'));
    notes.append(el('p', 'Данные клиента: серверная выдача, условия и гарантированность наград не проверены. RewardRate / Rate — исходные единицы; шанс в процентах не установлен.', 'muted'));
    if(clientScope)notes.append(el('p',clientScope==='area'?'Окно наград использует AreaReward области '+p.area_id+'. Личные записи NPC показаны отдельно.':'Окно наград использует личные записи NpcReward.','muted'));
    notes.append(link('Полная добыча и условия NPC', '../loot/index.html?npc=' + p.npc_id)); card.append(notes);
    const actions = el('div', undefined, 'npc-actions');
    actions.append(link('Мир отдельно', 'world.html?world=' + p.world_id + '&npc=' + p.npc_id + '&spawn=' + p.id)); card.append(actions);
    const placements = scene.points.filter(point => point.type === 'NpcSpawn' && point.npc_id === p.npc_id);
    const positions = el('details'); positions.append(el('summary', 'Размещения на Nocturne · ' + placements.length));
    for (const point of placements) { const button = el('button', 'Мир ' + point.world_id + ' · ' + point.id + ' · X ' + Math.round(point.x) + ' / Y ' + Math.round(point.y), 'member'); button.onclick = () => focus(point); positions.append(button); }
    card.append(positions);
  }
  if (p.type === 'Area') {
    const data = await areaRewards(); if (epoch !== cardEpoch) return;
    const candidate = data.areas[p.id];
    if (candidate) {
      card.append(el('p', 'Записи AreaReward с ID этой области. Не доказано, что они применяются к каждому монстру или каждому убийству.', 'muted'));
      renderMonsterFacts(card, { rewards: candidate.rewards }, true); renderLoot(card, p, candidate, true);
    }
    if (p.anchor !== 'MapIconXY') card.append(el('p', 'Позиция подписи: ' + p.anchor, 'muted'));
    const portal = scene.points.find(g => g.type === 'Waypoint' && g.waypoint_ids.includes(p.waypoint_id));
    if (portal) { const b = el('button', 'Показать портал области'); b.onclick = () => focus(portal); card.append(b); }
  }
  for (const edge of model.portalDestination(scene, p)) {
    const d = edge.destination;
    card.append(el('h3', 'Портал ' + edge.id));
    card.append(el('p', 'Стоимость: ' + (edge.record.CostValue || '0') + ' ' + (edge.record.CostParam || ''), 'muted'));
    if (d) {
      card.append(el('p', 'Прибытие: Spot ' + d.Id + ' · мир ' + d.WorldInfoId, 'muted'));
      const target = pointByKey.get('WorldSpot:' + d.Id), b = el('button', 'Показать точку прибытия');
      b.onclick = () => focus(target); b.disabled = !target; card.append(b);
    }
    card.append(el('p', 'Доступность и условия активации не вычислены. Линия связи не является маршрутом.', 'muted'));
  }
  if (p.type === 'QuestTask') {
    card.append(el('p', p.task_label || '', 'muted'));
    const target = pointByKey.get('WorldSpot:' + p.target_spot_id);
    if (target) { const b = el('button', 'Целевая мировая точка'); b.onclick = () => focus(target); card.append(b); }
  }
  addTasks(card, p);
  const source = el('details'), summary = el('summary', 'Исходная запись и условия'), pre = el('pre', 'Загрузка…'); source.append(summary, pre); card.append(source);
  const world = await rawWorld(p.world_id); if (epoch !== cardEpoch) return;
  const table = p.type === 'Waypoint' ? 'GadgetSpawn' : p.type;
  const row = world[table]?.find(r => r.Id === p.id);
  if (p.type === 'NpcSpawn' && row) {
    const conditions = el('p', 'Радиус размещения: ' + (row.Radius || '0') + ' · перемещения: ' + (row.MoveRadius || '0')
      + (row.VisibleOnQuestTaskInfoId && row.VisibleOnQuestTaskInfoId !== '0' ? ' · видимость связана с задачей ' + row.VisibleOnQuestTaskInfoId : '')
      + (row.VisibleOffQuestTaskInfoId && row.VisibleOffQuestTaskInfoId !== '0' ? ' · скрытие связано с задачей ' + row.VisibleOffQuestTaskInfoId : ''), 'muted');
    const placement = el('details', undefined, 'npc-fold'); placement.append(el('summary', 'Условия размещения'), conditions);
    card.insertBefore(placement, source);
  }
  pre.textContent = JSON.stringify({ coordinate_anchor: p.anchor, ...row,
    ...(monster ? { battle: monster.battle, npc_reward_rows: monster.rewards, area_reward_candidate: monster.area_candidates?.[p.area_id] } : {}),
    labels_source: p.type === 'Area' ? scene.localizations.areas[p.id] : scene.localizations.npcs[p.npc_id],
    ...(p.type === 'NpcSpawn' ? { npc: world.Npc[p.npc_id] } : {}),
    ...(p.gadget_id ? { gadget: world.Gadget[p.gadget_id] } : {}),
    ...(p.type === 'Waypoint' ? { waypoints: model.portalDestination(scene, p) } : {}) }, null, 2);
}
function showGroup(group) {
  selectedNavSpecial=null;
  if (group.type === 'NpcSpawn') {
    const choices = model.monsterChoices(group.points);
    if (choices.length === 1) { focus(choices[0].points[0]); return; }
    ++cardEpoch; $('selection').hidden = false; $('card').replaceChildren(el('h2', 'Выберите монстра · ' + choices.length));
    $('card').append(el('p', 'Нажмите на монстра, чтобы открыть его дроп, характеристики и размещения.', 'muted'));
    for (const choice of choices) {
      const p = choice.points[0], button = el('button', p.label + ' · ур. ' + (p.level || '—'), 'member');
      button.append(el('small', 'NPC ' + p.npc_id + ' · предметов ' + (p.loot_count || 0) + ' · записей в группе ' + choice.points.length));
      button.onclick = () => focus(p); $('card').append(button);
    }
    return;
  }
  if (group.points.length === 1) { focus(group.points[0]); return; }
  ++cardEpoch; $('selection').hidden = false; $('card').replaceChildren(el('h2', group.points.length + ' записей рядом'));
  $('card').append(el('p', 'Близкие отметки объединены для текущего масштаба. Каждая запись сохраняет свой мир и ID.', 'muted'));
  const b = el('button', 'Приблизить эту группу'); b.onclick = () => { fitPoints(group.points); $('selection').hidden = true; }; $('card').append(b);
  let limit = 40; const list = el('div'); $('card').append(list);
  function render() {
    list.replaceChildren();
    for (const p of group.points.slice(0, limit)) { const button = el('button', p.label + ' · мир ' + p.world_id + ' · ' + p.id, 'member'); button.onclick = () => focus(p); list.append(button); }
    if (limit < group.points.length) { const more = el('button', 'Ещё записи'); more.onclick = () => { limit += 60; render(); }; list.append(more); }
  }
  render();
}
async function applyItem() {
  if (!scene) return;
  let value = $('lootItem').value.trim();
  let id = scene.items[value] ? value : Object.keys(scene.items).find(k => k + ' · ' + scene.items[k].label === value);
  if (!value) { clearItem(); return; }
  if (!id) { $('lootStatus').textContent = 'Выберите предмет из подсказок или введите его ID.'; return; }
  itemId = id; $('lootItem').value = id + ' · ' + scene.items[id].label;
  if ($('rewardScope').value === 'area') {
    $('directLootOnly').checked=false;
    const data = await areaRewards();
    if (itemId !== id || $('rewardScope').value !== 'area') return;
    npcFilter = null; areaFilter = new Set(data.item_areas[id] || []); types.add('Area'); document.querySelector('[data-layer="Area"]').checked = true;
    const all = scene.points.filter(p => p.type === 'Area' && areaFilter.has(p.id));
    $('lootStatus').textContent = scene.items[id].label + ' · записи AreaReward: ' + all.length + ' областей на карте. Список клиента; серверная выдача и проценты не проверены.';
  } else {
  areaFilter = null; npcFilter = new Set(scene.item_npcs[id] || []); types.add('NpcSpawn'); document.querySelector('[data-layer="NpcSpawn"]').checked = true;
  const all = scene.points.filter(p => p.type === 'NpcSpawn' && npcFilter.has(p.npc_id));
  $('lootStatus').textContent = scene.items[id].label + ' · на Nocturne: ' + new Set(all.map(p => p.npc_id)).size + ' NPC / ' + all.length + ' записей / ' + new Set(all.map(p => p.world_id)).size + ' миров. Шанс не установлен.';
  }
  $('itemCatalog').href = '../loot/items.html?item=' + id; $('search').value = ''; selected = null; $('selection').hidden = true; ++cardEpoch;
  update(true);
}
function clearItem() { itemId = ''; npcFilter = null; areaFilter = null; $('lootItem').value = ''; $('lootStatus').textContent = 'Фильтр наград снят. Проценты выпадения не установлены.'; $('itemCatalog').href = '../loot/index.html'; update(); }
async function renderSelectedSkill(id,entry){
  const epoch=++skillEpoch,panel=$('selectedSkill');panel.hidden=false;panel.replaceChildren(el('p','Загрузка навыка…'));
  try{
    const skill=entry?.detail?await json(entry.detail.file,entry.detail.sha256):{id};
    if(epoch!==skillEpoch||id!==skillId)return;
    const header=el('div',undefined,'skillNavigation'),back=el('button','Вернуться к карте');
    back.onclick=()=>{clearSkill();$('mapFrame').scrollIntoView({block:'start'});canvas.focus({preventScroll:true});};
    header.append(el('h2','Навык'),back);panel.replaceChildren(header);
    const count=entry?.npc_ids.length||0,actions=el('div',undefined,'skillNavigation');
    if(count||skillFilter){const show=el('button',skillFilter?'Снять фильтр NPC':'Показать NPC с этим навыком · '+count);
      show.onclick=async()=>{if(skillFilter){clearSkill();fitPoints(visible,$('worlds').value==='all'&&!itemId);}else await applySkill(id,false,true);$('mapFrame').scrollIntoView({block:'start'});canvas.focus({preventScroll:true});};actions.append(show);}
    else actions.append(el('p','Связанные NPC на Nocturne не найдены. Просмотр навыка не скрывает отметки карты.','muted'));
    panel.append(actions);
    panel.append(el('h3',(entry?.display_names||[]).map(n=>n.text).join(' / ')||'Навык '+id),link('Открыть полную карточку навыка','skills.html?skill='+encodeURIComponent(id)));
  }catch(error){if(epoch===skillEpoch)panel.replaceChildren(el('p','Не удалось загрузить карточку навыка: '+error.message));}
}
async function skillIndex(){
  if(!skillIndexPending)skillIndexPending=(async()=>{
    if(!monsterManifest)monsterManifest=await json('monster-manifest.json');
    if(!monsterManifest.skill_index)throw Error('Индекс навыков не собран');
    const data=await json(monsterManifest.skill_index.file,monsterManifest.skill_index.sha256);
    for(const skill of Object.values(data.skills)){
      const option=el('option');option.value=skill.id+' · '+(skill.display_names.map(n=>n.text).join(' / ')||'Навык '+skill.id);
      $('skillOptions').append(option);
    }
    $('skillSearch').disabled=false;return data;
  })().catch(error=>{skillIndexPending=null;throw error;});
  return skillIndexPending;
}
async function applySkill(value=$('skillSearch').value,resetWorld=true,filterNpcs=false){
  const data=await skillIndex(),input=value.trim();
  if(!input){clearSkill();return;}
  const id=data.skills[input]?input:Object.keys(data.skills).find(id=>id+' · '+(data.skills[id].display_names.map(n=>n.text).join(' / ')||'Навык '+id)===input);
  if(!id&&!/^\d+$/.test(input)){$('skillStatus').textContent='Выберите навык из подсказок или введите его ID.';return;}
  if(!filterNpcs){location.assign('skills.html?skill='+encodeURIComponent(id||input));return;}
  skillId=id||input;skillFilter=filterNpcs?new Set(data.skills[skillId]?.npc_ids||[]):null;
  $('skillSearch').value=id?id+' · '+(data.skills[id].display_names.map(n=>n.text).join(' / ')||'Навык '+id):input;
  if(filterNpcs){$('search').value='';if(resetWorld)$('worlds').value='all';types.add('NpcSpawn');document.querySelector('[data-layer="NpcSpawn"]').checked=true;}
  selected=null;++cardEpoch;$('selection').hidden=true;update(filterNpcs);
  await renderSelectedSkill(skillId,data.skills[skillId]);
  if(!filterNpcs&&resetWorld)$('selectedSkill').scrollIntoView({block:'start'});
}
function clearSkill(){++skillEpoch;$('selectedSkill').hidden=true;skillId='';skillFilter=null;$('skillSearch').value='';$('skillStatus').textContent='Карточка закрыта. Фильтр навыка выключен.';update();}
function nearest(x, y) {
  let found = null, best = 20;
  for (const g of groups) { const d = Math.hypot(g.x - x, g.y - y); if (d < best) { best = d; found = g; } }
  return found;
}
let drag = null, distance = 0;
canvas.onpointerdown = e => { canvas.setPointerCapture(e.pointerId); drag = [e.clientX, e.clientY]; distance = 0; };
canvas.onpointermove = e => {
  const rect = canvas.getBoundingClientRect(), x = e.clientX - rect.left, y = e.clientY - rect.top;
  if (drag) { const dx = e.clientX - drag[0], dy = e.clientY - drag[1]; distance += Math.abs(dx) + Math.abs(dy); view.x -= dx / view.s; view.y -= dy / view.s; drag = [e.clientX, e.clientY]; schedule(); }
  const g = nearest(x, y);
  $('hover').textContent = g ? g.points[0].label + (g.points.length > 1 ? ' · записей ' + g.points.length : '') : 'X ' + Math.round((x - rect.width / 2) / view.s + view.x) + ' · Y ' + Math.round((y - rect.height / 2) / view.s + view.y);
};
canvas.onpointerup = e => { drag = null; if (distance > 5) return; const r = canvas.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top,lift=nearestLift(x,y);if(lift){focusLift(lift);return;}const g = nearest(x,y); if (g)showGroup(g);else if(navOverlay&&$('navSpecialLayer')?.checked)focusNavSpecial(NavOverlayModel.nearestSpecial(navOverlay.special_links||[],view,dimensions.width,dimensions.height,x,y)); };
canvas.onpointercancel = () => { drag = null; };
function zoom(factor, anchor) {
  const r = canvas.getBoundingClientRect(), x = anchor ? anchor[0] - r.width / 2 : 0, y = anchor ? anchor[1] - r.height / 2 : 0;
  const old = view.s; view.s = Math.min(.3, Math.max(Math.min(r.width, r.height) / 1500000, view.s * factor));
  view.x += x / old - x / view.s; view.y += y / old - y / view.s; schedule();
}
canvas.addEventListener('wheel', e => { e.preventDefault(); const r = canvas.getBoundingClientRect(); zoom(Math.exp(-e.deltaY * .0015), [e.clientX - r.left, e.clientY - r.top]); }, { passive: false });
canvas.onkeydown = e => {
  const amount = 55 / view.s;
  if (e.key === 'ArrowLeft') view.x -= amount; else if (e.key === 'ArrowRight') view.x += amount;
  else if (e.key === 'ArrowUp') view.y -= amount; else if (e.key === 'ArrowDown') view.y += amount;
  else if (e.key === '+' || e.key === '=') zoom(1.5); else if (e.key === '-') zoom(1 / 1.5);
  else if (e.key === 'Home') fitPoints([], true); else if (e.key === 'Escape') $('selection').hidden = true; else return;
  e.preventDefault(); schedule();
};
$('whole').onclick = () => fitPoints([], true); $('fit').onclick = () => fitPoints(visible);
$('plus').onclick = () => zoom(1.6); $('minus').onclick = () => zoom(1 / 1.6);
$('worlds').onchange = () => { selected = null;selectedLift=null; ++cardEpoch; $('selection').hidden = true; update($('worlds').value !== 'all'); if ($('worlds').value === 'all') fitPoints(visible, !skillFilter&&!itemId); };
$('search').oninput = () => update(); $('searchAll').onchange = () => update(); $('search').onkeydown = e => { if (e.key === 'Enter') fitPoints(visible); };
$('directLootOnly').onchange = () => {
  if($('directLootOnly').checked){
    $('worlds').value='all';$('search').value='';types.add('NpcSpawn');document.querySelector('[data-layer="NpcSpawn"]').checked=true;
    if(areaFilter){areaFilter=null;itemId='';$('lootItem').value='';}
  }
  selected=null;++cardEpoch;$('selection').hidden=true;update(true);
};
$('fitSearch').onclick = () => fitPoints(visible); $('more').onclick = () => { resultLimit += 100; renderList(); };
$('separateSpawns').onchange=()=>{resultLimit=60;renderList();};
$('applyLoot').onclick = () => applyItem().catch(fail); $('clearLoot').onclick = clearItem;
$('applySkill').onclick=()=>applySkill().catch(fail);$('clearSkill').onclick=clearSkill;
$('skillSearch').onkeydown=e=>{if(e.key==='Enter')applySkill().catch(fail);};
$('rewardScope').onchange = () => { if (itemId) applyItem().catch(fail); };
$('lootItem').onkeydown = e => { if (e.key === 'Enter') applyItem().catch(fail); };
$('closeCard').onclick = () => { rewardTooltip?.remove();rewardTooltip=null; ++cardEpoch; selected = null;selectedLift=null;selectedNavSpecial=null; $('selection').hidden = true; schedule(); updateUrl(); };
$('showLift').onclick=()=>focusLift(liftPreview?.lifts.find(lift=>lift.id===$('liftChoice').value)||liftPreview?.lifts.find(lift=>lift.calculated_links.length));
$('liftLayer').onchange=()=>{if(!$('liftLayer').checked&&selectedLift){selectedLift=null;$('selection').hidden=true;}schedule();updateUrl();};
async function loadNavOverlay(){
  if(!navOverlay){
    $('navStatus').textContent='Загрузка геометрии сетки…';
    try{navOverlayPending??=json(scene.navigation_overlay.file,scene.navigation_overlay.sha256).then(NavOverlayModel.validate);navOverlay=await navOverlayPending;
      $('navStatus').textContent=navOverlay.stats.tiles.toLocaleString('ru')+' ячеек · '+navOverlay.stats.surface_polygons.toLocaleString('ru')+' полигонов.';
      if($('navSpecialChoice')?.options.length===1)for(const p of navOverlay.special_links||[]){const option=el('option',p.label);option.value=p.id;$('navSpecialChoice').append(option);}
    }catch(error){navOverlayPending=null;throw error;}
  }
  return navOverlay;
}
async function toggleNavOverlay(){
  if(!$('navLayer').checked&&!$('navSpecialLayer')?.checked){if(selectedNavSpecial){selectedNavSpecial=null;$('selection').hidden=true;}schedule();updateUrl();return;}
  try{await loadNavOverlay();if(!$('navSpecialLayer')?.checked&&selectedNavSpecial){selectedNavSpecial=null;$('selection').hidden=true;}schedule();updateUrl();}
  catch(error){$('navLayer').checked=false;if($('navSpecialLayer'))$('navSpecialLayer').checked=false;$('navStatus').textContent='Сетка не загружена: '+error.message;}
}
if($('navLayer'))$('navLayer').onchange=toggleNavOverlay;
if($('navSpecialLayer'))$('navSpecialLayer').onchange=toggleNavOverlay;
if($('showNavSpecial'))$('showNavSpecial').onclick=async()=>{try{await loadNavOverlay();focusNavSpecial(navOverlay.special_links?.find(p=>p.id===$('navSpecialChoice').value)||navOverlay.special_links?.[0]);}catch(error){$('navStatus').textContent=error.message;}};
for (const id of ['labels', 'worldBounds', 'areaBounds', 'relations']) $(id).onchange = schedule;
$('share').onclick = async () => { try { await navigator.clipboard.writeText(location.href); $('share').textContent = 'Ссылка скопирована'; } catch { $('status').textContent = location.href; } };
window.addEventListener('resize', schedule);
(async () => {
  const requested = new URLSearchParams(location.search), manifest = await json('nocturne-manifest.json');
  $('directLootOnly').checked=requested.get('npcLoot')==='1';
  scene = await json(manifest.file, manifest.sha256);
  if(scene.navigation_overlay&&$('navPanel')){$('navPanel').hidden=false;$('navStatus').textContent=scene.navigation_overlay.stats.tiles.toLocaleString('ru')+' ячеек · '+scene.navigation_overlay.stats.surface_polygons.toLocaleString('ru')+' полигонов. Загрузка при включении.';}
  if(scene.navigation_overlay?.stats.special_links&&$('navSpecialPanel')){$('navSpecialPanel').hidden=false;$('navSpecialStatus').textContent=scene.navigation_overlay.stats.special_links+' записей · нажмите пунктир или выберите из списка.';}
  if(scene.lift_preview){
    liftPreview=await json(scene.lift_preview.file,scene.lift_preview.sha256);$('liftPanel').hidden=false;
    $('liftStatus').textContent=liftPreview.summary.lifts+' размещения · '+liftPreview.summary.calculated_links+' расчётных связей: '+liftPreview.summary.fully_explicit_lifts+' по явным значениям, '+liftPreview.summary.inherited_initial_lifts+' с начальными настройками клиента. '+(liftPreview.summary.lifts-liftPreview.summary.calculated_lifts)+' ещё не рассчитаны.';
    for(const lift of [...liftPreview.lifts].sort((a,b)=>b.calculated_links.length-a.calculated_links.length||Number(a.id)-Number(b.id))){const option=el('option',lift.label+(lift.calculated_links.length?' · связь рассчитана':' · данные неполные'));option.value=lift.id;$('liftChoice').append(option);}
  }
  for (const w of scene.worlds) {
    worldById.set(w.id, w); const option = el('option', w.id + ' · ' + (w.label.length > 75 ? w.label.slice(0, 75) + '…' : w.label)); option.value = w.id; $('worlds').append(option);
  }
  for (const p of scene.points) { pointByKey.set(p.key, p); p.search = [p.label, p.id, p.npc_id, p.quest_id, p.world_id, p.task_label].join(' ').toLowerCase(); }
  for (const task of scene.quest_links) {
    if (!areaTaskIndex.has(task.target_area_id)) areaTaskIndex.set(task.target_area_id, []); areaTaskIndex.get(task.target_area_id).push(task);
    if (!spotTaskIndex.has(task.target_spot_id)) spotTaskIndex.set(task.target_spot_id, []); spotTaskIndex.get(task.target_spot_id).push(task);
  }
  for (const [type, name] of Object.entries(layerNames)) {
    const label = el('label'), input = el('input'); input.type = 'checkbox'; input.dataset.layer = type; input.checked = types.has(type);
    input.onchange = () => { input.checked ? types.add(type) : types.delete(type); update(); };
    label.style.color = colors[type]; label.append(input, document.createTextNode(name), el('small', scene.stats.point_types[type].toLocaleString('ru'))); $('layers').append(label);
  }
  for (const [id, item] of Object.entries(scene.items)) { const option = el('option'); option.value = id + ' · ' + item.label; $('lootItems').append(option); }
  $('totals').textContent = 'Вся карта · ' + scene.stats.worlds + ' миров · ' + scene.stats.point_types.NpcSpawn.toLocaleString('ru') + ' записей NPC · ' + scene.stats.named_areas + ' названий областей';
  const geometry=scene.geometry_audit?.summary;
  $('geometryStatus').textContent='Nocturne: '+(scene.stats.rotated_area_boxes_verified||0)+' повёрнутых контуров построены по проверенной формуле клиента вокруг центра Min/Max; '+scene.rotated_area_boxes.length+' контуров с неизвестной точкой вращения. '+(geometry?.nav_files?.['Nocturne_Nav.bin']||0)+' пар начальной и конечной точек для проверки маршрутов; проходимость пока не подтверждена. '+(geometry?.exported_nav_files===0?'В библиотеке извлечённых ресурсов файлы *_Nav.bin не найдены. ':'')+(geometry?.reference_asset_records?'В архивах найдены '+geometry.reference_asset_records+' записей RefNavMesh; их наличие ещё не подтверждает проходимость. ':'')+(geometry?.decoded_navigation_chunks?'Разобраны заголовки '+geometry.decoded_navigation_chunks+' частей Nocturne: ссылки и габариты, без полигонов прохода. ':'')+(geometry?.generated_nav_packages?'Дополнительно извлечено '+geometry.generated_nav_packages+' пакета навигационных данных; их связь с заголовком и проходимость ещё не подтверждены. ':'')+'Прямые линии и связи порталов не доказывают доступность пути.';
  if($('generatedNavReport'))$('generatedNavReport').hidden=!geometry?.generated_nav_packages;
  $('unplacedTitle').textContent = 'Исходные записи: ' + scene.unplaced.length + ' без точки · ' + scene.rotated_area_boxes.length + ' контуров с неподтверждённым поворотом · ' + scene.invalid_area_boxes.length + ' с обратными Min/Max';
  $('unplacedList').textContent = JSON.stringify({ unplaced: scene.unplaced, rotated_area_boxes: scene.rotated_area_boxes, invalid_area_boxes: scene.invalid_area_boxes }, null, 2);
  $('sources').textContent = JSON.stringify({ stats: scene.stats, sources: scene.sources, limitations: scene.limitations }, null, 2);
  preview.onload = schedule; preview.src = '../../' + scene.background.preview;
  for (const input of document.querySelectorAll('input,select')) input.disabled = false;
  if (requested.has('world')) {
    if (worldById.has(requested.get('world'))) $('worlds').value = requested.get('world');
    else { location.replace('world.html?' + requested); return; }
  }
  update(); fitPoints(visible, $('worlds').value === 'all');
  if (requested.has('item')) { $('lootItem').value = requested.get('item'); $('rewardScope').value = requested.get('rewardScope') === 'area' ? 'area' : 'npc'; await applyItem(); }
  await skillIndex();
  if(requested.has('skill'))await applySkill(requested.get('skill'),false,requested.get('skillNpc')==='1');
  const point = pointByKey.get(requested.get('point')) || pointByKey.get('NpcSpawn:' + requested.get('spawn'))
    || scene.points.find(p => p.type === 'NpcSpawn' && p.npc_id === requested.get('npc') && ($('worlds').value === 'all' || p.world_id === $('worlds').value));
  if (point && (!skillFilter || visible.includes(point))) focus(point);
  if(requested.has('lift'))focusLift(liftPreview?.lifts.find(lift=>lift.id===requested.get('lift')));
  if(requested.has('navLink')&&scene.navigation_overlay){await loadNavOverlay();focusNavSpecial(navOverlay.special_links?.find(p=>p.id===requested.get('navLink')));}
})().catch(fail);
