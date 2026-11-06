/* Shared atlas renderer. The parent adapter supplies all game state. */
(() => {
 'use strict';
 const canvas=document.getElementById('group-canvas'),ctx=canvas.getContext('2d'),image=new Image();
 const label=document.getElementById('map-world');
 const navCheck=document.getElementById('map-navigation'),layerStatus=document.getElementById('map-layer-status');
 const gear=document.getElementById('map-layers-toggle'),layerPanel=document.getElementById('map-layers-panel');
 const detailCheck=document.getElementById('map-detail'),charactersCheck=document.getElementById('map-characters'),labelsCheck=document.getElementById('map-labels');
 const npcCheck=document.getElementById('map-npcs'),npcStatus=document.getElementById('map-npc-status'),npcCount=document.getElementById('map-npc-count');
 const staticTypes=['Area','Waypoint','GadgetSpawn','WorldSpot','QuestTask'];
 const typeChecks=new Map(staticTypes.map(type=>[type,document.getElementById('layer-'+type)]));
 let layers,navigation,navPending,staticPoints,pointsPending,frame,disposed=false;
 const requests=new Set();
 const schedule=()=>{if(!disposed&&!frame)frame=requestAnimationFrame(()=>{frame=null;draw();});};
 const layerPainter=VampirAtlasLayers.create({requestDraw:schedule,resolveUrl:file=>file});
 let payload,sessions={},selected,atlas,points=[],hits=[],drag,moved=false,entryWorld,activeMap;
 let view={x:5120,y:5120,zoom:1};
 const notify=(type,data={})=>parent.postMessage({source:'vampir-group-map',type,...data},location.origin);
 const current=()=>points.find(row=>row.id===selected);
 const selectedModel=()=>VampirPrototypeLiveModel.project(sessions[selected]??null,atlas);
 function panel(open){layerPanel.hidden=!open;gear.setAttribute('aria-expanded',String(open));}
 gear.onclick=()=>panel(layerPanel.hidden);
 addEventListener('pointerdown',event=>{if(!layerPanel.hidden&&event.target!==gear&&!layerPanel.contains(event.target))panel(false);});
 addEventListener('keydown',event=>{if(event.key==='Escape'&&!layerPanel.hidden){panel(false);gear.focus();}});
 for(const control of [detailCheck,charactersCheck,labelsCheck,npcCheck])control.onchange=()=>draw();
 for(const control of typeChecks.values())control.onchange=()=>{loadPoints();draw();};
 function compatibleLayers(){
  const p=layers?.projection;
  return !!p&&!!atlas&&p.map_ids.includes(activeMap)&&p.ground_distance===atlas.ground_distance
   &&p.size.every((n,i)=>n===atlas.size[i])&&p.center.every((n,i)=>n===atlas.center[i]);
 }
 function worldView(scale){return {x:atlas.center[0]+(view.x-atlas.size[0]/2)*atlas.ground_distance/atlas.size[0],
  y:atlas.center[1]+(view.y-atlas.size[1]/2)*atlas.ground_distance/atlas.size[1],s:scale*atlas.size[0]/atlas.ground_distance};}
 async function json(file,budget,sha){
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),15000);requests.add(abort);
  try{
   const response=await fetch(file,{cache:'no-store',signal:abort.signal});
   if(!response.ok)throw Error('HTTP '+response.status);
   const bytes=await response.arrayBuffer();if(bytes.byteLength>budget)throw Error('Превышен размер слоя');
   if(sha){const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('');
    if(hash!==sha)throw Error('Изменился SHA слоя');}
   return JSON.parse(new TextDecoder().decode(bytes));
  }finally{clearTimeout(timer);requests.delete(abort);}
 }
 async function loadLayers(){
  try{
   const data=await json('atlas-layers.json',65536);
   if(data.schema!==1||data.kind!=='reference_atlas_layers'||data.navigation_ready!==false
    ||!Array.isArray(data.projection?.map_ids)||data.projection.size?.length!==2||data.projection.center?.length!==2)
     throw Error('Неизвестный формат слоёв');
   if(disposed)return;layers=data;
   for(const type of staticTypes)document.getElementById('layer-count-'+type).textContent=(layers.points?.counts?.[type]??0).toLocaleString('ru');
   update();loadPoints();
  }catch(error){if(!disposed){navCheck.disabled=true;layerStatus.textContent='Детальные слои не загружены: '+error.message;}}
 }
 async function loadPoints(){
  if(!layers?.points||![...typeChecks.values()].some(control=>control.checked))return;
  try{
   pointsPending??=json(layers.points.file,16*2**20,layers.points.sha256).then(data=>{
    if(data.schema!==1||data.kind!=='reference_atlas_points'||data.runtime_visibility_verified!==false
      ||!Array.isArray(data.points)||data.points.length>32768)throw Error('Неизвестный формат точек');
    return data;
   });
   staticPoints=await pointsPending;if(!disposed)draw();
  }catch(error){pointsPending=null;if(!disposed)layerStatus.textContent='Точки атласа не загружены: '+error.message;}
 }
 function liveNpcs(){
  const value=selectedModel();
  if(!value.entitiesKnown||!value.person)return [];
  return value.entityRows.filter(row=>row.kind==='npc'&&String(row.world_id)===String(value.person.world_id)
   &&row.position&&['x','y','z'].every(key=>Number.isFinite(row.position[key]))
   &&['server_sight_position','server_create_position'].includes(row.position_semantics));
 }
 function drawLiveNpcs(nativeView,width,height){
  if(!npcCheck.checked||npcCheck.disabled)return;
  for(const row of liveNpcs()){
   const x=(row.position.x-nativeView.x)*nativeView.s+width/2,y=(row.position.y-nativeView.y)*nativeView.s+height/2;
   if(x < -20||y < -20||x > width+20||y > height+20)continue;
   ctx.fillStyle='#84b9ef';ctx.strokeStyle='#122638';ctx.lineWidth=2;ctx.beginPath();ctx.arc(x,y,6,0,Math.PI*2);ctx.fill();ctx.stroke();
   if(labelsCheck.checked){ctx.fillStyle='#c4e4ff';ctx.font='12px system-ui';ctx.textAlign='left';ctx.fillText(row.name||'NPC '+(row.wire_id??row.key),x+9,y-5);}
  }
 }
 navCheck.onchange=async()=>{
  if(!navCheck.checked){draw();return;}
  if(!compatibleLayers()){navCheck.checked=false;return;}
  layerStatus.textContent='Загрузка навигационной сетки…';
  try{
   navPending??=json(layers.navigation.file,16*2**20,layers.navigation.sha256).then(NavOverlayModel.validate);
   navigation=await navPending;if(!disposed)draw();
  }catch(error){navPending=null;if(!disposed){navCheck.checked=false;layerStatus.textContent='Сетка не загружена: '+error.message;}}
 };
 function center(){const p=current()?.position;if(p){view={x:p.pixel_x,y:p.pixel_y,zoom:5};draw();}}
 function fit(){
  const values=points.filter(p=>p.position.map_id===activeMap).map(row=>row.position);
  if(!values.length||!atlas)return;
  const {width,height}=canvas.getBoundingClientRect(),base=Math.min(width/atlas.size[0],height/atlas.size[1]);
  const xs=values.map(p=>p.pixel_x),ys=values.map(p=>p.pixel_y),minX=Math.min(...xs),maxX=Math.max(...xs),minY=Math.min(...ys),maxY=Math.max(...ys);
  view={x:(minX+maxX)/2,y:(minY+maxY)/2,zoom:Math.min(8,Math.max(1,Math.min(width/(maxX-minX+1000),height/(maxY-minY+1000))/base))};draw();
 }
 function update(){
  if(!atlas)return;
  points=[];
  for(const [id,row] of Object.entries(sessions)){
   if(row.state!=='connected'||!row.character)continue;
   const model=VampirPrototypeLiveModel.project(row,atlas);
   const p=model.positionOrigin==='owner_projection'?row.position:VampirLocalMapProjection.project(row,atlas);
   if(p?.inside)points.push({id,name:row.character.name,world:row.character.world_id,position:p,server:[row.region,row.server??row.server_id].join(' · ')});
  }
  const row=sessions[selected],p=current();
  activeMap=p?.position.map_id;
  navCheck.disabled=!compatibleLayers();
  const model=selectedModel();npcCheck.disabled=!model.entitiesKnown;
  npcCount.textContent=model.entitiesKnown?String(liveNpcs().length):'—';
  npcStatus.textContent=model.entitiesKnown?'Позиции из сообщений окружения; роли и действия ещё не подключены':'Живое окружение ещё не подключено';
  if(layers&&!activeMap)layerStatus.textContent='Слои недоступны без известной карты персонажа';
  const key=p?JSON.stringify([p.world,p.position.map_id]):null;
  label.textContent=row?.character?'Мир '+row.character.world_id+' · '+(p?'Карта '+activeMap:'Карта ещё не подключена'):'Ожидание персонажа';
  if(key&&key!==entryWorld){entryWorld=key;center();}
  if(payload?.follow===true&&p)center();
  draw();
 }
 function draw(){
  const {width,height}=canvas.getBoundingClientRect(),ratio=devicePixelRatio||1;
  if(!width||!height)return;
  canvas.width=Math.round(width*ratio);canvas.height=Math.round(height*ratio);ctx.setTransform(ratio,0,0,ratio,0,0);hits=[];
  if(!atlas||!activeMap)return;
  const scale=Math.min(width/atlas.size[0],height/atlas.size[1])*view.zoom;
  const screen=p=>[(p.pixel_x-view.x)*scale+width/2,(p.pixel_y-view.y)*scale+height/2];
  const [left,top]=screen({pixel_x:0,pixel_y:0});
  if(compatibleLayers()){
   const nativeView=worldView(scale);
   const tiles=layerPainter.background(ctx,image,detailCheck.checked?layers.background:{...layers.background,tiles:[]},layers.projection,nativeView,width,height,ratio);
   const messages=[];
   if(detailCheck.checked&&tiles.detailed)messages.push('Детальные части карты: '+tiles.loaded+'/'+tiles.visible+'.');
   if(navCheck.checked&&navigation){
    const visible=layerPainter.navigation(ctx,navigation,nativeView,width,height);
    messages.push(navigation.stats.tiles.toLocaleString('ru')+' ячеек · '+navigation.stats.surface_polygons.toLocaleString('ru')
     +' полигонов · в окне '+visible.toLocaleString('ru')+'. Все высоты вместе; проходимость в игре не проверена.');
   }else if(!navCheck.checked)messages.push('Сетка загружается при включении.');
   if(staticPoints){
    const types=new Set([...typeChecks].filter(([,control])=>control.checked).map(([type])=>type));
    const shown=layerPainter.points(ctx,staticPoints,nativeView,width,height,{worldId:sessions[selected]?.character?.world_id,
     types,labels:labelsCheck.checked?new Set(['Area']):false});
    messages.push('Точки атласа в окне: '+shown.visible+'. Доступность действий ещё не проверена.');
   }
   drawLiveNpcs(nativeView,width,height);layerStatus.textContent=messages.join(' ');
  }else{
   if(image.naturalWidth)ctx.drawImage(image,left,top,atlas.size[0]*scale,atlas.size[1]*scale);
   if(layers)layerStatus.textContent='Детальные слои не соответствуют проекции этой карты';
  }
  const groups=[];
  for(const row of points.filter(row=>charactersCheck.checked&&row.position.map_id===activeMap)){
   const [x,y]=screen(row.position),group=groups.find(g=>Math.hypot(g.x-x,g.y-y)<25);
   if(group)group.rows.push(row);else groups.push({x,y,rows:[row]});
  }
  for(const g of groups)g.rows.forEach((row,index)=>{
   const angle=index*2*Math.PI/g.rows.length-Math.PI/2,radius=g.rows.length>1?Math.max(30,g.rows.length*7):0;
   const x=g.x+Math.cos(angle)*radius,y=g.y+Math.sin(angle)*radius,active=row.id===selected;
   hits.push({x,y,row});
   if(radius){ctx.strokeStyle='#babfbc';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(g.x,g.y);ctx.lineTo(x,y);ctx.stroke();}
   ctx.fillStyle=active?'#f5ce7c':'#65d4b4';ctx.strokeStyle='#10241d';ctx.lineWidth=2;
   ctx.beginPath();ctx.arc(x,y,11,0,Math.PI*2);ctx.fill();ctx.stroke();
   ctx.fillStyle='#091b14';ctx.textAlign='center';ctx.font='bold 11px system-ui';ctx.fillText(String(index+1),x,y+4);
   ctx.fillStyle='#fff';ctx.font='12px system-ui';ctx.textAlign='left';ctx.shadowColor='#000';ctx.shadowBlur=5;
   if(labelsCheck.checked)ctx.fillText(row.name,x+15,y-8);ctx.shadowBlur=0;
  });
 }
 function zoom(factor){view.zoom=Math.max(.5,Math.min(24,view.zoom*factor));draw();}
 document.getElementById('map-fit').onclick=fit;
 document.getElementById('map-in').onclick=()=>zoom(1.4);
 document.getElementById('map-out').onclick=()=>zoom(1/1.4);
 canvas.addEventListener('wheel',event=>{event.preventDefault();zoom(Math.exp(-event.deltaY*.001));},{passive:false});
 canvas.onpointerdown=event=>{canvas.setPointerCapture(event.pointerId);drag={x:event.clientX,y:event.clientY};moved=false;};
 canvas.onpointermove=event=>{
  if(!drag||!atlas)return;
  const dx=event.clientX-drag.x,dy=event.clientY-drag.y;if(!moved&&Math.hypot(dx,dy)<4)return;
  const {width,height}=canvas.getBoundingClientRect(),scale=Math.min(width/atlas.size[0],height/atlas.size[1])*view.zoom;
  moved=true;view.x-=dx/scale;view.y-=dy/scale;drag={x:event.clientX,y:event.clientY};draw();
 };
 canvas.onpointerup=event=>{
  drag=null;if(moved)return;
  const r=canvas.getBoundingClientRect(),hit=hits.find(p=>Math.hypot(p.x-event.clientX+r.left,p.y-event.clientY+r.top)<=13);
  if(hit)notify('select',{bot_id:hit.row.id});
 };
 canvas.onpointercancel=()=>{drag=null;};
 addEventListener('message',event=>{
  if(event.origin!==location.origin||event.source!==parent||event.data?.source!=='vampir-live-prototype')return;
  const {type}=event.data;
  if(type==='state'){
   payload=event.data.payload;selected=event.data.bot_id;sessions=payload?.sessions??{};
   if(VampirLocalMapProjection.valid(payload?.atlas))atlas=payload.atlas;
   update();
  }
  if(type==='focus')center();
 });
 addEventListener('resize',draw);image.onload=draw;image.src='world-atlas.jpg';notify('ready');loadLayers();
 addEventListener('pagehide',event=>{
  if(event.persisted)return;disposed=true;for(const request of requests)request.abort();
  if(frame)cancelAnimationFrame(frame);layerPainter.dispose();image.onload=null;
 });
})();
