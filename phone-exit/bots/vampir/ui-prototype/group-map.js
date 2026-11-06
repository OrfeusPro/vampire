/* Shared atlas renderer. The parent adapter supplies all game state. */
(() => {
 'use strict';
 const canvas=document.getElementById('group-canvas'),ctx=canvas.getContext('2d'),image=new Image();
 const label=document.getElementById('map-world');
 let payload,sessions={},selected,atlas,points=[],hits=[],drag,moved=false,entryWorld,activeMap;
 let view={x:5120,y:5120,zoom:1};
 const notify=(type,data={})=>parent.postMessage({source:'vampir-group-map',type,...data},location.origin);
 const current=()=>points.find(row=>row.id===selected);
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
  if(image.naturalWidth)ctx.drawImage(image,left,top,atlas.size[0]*scale,atlas.size[1]*scale);
  const groups=[];
  for(const row of points.filter(row=>row.position.map_id===activeMap)){
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
   ctx.fillText(row.name,x+15,y-8);ctx.shadowBlur=0;
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
 addEventListener('resize',draw);image.onload=draw;image.src='world-atlas.jpg';notify('ready');
})();
