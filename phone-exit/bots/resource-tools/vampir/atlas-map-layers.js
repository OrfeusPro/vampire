/* Shared reference-atlas background, static points and research navigation; no game actions. */
(function(root){
 'use strict';
 const model=root.WorldMapModel||(typeof require==='function'?require('./world-map-model.js'):null);
 const navigationModel=root.NavOverlayModel||(typeof require==='function'?require('./nav-overlay-model.js'):null);
 const pointOrder=['Area','Waypoint','GadgetSpawn','NpcSpawn','WorldSpot','QuestTask'];
 const pointColors={NpcSpawn:'#84b9ef',Area:'#f4d48b',Waypoint:'#d7a7ff',GadgetSpawn:'#bda1e3',WorldSpot:'#62e7bc',QuestTask:'#ff8da5'};
 function create({requestDraw,resolveUrl=file=>file,ImageCtor=root.Image}={}){
  const cache=new Map(),failed=new Set();let disposed=false,pending=false,frame;
  function schedule(){
   if(disposed||pending)return;pending=true;
   const run=()=>{pending=false;frame=undefined;if(!disposed)requestDraw?.();};
   if(typeof root.requestAnimationFrame==='function')frame=root.requestAnimationFrame(run);
   else Promise.resolve().then(run);
  }
  function release(image){image.onload=null;image.onerror=null;image.src='';}
  function trim(needed){
   for(const [key,image] of cache){
    if(cache.size<=10)break;
    if(!needed.has(key)){cache.delete(key);release(image);}
   }
  }
  function imageFor(file){
   if(cache.has(file)){const image=cache.get(file);cache.delete(file);cache.set(file,image);return image;}
   if(disposed||failed.has(file))return null;
   const image=new ImageCtor();cache.set(file,image);
   image.onload=()=>{if(cache.get(file)===image)schedule();};
   image.onerror=()=>{failed.add(file);if(cache.get(file)===image)schedule();};
   image.src=resolveUrl(file);return image;
  }
  function background(ctx,preview,source,projection,view,width,height,dpr=1){
   const result={detailed:false,visible:0,loaded:0,cached:cache.size};
   if(disposed)return result;
   const bounds=projection.world_bounds,size=projection.size;
   if(!model||!Array.isArray(bounds)||bounds.length!==4||!bounds.every(Number.isFinite)
      ||!Array.isArray(size)||size.length!==2||!size.every(n=>Number.isFinite(n)&&n>0)
      ||!Array.isArray(source.tiles)||source.tiles.length>25)throw Error('Некорректный справочный атлас');
   const x=(bounds[0]-view.x)*view.s+width/2,y=(bounds[1]-view.y)*view.s+height/2;
   const extent=(bounds[2]-bounds[0])*view.s,vertical=(bounds[3]-bounds[1])*view.s;
   if(extent<=0||vertical<=0||!Number.isFinite(extent)||!Number.isFinite(vertical))throw Error('Некорректный масштаб атласа');
   if(preview.complete&&preview.naturalWidth)ctx.drawImage(preview,x,y,extent,vertical);
   // Same threshold and LTRB rectangles as the original geographical atlas.
   if(extent/5*Math.min(dpr,2)<390){trim(new Set());result.cached=cache.size;return result;}
   result.detailed=true;const needed=new Set();
   for(const tile of source.tiles){
    const rect=model.tileRect(tile.atlas_rect);
    const tx=x+rect.x/size[0]*extent,ty=y+rect.y/size[1]*vertical;
    const tw=rect.width/size[0]*extent,th=rect.height/size[1]*vertical;
    if(tx>width||ty>height||tx+tw<0||ty+th<0)continue;
    needed.add(tile.file);result.visible++;
    const image=imageFor(tile.file);
    if(image?.complete&&image.naturalWidth){ctx.drawImage(image,tx,ty,tw,th);result.loaded++;}
   }
   trim(needed);result.cached=cache.size;return result;
  }
  function navigation(ctx,overlay,view,width,height){
   if(disposed)return 0;
   const tiles=navigationModel.visible(overlay.tiles,view,width,height);
   const screen=v=>[(v[0]-view.x)*view.s+width/2,(v[1]-view.y)*view.s+height/2];
   ctx.save();ctx.strokeStyle='#bb9af0a6';ctx.fillStyle='#ad86ed24';ctx.lineWidth=.7;
   for(const tile of tiles){
    if(!navigationModel.detailed(tile,view.s)){
     const [x,y]=screen(tile.bounds);
     ctx.fillRect(x,y,(tile.bounds[2]-tile.bounds[0])*view.s,(tile.bounds[3]-tile.bounds[1])*view.s);
     continue;
    }
    const vertices=tile.vertices.map(screen);
    for(const face of tile.polygons){
     ctx.beginPath();face.forEach((id,i)=>{const [x,y]=vertices[id];i?ctx.lineTo(x,y):ctx.moveTo(x,y);});
     ctx.closePath();ctx.fill();ctx.stroke();
    }
   }
   ctx.restore();return tiles.length;
  }
  function points(ctx,data,view,width,height,{worldId,types=new Set(pointOrder),labels=false}={}){
   const result={visible:0,clusters:0};if(disposed)return result;
   if(data?.schema!==1||data.kind!=='reference_atlas_points'||data.runtime_visibility_verified!==false
      ||!Array.isArray(data.points)||data.points.length>32768||!(types instanceof Set)
      ||[...types].some(type=>!Object.hasOwn(pointColors,type)))throw Error('Неизвестные справочные слои карты');
   const world=String(worldId??'');
   const candidates=data.points.filter(point=>String(point.world_id)===world&&Number.isFinite(point.x)&&Number.isFinite(point.y)
      &&Object.hasOwn(pointColors,point.type))
    .map(point=>({...point,world_id:String(point.world_id),key:point.key??[point.type,point.id,point.world_id].join(':')}));
   const selected=model.filter(candidates,{world,types});
   const groups=model.clusters(selected,view,width,height,24).sort((a,b)=>pointOrder.indexOf(a.type)-pointOrder.indexOf(b.type));
   result.visible=groups.reduce((sum,group)=>sum+group.points.length,0);result.clusters=groups.length;
   ctx.save();ctx.lineWidth=1.2;ctx.strokeStyle='#173443';
   for(const group of groups){
    const multiple=group.points.length>1;
    ctx.fillStyle=pointColors[group.type];ctx.beginPath();ctx.arc(group.x,group.y,multiple?10:group.type==='Area'?4:5,0,Math.PI*2);ctx.fill();ctx.stroke();
    if(multiple){
     ctx.fillStyle='#10283b';ctx.font='bold 11px system-ui';ctx.textAlign='center';ctx.fillText(String(group.points.length),group.x,group.y+4);
    }else if(labels===true||labels instanceof Set&&labels.has(group.type)){
     const point=group.points[0],label=String(point.label??point.npc_id??point.id??'NPC').replace(/\s+/g,' ').slice(0,48);
     ctx.fillStyle='#d9ecff';ctx.font='12px system-ui';ctx.textAlign='left';ctx.fillText(label,group.x+9,group.y-8);
    }
   }
   ctx.restore();return result;
  }
  function dispose(){
   if(disposed)return;disposed=true;
   if(frame!==undefined&&typeof root.cancelAnimationFrame==='function')root.cancelAnimationFrame(frame);
   frame=undefined;pending=false;for(const image of cache.values())release(image);cache.clear();failed.clear();
  }
  return {background,navigation,points,dispose};
 }
 const api={create};root.VampirAtlasLayers=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
