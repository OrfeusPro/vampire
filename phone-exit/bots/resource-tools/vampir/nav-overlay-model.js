(function(root){
  'use strict';
  function validate(data){
    if(data.schema_version!==1||data.coordinate_space!=='world_xy'||data.navigation_ready!==false||!Array.isArray(data.tiles))throw Error('Неизвестный формат сетки');
    for(const tile of data.tiles){
      if(tile.bounds?.length!==4||!tile.bounds.every(Number.isFinite)||tile.bounds[0]>tile.bounds[2]||tile.bounds[1]>tile.bounds[3])throw Error('Неверные границы сетки');
      if(!Array.isArray(tile.vertices)||!tile.vertices.every(v=>v.length===2&&v.every(Number.isFinite)))throw Error('Неверные координаты сетки');
      if(!Array.isArray(tile.polygons)||!tile.polygons.every(p=>p.length>=1&&p.length<=6&&p.every(i=>Number.isInteger(i)&&i>=0&&i<tile.vertices.length)))throw Error('Неверные индексы сетки');
    }
    if(data.special_links!==undefined&&(!Array.isArray(data.special_links)||!data.special_links.every(p=>typeof p.id==='string'&&p.attachment_verified===false&&[p.start,p.end,p.baked_start,p.baked_end].every(v=>Array.isArray(v)&&v.length===3&&v.every(Number.isFinite)))))throw Error('Неверные точки специального перехода');
    for(const p of data.special_links||[]){
      const a=p.native_attachment_scenario;
      if(a&&(a.runtime_verified!==false||typeof a.connected!=='boolean'||typeof a.matches_baked!=='boolean'||a.matches_baked&&!a.connected))throw Error('Неверный статус исследовательского присоединения');
      const c=p.surface_candidate_check;if(!c)continue;
      if(c.attachment_verified!==false||c.bv_disabled!==true||typeof c.start_found!=='boolean'||typeof c.start_matches_baked!=='boolean'||typeof c.end_matches_baked!=='boolean'||!Number.isInteger(c.end_candidate_count)||c.end_candidate_count<0||c.start_matches_baked&&!c.start_found||c.end_matches_baked&&c.end_candidate_count===0)throw Error('Неверный статус предварительной поверхности');
    }
    if(data.navigation_filter_application_evidence&&data.navigation_filter_application_evidence.runtime_selection_verified!==false)throw Error('Исследование фильтра не подтверждает активный выбор');
    for(const preset of data.navigation_filter_presets||[]){
      if(preset.application_check===undefined)continue;
      if(preset.runtime_verified!==false||!Array.isArray(preset.areas)||!Array.isArray(preset.application_check)||preset.application_check.length!==preset.areas.length)throw Error('Неверная проверка фильтра');
      for(const effect of preset.application_check){
        if(effect.travel_written!==undefined&&(!Number.isFinite(effect.travel_written)||effect.travel_written<1)||effect.entering_written!==undefined&&(!Number.isFinite(effect.entering_written)||effect.entering_written<0)||effect.excluded===true&&(effect.travel_written!==undefined||effect.entering_written!==undefined))throw Error('Неверное применение стоимости фильтра');
      }
    }
    return data;
  }
  function visible(tiles,view,width,height){
    const left=view.x-width/(2*view.s),right=view.x+width/(2*view.s),top=view.y-height/(2*view.s),bottom=view.y+height/(2*view.s);
    return tiles.filter(t=>t.bounds[2]>=left&&t.bounds[0]<=right&&t.bounds[3]>=top&&t.bounds[1]<=bottom);
  }
  function detailed(tile,scale){return Math.max(tile.bounds[2]-tile.bounds[0],tile.bounds[3]-tile.bounds[1])*scale>=6;}
  function nearestSpecial(links,view,width,height,x,y,limit=10){
    let closest=null,best=limit;
    for(const link of links){
      const ax=(link.start[0]-view.x)*view.s+width/2,ay=(link.start[1]-view.y)*view.s+height/2,bx=(link.end[0]-view.x)*view.s+width/2,by=(link.end[1]-view.y)*view.s+height/2;
      const dx=bx-ax,dy=by-ay,length=dx*dx+dy*dy,t=length?Math.max(0,Math.min(1,((x-ax)*dx+(y-ay)*dy)/length)):0,d=Math.hypot(x-ax-t*dx,y-ay-t*dy);
      if(d<best){closest=link;best=d;}
    }
    return closest;
  }
  const api={validate,visible,detailed,nearestSpecial};root.NavOverlayModel=api;if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
