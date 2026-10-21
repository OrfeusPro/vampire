/* Read-only session overlay; no game commands or persistent storage. */
(function(root){
  'use strict';
  function validate(value){
    if(!value||value.schema!==1||!['waiting','connected','disconnected','unsupported_world'].includes(value.state))throw Error('Неверное состояние сессии');
    if(value.state!=='connected')return {state:value.state,position:null};
    const p=value.position;
    if(!p||!Number.isInteger(p.world_id)||!['10','11'].includes(p.map_id)
      ||!['x','y','z','pixel_x','pixel_y'].every(k=>typeof p[k]==='number'&&Number.isFinite(p[k]))
      ||typeof p.inside!=='boolean'||p.semantics!=='server_target_before_engine_correction'
      ||!Number.isFinite(value.updated_at_ms))throw Error('Неверная позиция сессии');
    return {state:value.state,position:p,updated_at_ms:value.updated_at_ms};
  }
  function marker(snapshot,world,now){
    const p=snapshot?.position;
    if(snapshot?.state!=='connected'||!p||!p.inside||(world!=='all'&&world!==String(p.world_id)))return null;
    return {...p,stale:now-snapshot.updated_at_ms>5000};
  }
  const api={validate,marker};root.MapSessionModel=api;
  if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
