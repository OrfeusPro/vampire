const assert=require('node:assert/strict');
const model=require('./map-session-model.js');
const now=10000;
const position={world_id:1001,map_id:'10',x:1,y:2,z:3,pixel_x:5120,pixel_y:5120,inside:true,semantics:'server_target_before_engine_correction'};
const value={schema:1,state:'connected',position,updated_at_ms:now};
assert.equal(model.marker(model.validate(value),'1001',now).stale,false);
assert.equal(model.validate({...value,position:{...position,semantics:'server_target_xy_retained_z'}}).position.semantics,'server_target_xy_retained_z');
assert.equal(model.marker(model.validate(value),'1001',now+6000).stale,true);
assert.equal(model.marker(model.validate(value),'1002',now),null);
assert.equal(model.marker(model.validate({...value,position:{...position,inside:false}}),'all',now),null);
assert.equal(model.marker(model.validate({schema:1,state:'disconnected'}),'all',now),null);
for(const changed of [{world_id:'1001'},{x:NaN},{map_id:'99'},{semantics:'current_actor'}]){
  assert.throws(()=>model.validate({...value,position:{...position,...changed}}));
}
console.log('Map session model checks passed');
