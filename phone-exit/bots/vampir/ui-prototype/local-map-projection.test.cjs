const assert = require('node:assert/strict');
const local = require('./local-map-projection.js');
const model = require('./prototype-live-model.js');
const spec = {schema:1,kind:'local_atlas',formula:'centered_positive_xy_v1',archive_data_verified:true,
  current_native_widget_math_verified:false,
  client_context_sha256:'d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c',
  archive_sha256:'15cf4f880170e87fc5fdea661cf9ba3d54a4f66c607844f5ab1047ed87f1e6a4',
  data_evidence:{sha256:'0b26af0a29fcf9f968e9d6f01fd7b3bc198a2e15d944007d93915b34a662c677'},
  worlds:{10012:'10',70010:'11'},map_ids:['10','11'],size:[10240,10240],center:[0,0],ground_distance:615000};
const snapshot = {state:'connected',character:{key:'42',world_id:10012,name:'Observed',stats:[],
  hp:null,max_hp:null,mp:null,max_mp:null,level:null,
  position:{x:90049,y:151840,z:-44,semantics:'server_target_before_engine_correction'}},position:null,coverage:{}};
const before = JSON.stringify(snapshot), result = local.project(snapshot,spec);
assert.equal(result.map_id,'10');
assert.equal(result.world_id,10012);
assert.equal(result.pixel_x,(90049*10240/615000)+5120);
assert.equal(result.pixel_y,(151840*10240/615000)+5120);
assert.equal(result.semantics,snapshot.character.position.semantics);
assert.equal(result.origin,'local_atlas');
assert.equal(result.current_native_widget_math_verified,false);
assert.equal(JSON.stringify(snapshot),before,'view does not overwrite owner position or coverage');
const view=model.project(snapshot,spec);
assert.deepEqual(view.position,{x:90049,y:151840});
assert.equal(view.mapId,'10');assert.equal(view.positionOrigin,'local_atlas');
assert.equal(view.person.hp,null);assert.equal(view.questsKnown,false);
assert.equal(model.availability('ButtonQuest',view).enabled,false,'map does not enable actions');
for (const invalid of [null,{...snapshot,state:'disconnected'},
  {...snapshot,character:{...snapshot.character,world_id:99999}},
  {...snapshot,character:{...snapshot.character,position:null}},
  ...[{x:NaN},{z:Infinity},{semantics:'server_target_xy_retained_z'},
    {semantics:'guessed'},{world_id:70010},{map_id:'11'}].map(changes =>
      ({...snapshot,character:{...snapshot.character,position:{...snapshot.character.position,...changes}}}))]) {
  assert.equal(local.project(invalid,spec),null,'unknown or conflicting raw data cannot locate marker');
}
for (const invalid of [{...spec,archive_sha256:'0'.repeat(64)},
  {...spec,current_native_widget_math_verified:true},{...spec,size:[0,10240]},
  {...spec,worlds:{10012:'99'}},{...spec,data_evidence:{sha256:'0'.repeat(64)}}]) {
  assert.equal(local.project(snapshot,invalid),null);
}
const native={world_id:10012,map_id:'10',x:1,y:2,z:3,pixel_x:5120,pixel_y:5120,
  semantics:'server_target_before_engine_correction'};
assert.deepEqual(model.project({...snapshot,position:native},spec).position,{x:1,y:2});
assert.equal(model.project({...snapshot,position:native},spec).positionOrigin,'owner_projection');
for (const invalid of [{...native,map_id:'99'},{...native,world_id:70010},{...native,x:NaN}]) {
  assert.equal(model.project({...snapshot,position:invalid},spec).position,null,'fallback cannot hide rejected owner projection');
}
const calls=[];
const first=local.load({fetchImpl:async (url,options) => {
  calls.push({url,options});return {ok:true,text:async()=>JSON.stringify(spec)};
}});
assert.equal(local.load({fetchImpl:()=>{throw Error('duplicate metadata request');}}),first);
first.then(metadata => {
  assert.equal(calls.length,1);assert.equal(calls[0].url,'local-map-projection.json');
  assert.equal(calls[0].options.method,undefined,'metadata fetch does not issue actions');
  assert.ok(Object.isFrozen(metadata));assert.ok(Object.isFrozen(metadata.worlds));
  console.log('Local atlas: source data scope, known world, finite XYZ, native precedence, unknowns, immutable shared load passed');
}).catch(error=>{console.error(error);process.exitCode=1;});
