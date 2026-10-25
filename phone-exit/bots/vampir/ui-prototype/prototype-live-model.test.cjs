const assert = require('node:assert/strict');
const model = require('./prototype-live-model.js');
const snapshot = {state:'connected', character:{world_id:'10012', position:{x:12,y:34,z:56},
  stats_semantics:'wire_stat_i64', stats:[{id:1,value:'9007199254740993'}, {id:134,value:'12345'}]},
  entities:[], coverage:{entities:'received',quests:'received'}, quests:[],
  position:{world_id:'10012',map_id:'10',x:12,y:34,z:56,pixel_x:5120,pixel_y:5120,semantics:'server_target_before_engine_correction'}};
const known = model.project(snapshot);
assert.equal(known.power,'123');
assert.equal(known.experience,'9007199254740993'); // Do not lose wire integer precision.
assert.deepEqual(known.position,{x:12,y:34});
assert.equal(known.entities,0);
assert.equal(known.questsKnown,true);
assert.equal(model.availability('ButtonQuest',known).enabled,true);
assert.equal(model.availability('ButtonInventory',known).enabled,false);
for (const unknown of [null, {...snapshot,state:'disconnected'}]) {
  const result = model.project(unknown);
  assert.equal(result.person,null); assert.equal(result.position,null); assert.equal(result.entities,null);
  assert.equal(result.power,null); assert.equal(result.experience,null);
  assert.equal(model.availability('ButtonCharacter',result).enabled,false);
}
for (const position of [{...snapshot.position,world_id:'another'}, {...snapshot.position,map_id:'99'},
  {...snapshot.position,x:NaN}, {...snapshot.position,semantics:'guessed'}]) {
  assert.equal(model.project({...snapshot,position}).position,null);
}
assert.equal(model.project({...snapshot,character:{...snapshot.character,stats_semantics:'unknown'}}).power,null);
assert.equal(model.project({...snapshot,coverage:{},quests:[{id:'1',title:'Unverified'}]}).questsKnown,false);
assert.equal(model.project({...snapshot,quests:undefined}).questsKnown,false);
assert.equal(model.project({...snapshot,quests:[{id:'1',title:'Received'}, {id:'bad',title:'Invalid'}]}).quests.length,1);
console.log('Main live projection: precision, unknowns, disconnect, map and menu gates passed');
