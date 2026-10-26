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
const partial = model.project({...snapshot,coverage:{entities:'partial'},entities:[{key:'42',kind:'npc'}]});
assert.equal(partial.entitiesKnown,true);assert.equal(partial.entitiesPartial,true);assert.equal(partial.entities,1);
const paged = model.project({...snapshot,coverage:{entities:'partial'},entities:Array(256).fill({key:'42'}),environment:{known_count:512,entity_page:1}});
assert.equal(paged.entities,512);assert.equal(paged.entityRows.length,256);assert.equal(paged.entityPage,1);
assert.equal(model.project({...snapshot,state:'disconnected',coverage:{entities:'partial'}}).entitiesKnown,false);
const tutorialMessage = {semantics:'last_received_message',applied_to_local_task:false,flag:false,character_key:'42',
  records:[{raw08:1001,raw0c:2,raw10:1,state:2}]};
const tutorialSnapshot = {...snapshot,character:{...snapshot.character,key:'42'},coverage:{tutorial:'last_received_message'},tutorial:tutorialMessage};
const tutorialView = model.project(tutorialSnapshot);
assert.deepEqual(tutorialView.tutorial,{flag:false,records:[{raw08:1001,raw0c:2,raw10:1,state:2}]});
assert.equal(tutorialView.questsKnown,false);assert.equal(model.availability('ButtonQuest',tutorialView).enabled,false);
tutorialView.tutorial.records[0].raw0c=3;assert.equal(tutorialMessage.records[0].raw0c,2);
for (const message of [{...tutorialMessage,character_key:'another'},{...tutorialMessage,applied_to_local_task:true},
  {...tutorialMessage,records:Array(65).fill(tutorialMessage.records[0])}, {...tutorialMessage,records:[{...tutorialMessage.records[0],raw10:2**32}]},
  {...tutorialMessage,records:[{...tutorialMessage.records[0],state:4}]}]) {
  assert.equal(model.project({...tutorialSnapshot,tutorial:message}).tutorial,null);
}
assert.equal(model.project({...tutorialSnapshot,state:'disconnected'}).tutorial,null);
assert.equal(model.project({...tutorialSnapshot,coverage:{tutorial:'decode_error'}}).tutorial,null);
assert.deepEqual(model.project({...tutorialSnapshot,tutorial:{...tutorialMessage,records:[]}}).tutorial,{flag:false,records:[]});
console.log('Main live projection: precision, unknowns, disconnect, map and menu gates passed');
