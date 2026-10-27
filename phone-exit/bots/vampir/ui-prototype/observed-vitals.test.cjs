const assert=require('node:assert/strict');
const live=require('./live-state.js');
const model=require('./prototype-live-model.js');
const now=1800000000000,originalNow=Date.now;
Date.now=()=>now;
const clone=value=>JSON.parse(JSON.stringify(value));
function state() {
  const value={schema:2,bot_id:'one',session_id:'session-one',state:'connected',error:null,entities:[],coverage:{},
    character:{key:'625841392748350208',world_id:10012,name:'Observed',hp:null,max_hp:null,mp:null,max_mp:null,level:null,
      stats:[],stats_semantics:'wire_stat_i64'},position:null};
  value.analysis={revision:'a'.repeat(64),error:null,values:{readonly_stats:{schema:1,
    semantics:'last_received_stat_notification',source_sha256:'d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c',
    bot_id:value.bot_id,session_id:value.session_id,character_key:value.character.key,world_id:'10012',
    status:'observed_partial',reason:null,stats:[{id:3,value:'1'},{id:4,value:'0'},{id:5,value:'100'},
      {id:9,value:'20'},{id:10,value:'30'},{id:134,value:'50000'}],
    vitals:{level:1,hp:0,max_hp:100,mp:20,max_mp:30},last_sample:{seq:4,packet_id:322},sample_cursor:4,
    sample_gap:false,event_gap:false,malformed_samples:0,updated_at_ms:now,owner_character_modified:false,
    provenance:{decoder_sha256:'70624e1a1225ddf14fddb6e215cf2d31de36285160db76296c42f7db6bcb9cd5',
      native_proofs:{notify:'4b6d7da19c0a9af1f043608d84ea7d097679b421448a70326ad3dada99b9c2b8',
        initial:'99fa2824cb6fd12065e41111dadff2233b0e115e315552adcd4072f801343bd8'},
      packet_bindings:{321:'c390d402da90e1b0a4aef9347c5b87d38aa0c4828264eeaeb1e5e5eae3675b3f',
        322:'4dcd921f619e8883cabf5a231723b33e06a609abf1f93ca7007733536a08d93f'},
      enum_sha256:'a9a373cdc17c73008ae0bc804a335d0996749187f092b49d7c8afc71a53d98e5'}}}};
  return value;
}
try {
  const snapshot=state(),before=clone(snapshot),display=live.displaySnapshot(snapshot);
  assert.equal(display.character.hp,0);assert.equal(display.character.level,1);
  assert.equal(display.character.max_hp,100);assert.equal(display.character.mp,20);
  assert.notEqual(display,snapshot);assert.notEqual(display.character,snapshot.character);
  assert.deepEqual(snapshot,before,'observations never overwrite owner API fields or coverage');
  assert.equal(display.stats_observation.semantics,'last_received_stat_notification');
  assert.equal(display.character.stats.length,5,'other wire IDs do not imply verified UI units');
  assert.equal(live.playerStatus(snapshot).vitals[0].known,true);
  assert.equal(live.playerStatus(snapshot).vitals[0].value,0,'received zero is a known value');
  const view=model.project(snapshot);
  assert.equal(view.person.hp,0);assert.equal(view.person.mp,20);assert.equal(view.power,null);
  assert.equal(view.statsObservation.fields.length,5);
  assert.equal(model.availability('ButtonQuest',view).enabled,false,'observation never admits quest actions');
  assert.equal(model.availability('ButtonCombatStats',view).enabled,true,'wire values have a read-only detail view');
  assert.equal(view.position,null);assert.deepEqual(snapshot.coverage,{});
  const partial=state();partial.analysis.values.readonly_stats.stats=[{id:4,value:'25'}];
  partial.analysis.values.readonly_stats.vitals={hp:25,max_hp:null,mp:null,max_mp:null,level:null};
  assert.equal(live.displaySnapshot(partial).character.hp,25);
  assert.equal(live.playerStatus(partial).vitals[0].known,false,'missing maximum stays unknown');
  const native=state();native.character.hp=70;native.character.stats=[{id:4,name:'Native HP',value:'70'}];
  const nativeView=live.displaySnapshot(native);
  assert.equal(nativeView.character.hp,70);assert.equal(nativeView.character.stats.find(r=>r.id===4).value,'70');
  assert.equal(nativeView.character.max_hp,100);assert.ok(!nativeView.stats_observation.fields.includes('hp'));
  const conflict=state();conflict.character.stats=[{id:4,name:'Native HP',value:'70'}];
  assert.equal(live.displaySnapshot(conflict).character.hp,null,'conflicting native wire values are not replaced');
  const reject=mutate=>{const value=state();mutate(value,value.analysis.values.readonly_stats);
    assert.equal(live.displaySnapshot(value),value);assert.equal(live.playerStatus(value).vitals[0].known,false);};
  for(const field of ['bot_id','session_id','character_key','world_id','source_sha256'])reject((s,o)=>{o[field]='other';});
  reject((s,o)=>{s.character.key=o.character_key='18446744073709551616';});
  reject((s,o)=>{s.character.world_id=o.world_id='18446744073709551616';});
  for(const field of ['sample_gap','event_gap','owner_character_modified'])reject((s,o)=>{o[field]=true;});
  reject((s,o)=>{o.updated_at_ms=now-6001;});reject((s,o)=>{o.updated_at_ms=now+1;});
  assert.equal(live.displaySnapshot(state(),now+6000).character.hp,0);
  assert.equal(live.displaySnapshot(state(),now+6001).character.hp,null);
  reject((s,o)=>{s.state='disconnected';});reject((s,o)=>{s.error='connection_closed';});
  reject((s,o)=>{s.analysis.error='HandlerFailed';});reject((s,o)=>{s.analysis.revision='not-a-digest';});
  reject((s,o)=>{o.status='waiting_for_notification';});reject((s,o)=>{o.reason='observation_gap';});
  reject((s,o)=>{o.malformed_samples=1;});reject((s,o)=>{o.last_sample.packet_id=1854;});
  reject((s,o)=>{o.last_sample.seq=5;});reject((s,o)=>{o.provenance.decoder_sha256='0'.repeat(64);});
  for(const key of ['notify','initial'])reject((s,o)=>{o.provenance.native_proofs[key]='0'.repeat(64);});
  for(const key of ['321','322'])reject((s,o)=>{o.provenance.packet_bindings[key]='0'.repeat(64);});
  reject((s,o)=>{o.provenance.enum_sha256='0'.repeat(64);});
  reject((s,o)=>{o.stats.push({...o.stats[0]});});reject((s,o)=>{o.stats[0].value='9223372036854775808';});
  reject((s,o)=>{o.vitals.hp=1;});reject((s,o)=>{delete o.vitals.max_hp;});
  const unsafe=state();unsafe.analysis.values.readonly_stats.stats=[{id:4,value:'9007199254740992'}];
  unsafe.analysis.values.readonly_stats.vitals={hp:null,max_hp:null,mp:null,max_mp:null,level:null};
  assert.equal(live.displaySnapshot(unsafe),unsafe,'unsafe integer cannot become a UI number');
  const signed=state();signed.analysis.values.readonly_stats.stats=[{id:4,value:'-1'}];
  signed.analysis.values.readonly_stats.vitals={hp:null,max_hp:null,mp:null,max_mp:null,level:null};
  assert.equal(live.displaySnapshot(signed).character.hp,null);
  const absent=state();delete absent.analysis;
  assert.equal(live.displaySnapshot(absent),absent);assert.equal(live.playerStatus(absent).vitals[0].known,false);
  assert.equal(live.displaySnapshot(null),null);
  console.log('Observed vitals: scope/proofs/freshness, nullable pairs, native precedence, read-only shared views passed');
} finally {Date.now=originalNow;}
