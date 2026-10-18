const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('./resource-tools/vampir/world-map-model.js');
const rarity = require('./resource-tools/vampir/item-rarity.js');

test('area labels stay inside the viewport and avoid full label backgrounds and markers', () => {
  const labels=Array.from({length:60},(_,i)=>({key:String(i),x:20+(i%10)*28,y:25+Math.floor(i/10)*30,width:90,height:22}));
  const original=JSON.stringify(labels),blockers=[{x:150,y:90,width:90,height:80}];
  const placed=model.placeLabels(labels,320,240,blockers);
  assert.ok(placed.length>0&&placed.length<labels.length);
  const overlap=(a,b)=>a.x<b.x+b.width+4&&a.x+a.width+4>b.x&&a.y<b.y+b.height+4&&a.y+a.height+4>b.y;
  for(const [i,box] of placed.entries()){
    assert.ok(box.x>=4&&box.y>=4&&box.x+box.width<=316&&box.y+box.height<=236);
    assert.ok(!placed.slice(0,i).some(other=>overlap(box,other)));
    assert.ok(!blockers.some(other=>overlap(box,other)));
  }
  assert.equal(JSON.stringify(labels),original);
  assert.deepEqual(model.placeLabels([...labels].reverse(),320,240,blockers),placed);
});

test('selected area wins a crowded label slot; other records are not moved', () => {
  const labels=[{key:'normal',x:100,y:80,width:100},{key:'selected',x:100,y:80,width:100,selected:true}];
  const placed=model.placeLabels(labels,220,120);
  assert.equal(placed[0].key,'selected');
  assert.equal(labels.length,2);
  assert.deepEqual(model.placeLabels(labels,30,20),[]);
});

test('area label can switch sides near edges instead of being clipped', () => {
  const right=model.placeLabels([{key:'right',x:190,y:80,width:80}],220,160);
  assert.equal(right.length,1);assert.ok(right[0].x<190);
  assert.deepEqual(model.placeLabels([],220,160),[]);
});

test('NPC summaries group by exact ID, preserve points and world contexts after filtering', () => {
  const points=[{type:'NpcSpawn',npc_id:'1',label:'Same',world_id:'10017'},
    {type:'NpcSpawn',npc_id:'1',label:'Same',world_id:'100171'},
    {type:'NpcSpawn',npc_id:'1',label:'Same',world_id:'10017'},
    {type:'NpcSpawn',npc_id:'11',label:'Same',world_id:'10017'},
    {type:'Area',id:'area',world_id:'10017'}];
  const grouped=model.npcSummaries(points);
  assert.equal(grouped.length,2);
  assert.equal(grouped[0].npc_id,'1');
  assert.deepEqual(grouped[0].worlds,['10017','100171']);
  assert.deepEqual(grouped[0].points,points.slice(0,3));
  assert.equal(grouped[1].points.length,1);
  const filtered=model.filter(points,{world:'10017',types:new Set(['NpcSpawn'])});
  assert.equal(model.npcSummaries(filtered)[0].points.length,2);
  assert.deepEqual(model.npcSummaries([]),[]);
});

test('skill filter uses exact NPC IDs and intersects item filters; missing skill stays empty', () => {
  const points=[{type:'NpcSpawn',npc_id:'1',world_id:'a'},{type:'NpcSpawn',npc_id:'11',world_id:'a'},{type:'Area',world_id:'a'}];
  const opts={world:'all',types:new Set(['NpcSpawn','Area']),skillNpcs:new Set(['1'])};
  assert.deepEqual(model.filter(points,opts),[points[0]]);
  assert.deepEqual(model.filter(points,{...opts,npcs:new Set(['11'])}),[]);
  assert.deepEqual(model.filter(points,{...opts,skillNpcs:new Set()}),[]);
  assert.deepEqual(model.filter(points,{...opts,skillNpcs:null}),points);
});

test('cooldown seconds require proven units and preserve zero, fractions and large values', () => {
  assert.equal(model.cooldownValue('23000','milliseconds'),'23 с');
  assert.equal(model.cooldownValue('1501','milliseconds'),'1,501 с');
  assert.equal(model.cooldownValue('0','milliseconds'),'0 с');
  assert.equal(model.cooldownValue('','milliseconds'),'—');
  assert.equal(model.cooldownValue('23000',null),'23000');
  assert.equal(model.cooldownValue('1.5','milliseconds'),'1.5');
  assert.equal(model.cooldownValue('9007199254740993','milliseconds'),'9007199254740,993 с');
});
test('direct loot filter excludes ordinary NPC and other layers while retaining item filters', () => {
  const p=[{type:'NpcSpawn',world_id:'a',npc_id:'1',loot_count:29},{type:'NpcSpawn',world_id:'a',npc_id:'2',loot_count:0},{type:'Area',world_id:'a',loot_count:29}];
  const opts={world:'all',types:new Set(['NpcSpawn','Area']),directLootOnly:true};
  assert.deepEqual(model.filter(p,opts),[p[0]]);
  assert.deepEqual(model.filter(p,{...opts,npcs:new Set(['2'])}),[]);
});
test('client reward UI scope follows the spawn area sentinel, not reward availability', () => {
  assert.equal(model.clientRewardScope({type:'NpcSpawn',area_id:'100181100'}),'area');
  assert.equal(model.clientRewardScope({type:'NpcSpawn',area_id:'0'}),'npc');
  assert.equal(model.clientRewardScope({type:'NpcSpawn',area_id:''}),'npc');
  assert.equal(model.clientRewardScope({type:'NpcSpawn'}),null);
  assert.equal(model.clientRewardScope({type:'NpcSpawn',area_id:'unknown'}),null);
  assert.equal(model.clientRewardScope({type:'Area',area_id:'42'}),null);
});
test('rarity sorts grades descending, keeps special categories separate and unknowns last', () => {
  const items = ['102','2','100','0','5','3','101','4','1'].map(id => ({rarity:{id}}));
  assert.deepEqual(items.sort(rarity.compare).map(item => item.rarity.id), ['5','4','3','2','1','0','100','101','102']);
  assert.equal(rarity.rank({data:{Rarity:'2'}}), rarity.rank({rarity:{id:'2'}}));
  assert.equal(rarity.rank({}), rarity.rank({rarity:{id:'102'}}));
});
const points = [
  {key:'n1',type:'NpcSpawn',world_id:'a',npc_id:'1',label:'Same',x:10,y:20},
  {key:'n2',type:'NpcSpawn',world_id:'b',npc_id:'2',label:'Same',x:10,y:20},
  {key:'area',type:'Area',world_id:'a',id:'a',label:'Krvna Nest',x:12,y:21},
];
test('overview preserves both same-name contexts; world filter is exact',()=>{
  const options={world:'all',types:new Set(['NpcSpawn'])};
  assert.equal(model.filter(points,options).length,2);
  assert.deepEqual(model.filter(points,{...options,world:'b'}).map(p=>p.key),['n2']);
});
test('empty item source set must not expose all NPCs or unrelated layers',()=>{
  assert.deepEqual(model.filter(points,{world:'all',types:new Set(['NpcSpawn','Area']),npcs:new Set()}),[]);
});
test('item filtering uses NPC ID, not shared label',()=>{
  assert.deepEqual(model.filter(points,{world:'all',types:new Set(['NpcSpawn']),npcs:new Set(['2'])}).map(p=>p.key),['n2']);
});
test('cluster conserves all records and type boundaries',()=>{
  const groups=model.clusters(points,{x:0,y:0,s:1},500,500);
  assert.equal(groups.reduce((n,g)=>n+g.points.length,0),3);
  assert.equal(groups.length,2);
  assert.equal(groups.find(g=>g.type==='NpcSpawn').points.length,2);
});
test('offscreen records disappear only from drawing, not source filtering',()=>{
  const p=[...points,{key:'far',type:'NpcSpawn',world_id:'a',x:99999,y:99999}];
  assert.equal(model.clusters(p,{x:0,y:0,s:1},500,500).reduce((n,g)=>n+g.points.length,0),3);
  assert.equal(p.length,4);
});
test('search reaches translated place names independently of casing',()=>{
  assert.deepEqual(model.filter(points,{world:'all',types:new Set(['Area']),query:'KRVNA'}).map(p=>p.key),['area']);
});
test('missing destinations and items are not guessed',()=>{
  assert.deepEqual(model.itemsForNpc({npcs:{},items:{}},'missing'),[]);
  assert.deepEqual(model.portalDestination({portal_links:[{source_key:'other'}]},{key:'gate'}),[]);
});
test('empty fit uses full atlas bounds',()=>{
  assert.deepEqual(model.extent([],[-1,-2,3,4]),[-1,-2,3,4]);
});
test('non-origin tile bounds use right/bottom minus left/top',()=>{
  assert.deepEqual(model.tileRect([6144,8192,8192,10240]),{x:6144,y:8192,width:2048,height:2048});
  assert.deepEqual(model.tileRect([0,2048,2048,4096]),{x:0,y:2048,width:2048,height:2048});
});
test('all25 tile positions keep the same size and have no gaps or overlap',()=>{
  let area=0;
  for(let x=0;x<5;x++)for(let y=0;y<5;y++){
    const r=model.tileRect([x*2048,y*2048,(x+1)*2048,(y+1)*2048]);
    assert.equal(r.width,2048);assert.equal(r.height,2048);area+=r.width*r.height;
  }
  assert.equal(area,10240*10240);
});
test('invalid tile bounds fail instead of stretching a texture',()=>{
  assert.throws(()=>model.tileRect([4096,0,2048,2048]));
  assert.throws(()=>model.tileRect([0,0,NaN,2048]));
});
test('drop quantities keep different conditional outcomes without adding them',()=>{
  assert.deepEqual(model.dropAmounts([{min_count:'1',max_count:'2'},{min_count:'10',max_count:'10'},{min_count:'1',max_count:'2'}]),['1–2','10']);
  assert.deepEqual(model.dropAmounts([{min_count:'0',max_count:'0'}]),['0']);
});
test('monster choice groups repeated spawns by ID without conflating same names',()=>{
  const choices=model.monsterChoices([...points, {...points[0],key:'another'}]);
  assert.equal(choices.length,2);
  assert.equal(choices.find(g=>g.npc_id==='1').points.length,2);
  assert.equal(choices.find(g=>g.npc_id==='2').points.length,1);
});
test('area rewards selected by exact spawn area, never another placement or name',()=>{
  const a={status:'candidate_group_id_match_only',drops:{item:[]}};
  const detail={area_candidates:{'100201040':a,'other':{drops:{wrong:[]}}}};
  assert.equal(model.areaCandidate(detail,{area_id:'100201040'}),a);
  assert.equal(model.areaCandidate(detail,{area_id:'missing'}),null);
  assert.equal(model.areaCandidate(detail,{}),null);
});
test('area item filter returns area points, never residents as confirmed drop sources',()=>{
  const all=[...points,{key:'area2',type:'Area',id:'b',world_id:'b',label:'Other',x:1,y:2}];
  assert.deepEqual(model.filter(all,{world:'all',types:new Set(['NpcSpawn','Area']),areas:new Set(['a'])}).map(p=>p.key),['area']);
  assert.deepEqual(model.filter(all,{world:'all',types:new Set(['NpcSpawn','Area']),areas:new Set()}),[]);
});


test('skill level cooldown uses first inclusive range, not additive growth',()=>{
 const skill={record:{Id:'1',MinCoolTime:'30000',MaxCoolTime:'40000',provenance:{csv_record:2}},
  level_overrides:{cooldown_replacement_verified:true,records:[
   {SkillInfoId:'11',MinLevel:'6',MaxLevel:'7',ChangeMinCoolTime:'99',ChangeMaxCoolTime:'99'},
   {SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeMinCoolTime:'23000',ChangeMaxCoolTime:'0',provenance:{csv_record:3}},
   {SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeMinCoolTime:'5',ChangeMaxCoolTime:'5'}]}};
 for(const level of [5,6,7,8]){
  const result=model.skillCooldownAtLevel(skill,level);
  assert.equal(result.values.MinCoolTime,level===6||level===7?'23000':'30000');
  assert.equal(result.values.MaxCoolTime,'40000');
  assert.equal(result.runtime_cooldown_verified,false);
  assert.equal(result.origins.MaxCoolTime.table,'Skill');
 }
 assert.deepEqual(model.skillCooldownAtLevel(skill,6).origins.MinCoolTime.provenance,{csv_record:3});
});

test('skill level empty overrides fall back; unverified or invalid level never computes',()=>{
 const skill={record:{Id:'1',MinCoolTime:'0',MaxCoolTime:'1000'},level_overrides:{cooldown_replacement_verified:true,records:[
  {SkillInfoId:'1',MinLevel:'0',MaxLevel:'32767',ChangeMinCoolTime:'',ChangeMaxCoolTime:'000'}]}};
 assert.deepEqual(model.skillCooldownAtLevel(skill,0).values,{MinCoolTime:'0',MaxCoolTime:'1000'});
 assert.deepEqual(model.skillCooldownAtLevel(skill,32767).values,{MinCoolTime:'0',MaxCoolTime:'1000'});
 for(const level of [-1,32768,6.5,NaN,'6'])assert.throws(()=>model.skillCooldownAtLevel(skill,level));
 assert.throws(()=>model.skillCooldownAtLevel({...skill,level_overrides:{cooldown_replacement_verified:false,records:[]}},6));
});


test('skill resource and stack overrides require proof and preserve independent first-row fallback',()=>{
 const skill={record:{Id:'1',MinCoolTime:'1000',MaxCoolTime:'1000',Resource:'base',StackCount:'1'},
  level_overrides:{cooldown_replacement_verified:true,resource_replacement_verified:true,stack_count_replacement_verified:true,records:[
   {SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeMinCoolTime:'',ChangeMaxCoolTime:'',ChangeResource:'A',ChangeStackCount:'2'}]}};
 assert.equal(model.skillValuesAtLevel(skill,6).values.Resource,'A');
 assert.equal(model.skillValuesAtLevel(skill,7).values.StackCount,'2');
 assert.equal(model.skillValuesAtLevel(skill,5).values.Resource,'base');
 assert.equal(model.skillValuesAtLevel(skill,8).values.StackCount,'1');
 skill.level_overrides.records.unshift({...skill.level_overrides.records[0],ChangeResource:'',ChangeStackCount:'0'});
 assert.equal(model.skillValuesAtLevel(skill,6).values.Resource,'base');
 assert.equal(model.skillValuesAtLevel(skill,6).values.StackCount,'1');
 skill.level_overrides.records[0].ChangeResource=' ';
 assert.equal(model.skillValuesAtLevel(skill,6).values.Resource,' ');
 skill.level_overrides.resource_replacement_verified=false;
 assert.equal(Object.hasOwn(model.skillValuesAtLevel(skill,6).values,'Resource'),false);
});

test('skill StackCount byte overflow and malformed changes fail without wrapping or guessing',()=>{
 const skill={record:{Id:'1',MinCoolTime:'0',MaxCoolTime:'0',StackCount:'1'},
  level_overrides:{cooldown_replacement_verified:true,stack_count_replacement_verified:true,records:[
   {SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeStackCount:'256'}]}};
 for(const value of ['256','-1','2tail','２']){
  skill.level_overrides.records[0].ChangeStackCount=value;
  assert.throws(()=>model.skillValuesAtLevel(skill,6));
 }
});


test('MP level values independently replace base only with verified nonzero fields',()=>{
 const skill={record:{Id:'1',MinCoolTime:'0',MaxCoolTime:'0',MpMin:'10',MpMax:'20'},level_overrides:{
  cooldown_replacement_verified:true,mp_min_replacement_verified:true,mp_max_replacement_verified:true,
  records:[{SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeMpMin:'7',ChangeMpMax:'0'},
   {SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeMpMin:'1',ChangeMpMax:'1'}]}};
 for(const level of [6,7]){const result=model.skillValuesAtLevel(skill,level);assert.equal(result.values.MpMin,'7');assert.equal(result.values.MpMax,'20');assert.equal(result.origins.MpMax.table,'Skill');}
 for(const level of [5,8])assert.equal(model.skillValuesAtLevel(skill,level).values.MpMin,'10');
 skill.level_overrides.mp_min_replacement_verified=false;
 assert.equal(Object.hasOwn(model.skillValuesAtLevel(skill,6).values,'MpMin'),false);
});

test('invalid MP overrides are rejected instead of guessing amounts',()=>{
 const skill={record:{Id:'1',MinCoolTime:'0',MaxCoolTime:'0'},level_overrides:{cooldown_replacement_verified:true,mp_min_replacement_verified:true,
  records:[{SkillInfoId:'1',MinLevel:'6',MaxLevel:'7',ChangeMpMin:'0'}]}};
 for(const value of ['-1','2147483648','12tail','１２']){skill.level_overrides.records[0].ChangeMpMin=value;assert.throws(()=>model.skillValuesAtLevel(skill,6));}
});
