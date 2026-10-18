const test=require('node:test'),assert=require('node:assert/strict');
const model=require('./resource-tools/vampir/items-catalog-model.js');
test('book kind requires a verified target, with explicit unknown rather than guessing from candidate data',()=>{
  const active={relation_verified:true,target:{id:'110016'},kind:'active'};
  assert.equal(model.matchesBookKind(active,'active'),true);
  assert.equal(model.matchesBookKind(active,'passive'),false);
  assert.equal(model.bookKind({...active,relation_verified:false}),'unknown');
  assert.equal(model.bookKind({...active,target:null}),'unknown');
  assert.equal(model.bookKind({...active,kind:'0'}),'unknown');
  assert.equal(model.matchesBookKind(undefined,'unknown'),true);
  assert.equal(model.matchesBookKind(undefined,'all'),true);
  assert.equal(model.matchesBookKind({relation_verified:true,target:{id:'1'},kind:'passive'},'passive'),true);
});
test('book target name uses exact display text and falls back to its ID',()=>{
  assert.equal(model.bookSkillName({target:{id:'110016',display_names:[{text:'Whirlpool'},{text:'Whirlpool'}]}}),'Whirlpool');
  assert.equal(model.bookSkillName({target:{id:'110016',display_names:[]}}),'Навык 110016');
});
test('monster reward source filter requires an explicit NPC origin and supports empty sources',()=>{
  assert.equal(model.matchesSource([{npc_id:'400006'}],'npcs'),true);
  assert.equal(model.matchesSource([{area_id:'10020'}],'npcs'),false);
  assert.equal(model.matchesSource(undefined,'npcs'),false);
  assert.equal(model.matchesSource([],'no-npcs'),true);
  assert.equal(model.matchesSource([{npc_id:'400006'}],'no-npcs'),false);
  assert.equal(model.matchesSource(undefined,'all'),true);
});
test('book sources retain exact NPC IDs, deduplicate chains, and route beyond Nocturne',()=>{
  const origins=[{npc_id:'400004'},{npc_id:'400006'},{npc_id:'400008'},{npc_id:'400006'},{}];
  assert.deepEqual(model.sourceNpcIds(origins),['400004','400006','400008']);
  assert.deepEqual(model.sourceNpcIds(),[]);
  const target=new URL(model.sourceMapUrl('22023005'),'http://127.0.0.1:17946/maps/loot/items.html');
  assert.equal(target.pathname,'/maps/atlas/world.html');
  assert.equal(target.searchParams.get('item'),'22023005');
});
test('effect filter keeps exact IDs and never infers a type from EffectParams',()=>{
  const item={data:{EffectType:'1',EffectParams:'13'}};
  assert.equal(model.matches(item,{effect:'1'}),true);
  assert.equal(model.matches(item,{effect:'13'}),false);
  assert.equal(model.matches({data:{EffectParams:'1'}},{effect:'1'}),false);
  assert.equal(model.matches({data:{EffectType:'10'}},{effect:'1'}),false);
});
test('unknown effect and explicit None remain distinct, including code zero',()=>{
  const types={'0':{name:'None'},'1':{name:'Effect'}};
  assert.equal(model.effectLabel('0',types),'Нет эффекта · 0');
  assert.equal(model.effectLabel('20',types),'Тип не расшифрован · 20');
  assert.equal(model.effectLabel('',types),'Тип не указан');
  assert.equal(model.matches({data:{EffectType:'20'}},{effect:'0'}),false);
});
test('passive and restriction filters use declarations, not names, descriptions or rewards',()=>{
  const data={PassiveSkillGroupId:'g',LimitGroupId:'',ItemUseLimitId:'u'};
  assert.deepEqual(model.flags({data}),{passive:true,limits:true});
  assert.equal(model.matches({data},{passive:'yes',limits:'yes'}),true);
  assert.equal(model.matches({data},{passive:'no'}),false);
  assert.equal(model.matches({data:{},names_en:[{Desc:'Passive skill with restrictions'}]},{passive:'yes'}),false);
  assert.deepEqual(model.flags({data:{PassiveSkillGroupId:' ',LimitGroupId:null}}),{passive:false,limits:false});
  assert.equal(model.flags({data:{ItemUseLimitId:'0'}}).limits,true);
});
test('effect, passive and restriction filters intersect without mutating input',()=>{
  const item={data:{EffectType:'1',PassiveSkillGroupId:'2',LimitGroupId:'3'}},before=JSON.stringify(item);
  assert.equal(model.matches(item,{effect:'1',passive:'yes',limits:'yes'}),true);
  assert.equal(model.matches(item,{effect:'1',passive:'yes',limits:'no'}),false);
  assert.equal(model.matches(item,{effect:'all',passive:'all',limits:'all'}),true);
  assert.equal(JSON.stringify(item),before);
});
