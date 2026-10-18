const test=require('node:test'),assert=require('node:assert/strict');
const {matchesRelation:matches}=require('./resource-tools/vampir/skills-catalog-model.js');
test('rank order uses source rarity, alphabet within rank, unknown/special grades last',()=>{
  const {compare}=require('./resource-tools/vampir/skills-catalog-model.js');
  const rows=['a','b','c','d','e'].map((id,i)=>({id,display_names:[{text:['Zulu','Beta','Alpha','Unknown','Special'][i]}]}));
  const meta={a:{rarity_raw:'0'},b:{rarity_raw:'3'},c:{rarity_raw:'3'},d:{rarity_raw:''},e:{rarity_raw:'100'}};
  assert.deepEqual([...rows].sort((a,b)=>compare(a,b,meta)).map(x=>x.id),['c','b','a','e','d']);
  assert.deepEqual([...rows].sort((a,b)=>compare(a,b,meta,'rank-asc')).map(x=>x.id),['a','c','b','e','d']);
  assert.equal([...rows].sort((a,b)=>compare(a,b,meta,'name'))[0].id,'c');
});
test('Registered date placeholders require explicit service filter',()=>{
  const entry={display_names:[{text:'2025-08-08 Registered'}],book_count:1};
  assert.equal(matches(entry),false);assert.equal(matches(entry,'books'),false);
  assert.equal(matches(entry,'service'),true);
  assert.equal(matches({display_names:[{text:'Registered Strike'}]}),true);
  assert.equal(matches({display_names:[{text:'2025-08-08 Registered'},{text:'Real name'}]}),true);
  assert.equal(matches({display_names:[{text:'Frenzy'}]},'service'),false);
});
test('NPC skills require explicit NPC filter even with books/items or matching class',()=>{
  const npc={all_npc_ids:['400006'],npc_ids:[],book_count:1,passive_item_count:1};
  for(const relation of ['all','books','items'])assert.equal(matches(npc,relation),false);
  assert.equal(matches(npc,'npcs'),true);
});
test('all-world NPC IDs take precedence over the Nocturne subset',()=>{
  assert.equal(matches({all_npc_ids:['x'],npc_ids:[]}),false);
  assert.equal(matches({npc_ids:['x']},'npcs'),true);
  assert.equal(matches({all_npc_ids:[],npc_ids:['x']},'npcs'),false);
});
test('ordinary skill filters still intersect declared book and item links',()=>{
  const skill={all_npc_ids:[],book_count:1,passive_item_count:0};
  assert.equal(matches(skill),true);assert.equal(matches(skill,'books'),true);
  assert.equal(matches(skill,'items'),false);assert.equal(matches(skill,'npcs'),false);
});
