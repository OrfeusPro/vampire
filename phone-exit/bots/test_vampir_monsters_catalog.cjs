const test=require('node:test'),assert=require('node:assert/strict');
const model=require('./resource-tools/vampir/monsters-catalog-model.js');
const rows=[
  {id:'1',name:'Same',level:'10',world_ids:['10017'],drop_item_count:2},
  {id:'2',name:'Same',level:'2',world_ids:['100171'],drop_item_count:0,reward_rows:7},
  {id:'3',name:'Unknown',level:'',world_ids:[],drop_item_count:1},
  {id:'4',name:'Malformed',level:'abc',world_ids:['10017'],drop_item_count:0},
];
test('portrait filter uses resolved images, never blueprint names or mere declarations',()=>{
  const data=[{...rows[0],portraits:{status:'found',images:[{file:'a.png'}]}},
    {...rows[1],portraits:{status:'missing',images:[]}}, {...rows[2],Blueprint:'BP_Portrait'}];
  assert.deepEqual(model.select(data,{images:'yes'}).map(n=>n.id),['1']);
  assert.deepEqual(model.select(data,{images:'no'}).map(n=>n.id),['2','3']);
});
test('NPC numeric levels sort correctly and unknown levels stay last in either direction',()=>{
  assert.deepEqual(model.select(rows,{sort:'level'}).map(n=>n.id),['2','1','4','3']);
  assert.deepEqual(model.select(rows,{sort:'level-desc'}).map(n=>n.id),['1','2','4','3']);
  assert.equal(model.level(rows[2]),null);
  assert.equal(model.level({level:'0'}),0);
});
test('NPC level range intersects exact world IDs and excludes unknown levels',()=>{
  assert.deepEqual(model.select(rows,{world:'10017',min:'2',max:'10'}).map(n=>n.id),['1']);
  assert.deepEqual(model.select(rows,{min:'10',max:'2'}),[]);
  assert.deepEqual(model.select(rows,{world:'1001'}),[]);
});
test('personal item filter does not use generic reward rows or common NPC names',()=>{
  assert.deepEqual(model.select(rows,{query:'same',dropsOnly:true}).map(n=>n.id),['1']);
  assert.deepEqual(model.select(rows,{query:'2',dropsOnly:true}),[]);
  const original=JSON.stringify(rows);model.select(rows,{sort:'name'});assert.equal(JSON.stringify(rows),original);
});
