const test=require('node:test'),assert=require('node:assert/strict');
const model=require('./resource-tools/vampir/collections-model.js');
const item={a:{name:'Rusty Sword'},b:{name:'Moon Stone'}};
const entry=(id,rarity,name,tab='1',type='423',iid='a')=>({id,name,row:{Rarity:rarity,CollectionTabId:tab},requirements:[{row:{CollectParam:iid},item_id:iid}],bonuses:[{row:{Type:type,Min:'3',Max:'3'},name:{Name:'Accuracy'}}]});
test('search finds member names and IDs as well as collection names and bonuses',()=>{
  const entries=[entry('12','0','Night'),entry('123','1','Veil','2','424','b')];
  assert.deepEqual(model.select(entries,item,{q:'rusty'}).map(e=>e.id),['12']);
  assert.deepEqual(model.select(entries,item,{q:'moon stone'}).map(e=>e.id),['123']);
  assert.equal(model.select(entries,item,{q:' ACCURACY '}).length,2);
  assert.equal(model.select(entries,item,{q:'absent'}).length,0);
});
test('tab, rarity zero and bonus filters intersect by exact field values',()=>{
  const entries=[entry('1','0','A'),entry('2','1','B','1','423'),entry('3','0','C','10','4230')];
  assert.deepEqual(model.select(entries,item,{tab:'1',rarity:'0',bonus:'423'}).map(e=>e.id),['1']);
  assert.equal(model.select(entries,item,{tab:'2'}).length,0);
});
test('rarity sorting puts normal grades ahead of special and unknown values, then alphabet',()=>{
  const entries=[entry('1','100','A'),entry('2','0','Z'),entry('3','3','C'),entry('4','3','B'),entry('5','102','A')];
  assert.deepEqual(model.select(entries,item,{sort:'rank'}).map(e=>e.id),['4','3','2','1','5']);
  assert.deepEqual(entries.map(e=>e.id),['1','2','3','4','5']);
});
test('alphabet sorting ignores rank and resolves ties by numeric ID',()=>{
  assert.deepEqual(model.select([entry('12','3','B'),entry('2','0','B'),entry('3','0','A')],item,{sort:'name'}).map(e=>e.id),['3','2','12']);
});
test('unknown bonus keeps ID and raw fractional ranges without invented percentages',()=>{
  const b={row:{Type:'999',Min:'0.5',Max:'2'}};
  assert.equal(model.bonusName(b),'Параметр 999');assert.equal(model.bonusValue(b),'0.5–2');
});
test('source order uses numeric categories and DisplayOrder while ties retain source sequence',()=>{
  const entries=[entry('a','0','Z','2'),entry('b','0','Z'),entry('c','3','A'),entry('d','0','B'),entry('e','0','A','10')];
  for(const [i,n]of ['1','10','2','2','1'].entries())entries[i].row.DisplayOrder=n;
  assert.deepEqual(model.select(entries,item,{sort:'source'}).map(e=>e.id),['c','d','b','a','e']);
  assert.deepEqual(model.select(entries,item,{sort:'source',tab:'1'}).map(e=>e.id),['c','d','b']);
  assert.deepEqual(entries.map(e=>e.id),['a','b','c','d','e']);
});
test('default quality increases from common and uses DisplayOrder within each grade',()=>{
  const entries=[entry('a','2','A'),entry('b','0','Z'),entry('c','1','Y'),entry('d','0','A'),entry('e','100','Special'),entry('f','102','Unknown')];
  entries[1].row.DisplayOrder='2';entries[3].row.DisplayOrder='10';
  assert.deepEqual(model.select(entries,item).map(e=>e.id),['b','d','c','a','e','f']);
  assert.deepEqual(model.select(entries,item,{sort:'quality'}).map(e=>e.id),['b','d','c','a','e','f']);
});
test('missing or malformed DisplayOrder is not interpreted as zero',()=>{
  const entries=[entry('a','0','A'),entry('b','0','B'),entry('c','0','C'),entry('d','0','D')];
  entries[1].row.DisplayOrder='0';entries[2].row.DisplayOrder='bad';entries[3].row.DisplayOrder='2';
  assert.deepEqual(model.select(entries,item).map(e=>e.id),['b','d','a','c']);
});
