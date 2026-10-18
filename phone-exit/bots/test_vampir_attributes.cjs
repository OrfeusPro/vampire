const test=require('node:test'),assert=require('node:assert/strict');
const model=require('./resource-tools/vampir/attributes-model.js');
const e=(id,tab,group,order,percent='0')=>({id,tab_id:tab,name:'ATK '+id,description:'Damage dealt',enum:{name:'EOperationType::Attack'},row:{StatType:'37',DisplayOrder:order,IsPercentage:percent},group:group?{GroupOrder:group}:null});
test('client tabs, group order and display order sort numerically; unassigned last',()=>{
 const rows=[e('1','unassigned',null,''),e('2','200','1','1'),e('3','100','2','1'),e('4','100','1','10'),e('5','100','1','2')];
 assert.deepEqual(model.select(rows).map(e=>e.id),['5','4','3','2','1']);assert.equal(rows[0].id,'1');
});
test('search includes description, enum and StatType; filters intersect',()=>{
 const rows=[e('1','100','1','1','1'),e('2','200','1','1')];
 assert.equal(model.select(rows,{q:' DAMAGE ',unit:'percent',tab:'100'}).length,1);
 assert.equal(model.select(rows,{q:'EOperationType',tab:'unassigned'}).length,0);
 assert.equal(model.select(rows,{q:'37',unit:'value'}).length,1);
 assert.equal(model.select(rows,{q:'missing'}).length,0);
});
test('missing order stays after numeric zero and hidden flags do not remove entries',()=>{
 const rows=[e('1','100','1',''),e('2','100','1','0')];rows[1].row.InvisibleStat='1';
 assert.deepEqual(model.select(rows).map(e=>e.id),['2','1']);
});
test('tree separates effect direction from opposed interactions and drops unknown endpoints',()=>{
 const entries=[{id:'a'},{id:'b'},{id:'c'}],relations=[{source:'a',target:'b',kind:'modifier'},
 {source:'b',target:'c',kind:'modifier'},{source:'c',target:'b',kind:'opposed'},
 {source:'absent',target:'b',kind:'modifier'}];
 const result=model.neighborhood(entries,relations,'b');
 assert.deepEqual(result.incoming,[relations[0]]);assert.deepEqual(result.outgoing,[relations[1]]);assert.deepEqual(result.opposed,[relations[2]]);
 assert.deepEqual(model.neighborhood(entries,relations,'unknown'),{incoming:[],outgoing:[],opposed:[]});
});
test('cyclic graph stays one neighborhood, without recursive expansion',()=>{
 const result=model.neighborhood([{id:'a'},{id:'b'}],[{source:'a',target:'b',kind:'modifier'},{source:'b',target:'a',kind:'modifier'}],'a');
 assert.equal(result.incoming.length,1);assert.equal(result.outgoing.length,1);
});
test('weighted contribution preserves float32 rounding and does not fill missing weights',()=>{
 assert.deepEqual(model.weightedContribution('1','4000'),{status:'known',result:4000});
 assert.deepEqual(model.weightedContribution('16777217','1'),{status:'known',result:16777216});
 assert.deepEqual(model.weightedContribution('-16777217','1'),{status:'known',result:-16777216});
 assert.equal(model.weightedContribution('1','').status,'unknown_weight');
 assert.equal(model.weightedContribution('1.5','10').status,'invalid');
 assert.equal(model.weightedContribution('1','32768').status,'invalid');
 assert.deepEqual(model.weightedContribution('20','0'),{status:'known',result:0});
 assert.equal(model.weightedContribution('1000000','8000').status,'out_of_range');
});
const fs=require('node:fs'),nativeProof='F:/PhoneExit Resources/Vampir/code-clues/attribute-weight-evidence.json';
test('browser arithmetic agrees with every captured native contribution within supported range',{skip:!fs.existsSync(nativeProof)},()=>{
 const proof=JSON.parse(fs.readFileSync(nativeProof,'utf8'));
 let checked=0;
 for(const c of proof.cases){
  if(c.accumulator!==0)continue;
  const actual=model.weightedContribution(String(c.value),String(c.weight));
  if(actual.status==='out_of_range')continue;
  assert.equal(actual.status,'known');for(const expected of c.results)assert.equal(actual.result,expected);checked++;
 }
 assert.ok(checked>=857);
});
