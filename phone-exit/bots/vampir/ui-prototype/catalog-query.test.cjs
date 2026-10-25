'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const Q = require('./catalog-query.js');
const records = [
  {id:'screen',name:'WBP_AchievementUI',path:'/Game/RED/UI/Achievement/WBP_AchievementUI',popup:false,variants:2},
  {id:'row',name:'WBP_AchievementListT',path:'/Game/RED/UI/Achievement/WBP_AchievementListT',popup:false,variants:1},
  {id:'lower',name:'WBP_uipanel',path:'/Game/RED/UI/Common/WBP_uipanel',popup:false,variants:1},
  {id:'unresolved',name:'WBP_UIPopup',path:'unresolved:sample.json',popup:true,variants:1}
];
test('uppercase UI name selection excludes directory-only and lowercase matches',()=>{
  assert.deepEqual(Q.filter(records,{query:'UI',scope:'all'}).map(r=>r.id),['screen','row','lower','unresolved']);
  assert.deepEqual(Q.filter(records,{query:'UI',scope:'ui-name'}).map(r=>r.id),['screen','unresolved']);
});
test('name-only search and popup filters compose without losing unresolved names',()=>{
  assert.deepEqual(Q.filter(records,{query:'achievement',scope:'ui-name',kind:'other'}).map(r=>r.id),['screen']);
  assert.deepEqual(Q.filter(records,{scope:'ui-name',kind:'popup'}).map(r=>r.id),['unresolved']);
  assert.equal(Q.filter(records,{query:'/Game/',scope:'name'}).length,0);
});
test('selection preserves resource identity, variants and source order without mutation',()=>{
  const snapshot=JSON.stringify(records), chosen=Q.filter(records,{scope:'ui-name'});
  assert.equal(chosen[0],records[0]);assert.equal(chosen[0].variants,2);
  assert.equal(JSON.stringify(records),snapshot);
});
test('unknown modes fail instead of silently broadening the worklist',()=>{
  assert.throws(()=>Q.filter(records,{scope:'guess'}));assert.throws(()=>Q.filter(records,{kind:'guess'}));
});
