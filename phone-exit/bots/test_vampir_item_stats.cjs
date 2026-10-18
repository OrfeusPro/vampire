const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('./resource-tools/vampir/item-stat-model.js');
const op = (type, min, max = min) => ({row:{Type:type,OperationRarity:'102',Min:min,Max:max}});
const part = (operations, category = '0') => ({row:{OperationCategory:category,IsExtra:'0',Index:''},operations});
test('shows source base plus enhancement difference without adding snapshots', () => {
  const current = op('542','277'), selected = part([current]);
  assert.deepEqual(model.compare(current,selected,[part([op('542','170')])]),{base:'170',delta:'+107',total:'277',added:false});
});
test('unchanged and newly added stats', () => {
  const same=op('408','3'),added=op('412','87'),selected=part([same,added]);
  const base=part([op('408','3')]);
  assert.equal(model.compare(same,selected,[base]).delta,null);
  assert.deepEqual(model.compare(added,selected,[base]),{base:'0',delta:'+87',total:'87',added:true});
});
test('missing base, ambiguous parameters and conditional categories are not guessed', () => {
  const current=op('1','5'),selected=part([current]);
  for(const base of [[],[part([op('1','1')],'2')],[part([op('1','1'),op('1','2')])]]) assert.equal(model.compare(current,selected,base).delta,null);
});
test('decimal differences, decreases and ranges preserve source units', () => {
  assert.equal(model.subtract('0.3','0.1'),'+0.2');
  assert.equal(model.subtract('-0.20','0.10'),'-0.3');
  assert.equal(model.subtract('12','12'),'0');
  assert.equal(model.subtract('','0'),null);
  const current=op('1','2.5','4.1');
  assert.equal(model.compare(current,part([current]),[part([op('1','3','4')])]).delta,'-0.5–+0.1');
});
