const test=require('node:test'),assert=require('node:assert/strict');
const model=require('./resource-tools/vampir/catalog-class-model.js');
test('class filter distinguishes shared, unknown, conflicts and exact named classes',()=>{
  assert.equal(model.matches({status:'all',keys:[]},'DarkMage'),true);
  assert.equal(model.matches({status:'unknown',keys:[]},'DarkMage'),false);
  assert.equal(model.matches(undefined,'unknown'),true);
  assert.equal(model.matches({status:'conflict',keys:[]},'unknown'),true);
  assert.equal(model.matches({status:'specified',keys:['DarkMage','Reaper']},'Reaper'),true);
  assert.equal(model.matches({status:'specified',keys:['DarkMageExtra']},'DarkMage'),false);
  assert.equal(model.matches({status:'all',keys:[]},'unknown'),false);
  assert.equal(model.matches(undefined,'all'),true);
});
test('labels expose unknown and conflict instead of claiming all-character eligibility',()=>{
  assert.equal(model.label({status:'specified',keys:['DarkMage']},[{key:'DarkMage',label:'Viper'}]),'Viper');
  assert.equal(model.label(undefined,[]),'Класс не указан');
  assert.equal(model.label({status:'all',keys:[]},[]),'Все классы');
  assert.equal(model.label({status:'conflict',keys:[]},[]),'Данные класса расходятся');
});
