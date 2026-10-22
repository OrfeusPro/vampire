const assert=require('node:assert/strict');
const {translator}=require('./resource-tools/vampir/atlas-locale.js');
const locale=translator({'Blood Pool':'Бассейн крови','Sword':'Меч','Skill {ReplaceString1}':'Навык {ReplaceString1}','First\nsecond':'Первая\nвторая'});
const source={label:'Blood Pool',names_en:[{Id:'123',Name:'Sword',provenance:{name:'Sword'}}],
  data:{Name:'Sword',Id:'123'},row:{label:'Sword'},file:'Sword',sha256:'Sword',description:'First\nsecond'};
const result=locale.localize(source);
assert.equal(result.label,'Бассейн крови');assert.equal(result.names_en[0].Name,'Меч');
assert.equal(result.names_en[0].Id,'123');assert.equal(result.file,'Sword');assert.equal(result.sha256,'Sword');
assert.deepEqual(result.data,source.data);assert.deepEqual(result.row,source.row);assert.deepEqual(result.names_en[0].provenance,source.names_en[0].provenance);
assert.equal(source.label,'Blood Pool');assert.equal(result.description,'Первая\nвторая');
assert.equal(locale.text('Skill 12'),'Навык 12');assert.equal(locale.text('Sword / Blood Pool'),'Меч / Бассейн крови');
assert.equal(locale.text('Unknown'),'Unknown');assert.equal(locale.text('123'),'123');
console.log('Atlas RU: labels, names, descriptions, templates, fallback and unchanged IDs/raw data verified');
