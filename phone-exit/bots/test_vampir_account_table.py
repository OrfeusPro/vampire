import json
from pathlib import Path
import subprocess
import unittest


class AccountTableTests(unittest.TestCase):
    def test_both_official_code_forms_use_the_same_confirm_control(self):
        source = Path(__file__).parent / 'vampir-headless/windows/verification-form.js'
        fixture = r'''
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[1], 'utf8');
class Input {
    constructor(placeholder, value = '') { this.placeholder = placeholder; this.value = value; }
    get value() { return this.text; }
    set value(value) { this.text = value; }
    getClientRects() { return [{}]; }
    dispatchEvent() {}
}
for (const [purpose, title, pathname] of [
    ['device-registration', 'Enter Verification Code', '/secure/device/additional/step3'],
    ['workplace', 'Verify with Email', '/restriction/release/email/step2'],
]) {
    let clicked = 0;
    const code = new Input('Enter only numbers.');
    const email = new Input('', 'test**@vampir.top');
    const context = vm.createContext({location:{origin:'https://profile-auth-view.netmarble.com',pathname},
        document:{body:{innerText:title},querySelectorAll:selector => ({
            input:[email,code], button:[{textContent:'Confirm',getClientRects:()=>[{}],click:()=>clicked++}],
            'iframe[title]':[],
        })[selector]}, HTMLInputElement:Input, Event:class {},
    });
    const run = vm.runInContext(source, context);
    assert.equal(run({purpose,email:'other@vampir.top',code:'12345',actions:['mail_requested']}), 'waiting');
    assert.equal(clicked, 0);
    assert.equal(run({purpose,email:'tester@vampir.top',code:'12345',actions:['mail_requested']}), 'code_submitted');
    assert.equal(code.value, '12345');
    assert.equal(clicked, 1);
    assert.equal(run({purpose,email:'tester@vampir.top',code:'12345',actions:['mail_requested','code_submitted']}), 'waiting');
    assert.equal(clicked, 1);
}
'''
        result = subprocess.run(['node', '-e', fixture, str(source.resolve())], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_password_reveals_only_on_click_and_blur_clears_it(self):
        source = Path(__file__).parent / 'vampir-headless/console/console.js'
        fixture = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
class Element{
 constructor(){this.children=[];this.elements=[];this.value='';this.dataset={};this.attributes={};}
 append(...items){this.children.push(...items);}
 replaceChildren(...items){this.children=items;}
 setAttribute(key,value){this.attributes[key]=value;}
 get options(){return this.children;}
}
const nodes=new Map(),events={},calls=[];
const document={hasFocus:()=>true,querySelector:()=>({content:'fixture-token'}),createElement:()=>new Element(),getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);}};
const state={accounts:[],jobs:{},catalogs:{},character_lists:{},creation_classes:[]};
const context=vm.createContext({document,window:{addEventListener:(name,fn)=>events[name]=fn},setInterval:()=>0,
 fetch:async(path,request)=>{calls.push({path,request});return {ok:true,json:async()=>path==='/api/reveal'?{password:'fake-private-secret'}:state};}});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{
 await new Promise(resolve=>setImmediate(resolve));
 vm.runInContext(`snapshot={accounts:[{id:'fixture',email:'fixture@unit.invalid',region:'EU',server_id:384,password_saved:true,mail_password_saved:true,mail_status:'planned',create_class:'Gunner',character_key:'11'}],jobs:{},catalogs:{EU:{servers:[{id:384,name:'Prelude 2'}]}},creation_classes:[{key:'Gunner',label:'Carnage'}],character_lists:{'fixture|EU|384':{characters:[{key:'11',name:'Confirmed'}]}}};renderRoster();`,context);
 let row=nodes.get('roster-body').children[0];
 assert.equal(row.children.length,7);assert.equal(row.children[3].textContent,'Confirmed');
 assert.equal(row.children[5].textContent,'EU · Prelude 2');assert.equal(row.children[6].textContent,'Ящик ещё не создан');
 assert.equal(calls.filter(c=>c.path==='/api/reveal').length,0);
 await row.children[1].children[0].children[1].onclick();
 row=nodes.get('roster-body').children[0];assert.equal(row.children[1].children[0].children[0].textContent,'fake-private-secret');
 assert.deepEqual(JSON.parse(calls.at(-1).request.body),{id:'fixture',kind:'mail'});
 events.blur();row=nodes.get('roster-body').children[0];
 assert.equal(row.children[1].children[0].children[0].textContent,'••••••••');
 assert.equal(vm.runInContext('shownPasswords.size',context),0);
 vm.runInContext(`snapshot.accounts[0].mail_status='verified';snapshot.accounts[0].registration_status='registered';snapshot.jobs.fixture={operation:'register',running:false,status:'stopped'};renderRoster();`,context);
 assert.match(nodes.get('roster-body').children[0].children[6].textContent,/Netmarble зарегистрирован/);
 let copied='',writes=0;
 context.navigator={clipboard:{writeText:async text=>{copied=text;writes++;}}};
 const cell=text=>({textContent:text,querySelector:()=>null});
 document.getElementById('roster').rows=[{cells:['Почта','Пароль почты','Пароль Netmarble'].map(cell)},
  {cells:['fixture@unit.invalid','••••••••','••••••••'].map(cell)}];
 const before=calls.filter(c=>c.path==='/api/reveal').length;
 await nodes.get('copy-roster').onclick();
 assert.equal(copied,'Почта\tПароль почты\tПароль Netmarble\r\nfixture@unit.invalid\tfake-private-secret\tfake-private-secret');
 assert.deepEqual(calls.filter(c=>c.path==='/api/reveal').slice(before).map(c=>JSON.parse(c.request.body).kind),['mail','netmarble']);
 assert.equal(vm.runInContext('shownPasswords.size',context),0);
 assert.equal(nodes.get('copy-roster').disabled,false);
 context.fetch=async()=>({ok:false,json:async()=>({error:'fixture failure'})});
 await nodes.get('copy-roster').onclick();
 assert.equal(writes,1);assert.match(nodes.get('copy-roster-status').textContent,/Не удалось/);
 assert.equal(nodes.get('copy-roster').disabled,false);
 process.stdout.write('passed');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', fixture, str(source.resolve())], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'passed')


if __name__ == '__main__': unittest.main()
