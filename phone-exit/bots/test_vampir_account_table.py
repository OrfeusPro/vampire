import json
from pathlib import Path
import subprocess
import unittest


class AccountTableTests(unittest.TestCase):
    def test_manual_netmarble_form_rejects_the_wrong_account(self):
        source = Path(__file__).parent / 'vampir-headless/windows/nid-sign-in.js'
        fixture = r'''
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const events = {}, messages = [];
const email = {type:'text', placeholder:'Email', value:'other@vampir.top'};
const window = {chrome:{webview:{postMessage:message=>messages.push(message)}}};
window.top = window;
const location = {origin:'https://members.netmarble.com', pathname:'/auth'};
const document = {querySelectorAll:()=>[email], addEventListener:(name,fn)=>events[name]=fn};
const run = vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'), {window, location, document});
run({bindManual:true,email:'fixture@vampir.top'});
location.pathname = '/auth/signin/email';
let blocked = 0;
const click = {type:'click',target:{closest:()=>({textContent:'Sign in with email'})},
  preventDefault:()=>blocked++,stopImmediatePropagation:()=>{}};
events.click(click);
assert.equal(blocked,1);
assert.equal(messages.at(-1),'manual_email_mismatch');
email.value='FIXTURE@vampir.top';
events.click(click);
assert.equal(blocked,1);
assert.equal(messages.at(-1),'manual_email_matched');
'''
        result = subprocess.run(['node', '-e', fixture, str(source.resolve())], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

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
 assert.equal(row.children.length,8);assert.equal(row.children[3].textContent,'Confirmed');
 assert.equal(row.children[5].textContent,'EU · Prelude 2');assert.equal(row.children[7].textContent,'Ящик ещё не создан');
 assert.equal(calls.filter(c=>c.path==='/api/reveal').length,0);
 await row.children[1].children[0].children[1].onclick();
 row=nodes.get('roster-body').children[0];assert.equal(row.children[1].children[0].children[0].textContent,'fake-private-secret');
 assert.deepEqual(JSON.parse(calls.at(-1).request.body),{id:'fixture',kind:'mail'});
 events.blur();row=nodes.get('roster-body').children[0];
 assert.equal(row.children[1].children[0].children[0].textContent,'••••••••');
 assert.equal(vm.runInContext('shownPasswords.size',context),0);
 vm.runInContext(`snapshot.accounts[0].mail_status='verified';snapshot.accounts[0].registration_status='registered';snapshot.jobs.fixture={operation:'register',running:false,status:'stopped'};renderRoster();`,context);
 assert.match(nodes.get('roster-body').children[0].children[7].textContent,/Netmarble зарегистрирован/);
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
 context.fetch=async(path,request)=>({ok:true,json:async()=>({password:JSON.parse(request.body).id})});
 vm.runInContext(`snapshot.accounts.unshift({id:'active',email:'active@vampir.top',region:'EU',server_id:384,
  active_game_account:true,reported_character_name:'Reported',password_saved:true,mail_password_saved:true,create_class:'Gunner'});
  renderRoster();`,context);
 const [ordinary,active]=nodes.get('roster-body').children;
 assert.equal(ordinary.children[0].children.at(-1).textContent,'fixture@unit.invalid');
 assert.equal(active.className,'active-game-account');
 assert.equal(active.children[3].textContent,'Reported');
 assert.equal(active.children[5].textContent,'EU · Prelude 2');
 document.getElementById('roster').rows.push({cells:['active@vampir.top','••••••••','••••••••'].map(cell)});
 await nodes.get('copy-roster').onclick();
 assert.match(copied,/fixture@unit.invalid\tfixture\tfixture\r\nactive@vampir.top\tactive\tactive$/);
 vm.runInContext(`snapshot.accounts.push({id:'google',email:'google@unit.invalid',login_provider:'google',region:'EU',server_id:381,
  character_index:null,character_key:null,active_game_account:true,reported_character_name:'Player',reported_device:'UgPhone',
  password_saved:false,mail_password_saved:false,create_class:'Gunner'});renderRoster();`,context);
 const google=nodes.get('roster-body').children.at(-1);
 assert.equal(google.children.length,8);
 assert.equal(google.className,'active-game-account');
 assert.equal(google.children[3].textContent,'Player');
 assert.equal(google.children[6].textContent,'UgPhone');
 assert.match(google.children[7].textContent,/Google/);
 assert.equal(google.children[0].children[0].disabled,true);
 for(const column of [1,2]){assert.equal(google.children[column].children[0].children[0].textContent,'—');assert.equal(google.children[column].children[0].children[1].disabled,true);}
 vm.runInContext('edit(snapshot.accounts.at(-1))',context);
 assert.equal(nodes.get('login-provider').value,'google');
 assert.equal(nodes.get('login-provider').disabled,true);
 assert.equal(nodes.get('password').required,false);assert.equal(nodes.get('password').disabled,true);
 for(const id of ['start','servers','characters','create','register','prepare-sdk','manual-sign-in'])assert.equal(nodes.get(id).disabled,true,id);
 assert.match(nodes.get('provider-hint').textContent,/пока не подключён/);
 vm.runInContext("edit(null);el('login-provider').value='google';el('login-provider').onchange();",context);
 assert.equal(nodes.get('login-provider').disabled,false);assert.equal(nodes.get('password').required,false);
 vm.runInContext("el('login-provider').value='email';el('login-provider').onchange();",context);
 assert.equal(nodes.get('password').required,true);assert.equal(nodes.get('password').disabled,false);
 process.stdout.write('passed');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', fixture, str(source.resolve())], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'passed')


if __name__ == '__main__': unittest.main()
