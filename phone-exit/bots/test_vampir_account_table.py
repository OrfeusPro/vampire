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

    def test_table_dialogs_keep_viewing_separate_from_saving_and_game_actions(self):
        source = Path(__file__).parent / 'vampir-headless/console/console.js'
        fixture = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes=new Map(),events={},calls=[];
class Element{
 constructor(){this.children=[];this.elements=[];this.value='';this.dataset={};this.attributes={};this.listeners={};this.open=false;this._text='';}
 append(...items){this.children.push(...items);}
 replaceChildren(...items){this.children=items;this._text='';}
 setAttribute(key,value){this.attributes[key]=value;}
 get parentElement(){if(!this._parent)this._parent=new Element();return this._parent;}
 querySelector(selector){if(!this._span)this._span=new Element();return this._span;}
 addEventListener(name,fn){this.listeners[name]=fn;}
 showModal(){this.open=true;}
 close(){this.open=false;this.listeners.close?.();}
 set id(value){this._id=value;nodes.set(value,this);}
 get id(){return this._id;}
 set textContent(value){this._text=String(value);this.children=[];}
 get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}
 get options(){return this.children;}
 get selectedOptions(){return this.children.filter(x=>String(x.value)===String(this.value));}
}
const document={hasFocus:()=>true,querySelector:()=>({content:'fixture-token'}),querySelectorAll:()=>[],createElement:()=>new Element(),getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);}};
const state={accounts:[],jobs:{},catalogs:{},character_lists:{},creation_classes:[],device_templates:[]};
const pc={device_settings:{cpu:{vendor:'AuthenticAMD',brand:'Fixture CPU'},windows:{major:10,minor:0,build:12345,product_type:1,suite_mask:256}},display_metadata:{I_NMCPU:'AuthenticAMD|Fixture CPU'},unknown:[],source:'Fixture source'};
let copied='',writes=0;
const fixtureFetch=async(path,request)=>{calls.push({path,request});return {ok:true,json:async()=>path==='/api/reveal'?{password:'fake-private-secret'}:path==='/api/current-pc'?pc:state};};
const context=vm.createContext({document,structuredClone,window:{addEventListener:(name,fn)=>events[name]=fn},setInterval:()=>0,navigator:{clipboard:{writeText:async text=>{copied=text;writes++;}}},
 fetch:fixtureFetch});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{
 await new Promise(resolve=>setImmediate(resolve));
 const account={id:'fixture',email:'fixture@unit.invalid',region:'EU',server_id:384,password_saved:true,mail_password_saved:true,mail_status:'verified',registration_status:'registered',create_class:'Gunner',create_nickname:'Unused proposal',character_key:'11',character_index:0,device_template_id:'device-one',device_template_revision:1,device_template_name:'Fixture PC',device_name:'FIXTURE-PC',device_profile:'custom',device_settings:{}};
 const second={...account,id:'second',email:'other@unit.invalid',active_game_account:true,reported_character_name:'Reported',reported_device:'UgPhone',device_template_id:'device-two',device_template_name:'Other PC'};
 const template={id:'device-one',name:'Fixture PC',device_name:'FIXTURE-PC',revision:1,settings:{cpu:{vendor:'AuthenticAMD',brand:'Fixture CPU'},metadata:{I_DeviceModel:'Desktop PC'},identity:{device_key:'a'.repeat(32),nm_device_key:'b'.repeat(32),nid_device_key:'c'.repeat(32)}},members:[{id:'fixture',email:account.email},{id:'third',email:'third@unit.invalid'}],source:'Fixture hardware'};
 state.accounts=[account,second];state.catalogs={EU:{servers:[{id:384,name:'Prelude 2'}]}};state.creation_classes=[{key:'Gunner',label:'Carnage'}];state.character_lists={'fixture|EU|384':{characters:[{key:'11',name:'Confirmed'}]}};state.device_templates=[template,{...template,id:'device-two',name:'Other PC',members:[{id:'second',email:second.email}]}];
 context.fixtureState=state;
 vm.runInContext('snapshot=fixtureState;renderRoster();',context);
 const [ordinary,active]=nodes.get('roster-body').children;
 assert.equal(ordinary.children.length,10);assert.equal(ordinary.children[2].textContent,'Confirmed');assert.equal(ordinary.children[4].textContent,'EU · Prelude 2');
 assert.match(active.className,/active-game-account.*device-type-ugphone/);assert.equal(active.children[2].textContent,'Reported');assert.equal(active.children[5].textContent,'UgPhone');
 const writesBefore=calls.filter(x=>x.request.method==='POST').length;
 ordinary.children[6].children[0].children[0].onclick();
 assert.equal(nodes.get('template-dialog').open,true);assert.equal(nodes.get('template-device-name').value,'FIXTURE-PC');
 assert.equal(nodes.get('template-device_key').type,'password');assert.equal(nodes.get('template-device_key').readOnly,true);
 assert.equal(calls.filter(x=>x.request.method==='POST').length,writesBefore);
 nodes.get('template-show-keys').checked=true;nodes.get('template-show-keys').onchange();assert.equal(nodes.get('template-device_key').type,'text');
 events.blur();assert.equal(nodes.get('template-device_key').type,'password');
 ordinary.children[1].children[0].children[1].children[0].onclick();
 assert.equal(nodes.get('account-dialog').open,true);assert.equal(nodes.get('account-template').value,'device-one');
 assert.equal(nodes.get('account-template').children.find(x=>x.value==='device-one').disabled,false);
 assert.equal(nodes.get('account-template').children.find(x=>x.value==='device-two').disabled,false);
 assert.equal(calls.filter(c=>c.path==='/api/reveal').length,0);
 await nodes.get('account-secrets').children[0].children[1].children[1].onclick();
 assert.equal(nodes.get('account-secrets').children[0].children[1].children[0].textContent,'fake-private-secret');
 events.blur();assert.equal(nodes.get('account-secrets').children[0].children[1].children[0].textContent,'••••••••');
 nodes.get('label').value='Unsaved label';await vm.runInContext('refresh()',context);assert.equal(nodes.get('label').value,'Unsaved label');
 nodes.get('search').value='Reported';nodes.get('search').oninput();assert.equal(nodes.get('roster-body').children.length,1);
 await nodes.get('copy-roster').onclick();assert.equal(writes,1);assert.match(copied,/fixture@unit.invalid\tfake-private-secret\tfake-private-secret\tConfirmed/);assert.match(copied,/other@unit.invalid/);
 const prior=writes;context.fetch=async()=>({ok:false,json:async()=>({error:'fixture failure'})});await nodes.get('copy-roster').onclick();assert.equal(writes,prior);
 context.fetch=fixtureFetch;
 const google={...account,id:'google',email:'google@gmail.com',login_provider:'google',mail_password_saved:false,password_saved:false,device_template_id:null,device_name:''};state.accounts.push(google);
 vm.runInContext('openAccount(fixtureState.accounts.at(-1));',context);assert.equal(nodes.get('password').required,false);assert.equal(nodes.get('password').disabled,true);
 assert.equal(nodes.get('account-template').children.find(x=>x.value==='device-one').disabled,true);assert.equal(vm.runInContext('canVerify(current())',context),true);
 assert.equal(nodes.get('start').disabled,true);assert.match(nodes.get('provider-hint').textContent,/код из Gmail/i);
 vm.runInContext('openAccount(null);',context);assert.equal(nodes.get('password').required,true);
 nodes.get('search').value='';vm.runInContext('snapshot=fixtureState;',context);
 nodes.get('sort-account').onclick();assert.equal(nodes.get('roster-body').children[0].children[1].textContent.includes('fixture@unit.invalid'),true);
 assert.equal(nodes.get('sort-account').parentElement.attributes['aria-sort'],'ascending');
 nodes.get('sort-account').onclick();assert.equal(nodes.get('roster-body').children[0].children[1].textContent.includes('other@unit.invalid'),true);
 state.catalogs.EU.servers.push({id:381,name:'Aria 10'},{id:382,name:'Aria 2'});state.accounts[0].server_id=381;state.accounts[1].server_id=382;
 nodes.get('sort-server').onclick();assert.equal(nodes.get('roster-body').children[0].children[1].textContent.includes('other@unit.invalid'),true);
 assert.equal(nodes.get('roster-body').children[0].children[0].textContent,'2');
 const reserve={...account,id:'reserve',email:'reserve@vampir.top',enabled:true,device_type:'Не задействован',create_nickname:'NightPlan',create_class:'DarkMage',character_key:null,character_index:null};
 const excluded={...reserve,id:'excluded',email:'excluded@vampir.top',device_type:'Не использовать',enabled:false,create_nickname:'ExcludedPlan'};
 state.accounts.push(reserve,excluded);state.creation_classes.push({key:'DarkMage',label:'Viper'});
 vm.runInContext('renderRoster();',context);
 assert.deepEqual(Array.from(vm.runInContext('runnableAccounts().map(a=>a.id)',context)),['fixture','second']);
 assert.equal(vm.runInContext('canVerify(fixtureState.accounts.at(-2))',context),true);
 assert.equal(vm.runInContext('canVerify(fixtureState.accounts.at(-1))',context),false);
 const reserveRow=nodes.get('roster-body').children.find(row=>row.children[1].textContent.includes('reserve@'));
 assert.equal(reserveRow.children[2].textContent,'NightPlan · план');assert.match(reserveRow.className,/device-type-reserve/);
 vm.runInContext('openAccount(fixtureState.accounts.at(-1));',context);
 assert.equal(nodes.get('enabled').checked,false);assert.equal(nodes.get('enabled').disabled,true);assert.equal(nodes.get('start').disabled,true);
 nodes.get('account-device-type').value='Не задействован';nodes.get('account-device-type').onchange();assert.equal(nodes.get('enabled').disabled,false);
 assert.equal(vm.runInContext('canVerify(current())',context),false);
 nodes.get('search').value='NightPlan';nodes.get('search').oninput();assert.equal(nodes.get('roster-body').children.length,1);
 await nodes.get('copy-roster').onclick();assert.match(copied,/NightPlan · план\tViper/);
 nodes.get('search').value='';
 nodes.get('filter-device').value='Не задействован';nodes.get('filter-device').onchange();
 nodes.get('filter-class').value='Carnage';nodes.get('filter-class').onchange();assert.equal(nodes.get('roster-body').children.length,0);
 nodes.get('filter-class').value='Viper';nodes.get('filter-class').onchange();assert.equal(nodes.get('roster-body').children.length,1);
 await vm.runInContext('refresh()',context);
 assert.equal(nodes.get('filter-device').value,'Не задействован');assert.equal(nodes.get('filter-class').value,'Viper');
 state.accounts.splice(state.accounts.indexOf(reserve),1);await vm.runInContext('refresh()',context);
 assert.equal(nodes.get('filter-device').value,'Не задействован');assert.equal(nodes.get('roster-body').children.length,0);
 assert.equal(nodes.get('filter-device').options.some(item=>item.value==='Не задействован'),true);
 state.accounts.push(reserve);await vm.runInContext('refresh()',context);assert.equal(nodes.get('roster-body').children.length,1);
 nodes.get('filter-character').value='Night';nodes.get('filter-character').oninput();assert.equal(nodes.get('roster-body').children.length,1);
 nodes.get('filter-account').value='excluded';nodes.get('filter-account').oninput();assert.equal(nodes.get('roster-body').children.length,0);
 nodes.get('reset-column-filters').onclick();assert.equal(nodes.get('roster-body').children.length,5);
 for(const id of ['class','device','character','account'])assert.equal(nodes.get('filter-'+id).value,'');
 nodes.get('roster-filter').value='reserve';nodes.get('roster-filter').onchange();assert.equal(nodes.get('roster-body').children.length,1);
 nodes.get('roster-filter').value='excluded';nodes.get('roster-filter').onchange();assert.equal(nodes.get('roster-body').children.length,1);assert.match(nodes.get('roster-body').children[0].className,/device-type-excluded/);
 nodes.get('roster-filter').value='all';nodes.get('roster-filter').onchange();
 assert.equal(vm.runInContext('sortValue(fixtureState.accounts.at(-1),"character")',context),'NightPlan · план');
 const dangerous=calls.filter(c=>['/api/save','/api/device-template','/api/assign-device','/api/generate-devices','/api/job','/api/verification-queue'].includes(c.path));assert.equal(dangerous.length,0);
 process.stdout.write('passed');
})().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', fixture, str(source.resolve())], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'passed')


if __name__ == '__main__': unittest.main()
