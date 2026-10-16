const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(__dirname+'/dist/app.js','utf8');
const submit=source.split("form.addEventListener('submit',async e=>{")[1].split('\n});')[0];
const show=source.split('function showOrderConfirmation(){')[1].split('\n}')[0];
async function run(ok){
 const button={disabled:false},result={focus(){this.focused=true},scrollIntoView(){this.scrolled=true}},confirmation={dataset:{},focus(){this.focused=true}},form={elements:{region:{value:'GLOBAL'}},reportValidity:()=>true};
 const context={form,result,confirmation,confirmationMessage:{replaceChildren(...nodes){this.nodes=nodes;this.textContent=nodes.map(n=>typeof n==='string'?n:n.textContent).join('');}},dialog:{classList:{add(){}},scrollTop:100},language:'en',messages:{en:{success:'Request {id} received',notificationWarning:'Saved {id}',sending:'Sending',submit:'Send',error:'Error',securityCheck:'Verify'}},savedEmailAccepted:false,savedRequest:null,orderSubmitting:false,turnstileWidget:'widget',window:{turnstile:{getResponse:()=> 'token',isExpired:()=>false}},document:{createElement:tag=>({tagName:tag}),querySelector:s=>s==='#submit-order'?button:{content:'csrf'}},FormData:class{*[Symbol.iterator](){yield ['amount','1000'];}},fetch:async()=>({ok,json:async()=>ok?{id:'VT-TEST',email_accepted:true}:{error:'turnstile_failed'}}),resetTurnstile(){},securityNotice(){},securityContainer:{focus(){}},e:{preventDefault(){}}};
 vm.createContext(context);vm.runInContext('function showOrderConfirmation(){'+show+'\n}',context);
 await vm.runInContext('(async()=>{'+submit+'\n})()',context);
 assert.equal(context.orderSubmitting,false);assert.equal(button.disabled,false);
 if(ok){assert.equal(form.hidden,true);assert.equal(confirmation.hidden,false);assert.equal(confirmation.focused,true);assert.equal(context.dialog.scrollTop,0);assert.match(context.confirmationMessage.textContent,/VT-TEST/);assert.equal(context.confirmationMessage.nodes[1].tagName,'strong');assert.equal(context.confirmationMessage.nodes[1].textContent,'VT-TEST');}
 else{assert.equal(form.hidden,undefined);assert.equal(result.focused,true);assert.equal(result.scrolled,true);assert.equal(result.textContent,'Verify');}
}
(async()=>{await run(true);await run(false);assert(!source.includes("dialog.addEventListener('click'"));console.log('Order feedback: visible focused confirmation, preserved error form, retry enabled, no backdrop dismissal OK');})().catch(e=>{console.error(e);process.exitCode=1;});
