import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {authenticateVmos,vmosSignature,translateScript,mapCoordinates,touchPlan} from '../src/vmos-compat.js';
import {createControlServer,sealControl,openControl,validateCommand} from '../src/control-api.js';
import {Directory} from '../src/directory.js';
const hex=n=>randomBytes(n).toString('hex');
test('VMOS HMAC checks body, timestamp, host, signature',()=>{
 const secret=hex(32),raw='{"text":"Привет"}',d=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,''),host='127.0.0.1:17842';
 const headers={host,'x-host':host,'x-date':d,'content-type':'application/json;charset=UTF-8','x-content-sha256':createHash('sha256').update(raw).digest('hex'),authorization:`HMAC-SHA256 Credential=phone-exit/${d.slice(0,8)}/armcloud-paas/request, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=${vmosSignature(secret,host,d,raw)}`};
 assert.equal(authenticateVmos({headers},raw,secret),true);assert.equal(authenticateVmos({headers},raw+' ',secret),false);assert.equal(authenticateVmos({headers},raw,secret,Date.now()+60000),false);assert.equal(authenticateVmos({headers:{...headers,host:'evil.test'}},raw,secret),false);assert.equal(authenticateVmos({headers},raw,hex(32)),false);
});
test('whitelisted scripts, virtual scaling and complete gestures',()=>{
 assert.equal(translateScript('wm size').command,'deviceInfo');assert.equal(translateScript('input keyevent KEYCODE_BACK').args.key,4);
 for(const s of ['pidof com.game','am force-stop com.game','input tap 1 2; id','su','input text $(id)'])assert.throws(()=>translateScript(s),e=>e.code===501);
 const info={width:1080,height:2400,frameWidth:576,frameHeight:1280};assert.deepEqual(mapCoordinates({x:360,y:640},info),{x:288,y:640,width:576,height:1280});assert.throws(()=>mapCoordinates({x:720,y:0},info));
 assert.throws(()=>touchPlan({positions:[{actionType:0,x:1,y:1},{actionType:2,x:2,y:2}]}));assert.throws(()=>touchPlan({pointCount:2,positions:[]}));
 const args=mapCoordinates(touchPlan({positions:[{actionType:0,x:1,y:1,nextPositionWaitTime:100},{actionType:2,x:2,y:2,nextPositionWaitTime:100},{actionType:1,x:3,y:3}]}),info);validateCommand('gesture',args);assert.equal(args.strokes[0].durationMs,200);
 assert.throws(()=>validateCommand('inputText',{text:'x'.repeat(4097)}));assert.throws(()=>validateCommand('screenshot',{width:1280}));
 assert.throws(()=>validateCommand('inputText',{text:'界'.repeat(4096)}));assert.throws(()=>validateCommand('inputText',{text:'\u0000'.repeat(4096)}));
});
test('real HTTP VMOS tasks, screenshot capability, failures and blocked device isolation',async t=>{
 const directory=new Directory(()=>{}),secret=hex(32),phone={id:hex(16),name:'Тест',token:hex(32)},jobs=new Map();
 directory.setAccount({version:1,feedToken:hex(32),privateKey:'test',blocked:[]});directory.setPhones([phone]);directory.states.set(phone.id,{received:Date.now(),control:{api:2}});
 let calls=0;const server=createControlServer({directory,secret,vmosWaitMs:30,request:async(url,o)=>{
   const b=JSON.parse(o.body);if(b.op==='enqueue'){calls++;const v=openControl(phone.token,b.box);jobs.set(b.request,v);return Response.json({ok:true});}
   const j=jobs.get(b.request),result=j.command==='deviceInfo'?{width:1080,height:2400,frameWidth:576,frameHeight:1280}:j.command==='screenshot'?{format:'png',image:Buffer.from('fake test image').toString('base64')}:j.command==='apps'?{apps:[{package:'com.example'}],total:1,nextOffset:null}:{};
   if(j.command==='keyevent'&&j.args.key===3)return Response.json({status:'delivered'});
   return Response.json({status:'done',box:sealControl(phone.token,{id:phone.id,request:b.request,at:Date.now(),ok:j.command!=='foreground',result,error:j.command==='foreground'?'foreground_unavailable':undefined})});
 }});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(async()=>{await new Promise(r=>server.close(r));await new Promise(r=>setTimeout(r,200));});
 const base='http://127.0.0.1:'+server.address().port,headers={Authorization:'Bearer '+secret,'Content-Type':'application/json'};
 const post=async(method,b={})=>(await fetch(base+'/vcpcloud/api/padApi/'+method,{method:'POST',headers,body:JSON.stringify(b)})).json();
 const list=await post('userPadList');assert.equal(list.data[0].padCode,phone.id);assert.equal(list.data[0].token,undefined);
 const unsupported=await post('stopApp',{padCodes:[phone.id]});assert.equal(unsupported.code,501);assert.equal(unsupported.supported,false);assert.equal(calls,0);
 const size=await post('syncCmd',{padCode:phone.id,scriptContent:'wm size'});assert.equal(size.data[0].errorMsg,'Physical size: 720x1280\n');assert.equal(size.data[0].taskResult,'success');
 const tap=await post('asyncCmd',{padCode:phone.id,scriptContent:'input tap 360 640'});const detail=await post('padTaskDetail',{taskIds:[tap.data[0].taskId]});assert.equal(detail.data[0].taskStatus,3);assert.equal(Array.from(jobs.values()).at(-1).args.x,288);
 const fail=await post('syncCmd',{padCode:phone.id,scriptContent:'dumpsys window'});assert.equal(fail.data[0].taskStatus,-1);assert.equal(fail.data[0].errorMsg,'foreground_unavailable');
 const screen=await post('getLongGenerateUrl',{padCodes:[phone.id],format:'png',width:720,height:1280});assert.equal(screen.data[0].success,true);const image=await fetch(screen.data[0].url);assert.equal(image.status,200);assert.equal(image.headers.get('content-type'),'image/png');
 const pending=await post('asyncCmd',{padCode:phone.id,scriptContent:'input keyevent 3'});assert.equal((await post('padTaskDetail',{taskIds:[pending.data[0].taskId]})).data[0].taskStatus,2);
 const before=calls,timeout=await post('syncCmd',{padCode:phone.id,scriptContent:'input keyevent 3'});assert.equal(timeout.code,110012);assert.ok(timeout.data[0].taskId);assert.equal(calls,before+1);assert.equal((await post('padTaskDetail',{taskIds:[timeout.data[0].taskId]})).data[0].taskStatus,2);
 directory.account.blocked.push(phone.id);assert.equal((await fetch(screen.data[0].url)).status,404);assert.equal((await post('padTaskDetail',{taskIds:[tap.data[0].taskId]})).code,404);
});
