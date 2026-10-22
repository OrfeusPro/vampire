import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {applyBlocked,createControlServer,sealControl,openControl,validateCommand} from '../src/control-api.js';
import {Directory} from '../src/directory.js';
import {RTCPeerConnection} from '../src/native-peer.js';
const hex=n=>randomBytes(n).toString('hex');
test('network probe accepts only fixed built-in destinations',()=>{
 validateCommand('networkProbe',{});
 assert.throws(()=>validateCommand('networkProbe',{host:'127.0.0.1'}));
});
test('control frames isolate devices and reject tampering',()=>{
  const token=hex(32),body={id:hex(16),request:hex(16),command:'tap',at:Date.now()};const box=sealControl(token,body);
  assert.deepEqual(openControl(token,box),body);assert.throws(()=>openControl(hex(32),box));
  const data=Buffer.from(box.data,'base64');data[0]^=1;assert.throws(()=>openControl(token,{...box,data:data.toString('base64')}));
});

test('bot management uses encrypted HTTPS without opening a direct channel; manual control still requires WebRTC',async t=>{
 const directory=new Directory(()=>{}),secret=hex(32),phone={id:hex(16),name:'No ICE',token:hex(32)},requests=new Map(),commands=[];
 directory.setAccount({version:1,feedToken:hex(32),privateKey:'test',blocked:[]});directory.setPhones([phone]);
 directory.states.set(phone.id,{received:Date.now(),control:{api:3,directControl:true,enabled:true,botApi:1}});
 const server=createControlServer({directory,secret,request:async(_,options)=>{
  const b=JSON.parse(options.body);
  if(b.op==='enqueue'){
   const v=openControl(phone.token,b.box);commands.push(v.command);
   requests.set(b.request,{status:'done',box:sealControl(phone.token,{id:phone.id,request:b.request,at:Date.now(),ok:v.command!=='connectControl',error:v.command==='connectControl'?'ice_no_candidates':undefined,result:{botId:'rfonlinenext',status:'assigned'}})});
   return Response.json({ok:true});
  }
  return Response.json(b.op==='ack'?{ok:true}:requests.get(b.request)||{status:'pending'});
 }});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const base='http://127.0.0.1:'+server.address().port,path=base+'/v1/devices/'+phone.id+'/commands',headers={Authorization:'Bearer '+secret,'Content-Type':'application/json'};
 const response=await fetch(path,{method:'POST',headers,body:JSON.stringify({command:'bot',args:{op:'assign',botId:'rfonlinenext'}})});
 assert.equal(response.status,202);const job=await response.json();assert.notEqual(job.transport,'webrtc');
 assert.deepEqual(commands,['bot']);
 const probe=await fetch(path,{method:'POST',headers,body:'{"command":"networkProbe","args":{}}'});assert.equal(probe.status,202);assert.deepEqual(commands,['bot','networkProbe']);
 const manual=await fetch(path,{method:'POST',headers,body:'{"command":"home"}'});assert.equal(manual.status,502);assert.deepEqual(commands,['bot','networkProbe','connectControl']);
});

test('HTTP API bootstraps authenticated native WebRTC once and survives catalog outage',async t=>{
  const directory=new Directory(()=>{}),secret=hex(32),phone={id:hex(16),name:'Direct',token:hex(32)};
  directory.setAccount({version:1,feedToken:hex(32),privateKey:'test',blocked:[]});directory.setPhones([phone]);
  directory.states.set(phone.id,{received:Date.now(),control:{api:3,directControl:true,enabled:true}});
  const remote=new RTCPeerConnection({iceServers:[]});let response,bootstraps=0,actions=0,icePolls=0;const iceSession=hex(16);let lateCandidates=[];
  remote.onDataChannel.subscribe(dc=>dc.onMessage.subscribe(raw=>{
    const v=JSON.parse(raw);if(v.type==='ping'){dc.send(JSON.stringify({type:'pong',request:v.request}));return;}
    actions++;const body=Buffer.from(JSON.stringify({id:phone.id,request:v.request,at:Date.now(),ok:true,result:{performed:true}})),b=Buffer.alloc(24+body.length);
    Buffer.from(v.request,'hex').copy(b);b.writeUInt32BE(body.length,16);b.writeUInt32BE(0,20);body.copy(b,24);dc.send(b);
  }));
  const server=createControlServer({directory,secret,request:async(_,options)=>{
    const b=JSON.parse(options.body);
    if(b.op==='enqueue'){
      const v=openControl(phone.token,b.box);let result;
      if(v.command==='connectControl'){
        bootstraps++;
        const stripped=v.args.sdp.split(/\r?\n/).filter(s=>!s.startsWith('a=candidate:')&&s!=='a=end-of-candidates').join('\r\n');
        await remote.setRemoteDescription({type:'offer',sdp:stripped});await remote.setLocalDescription({type:'answer'});
        lateCandidates=remote.localDescription.sdp.split(/\r?\n/).filter(s=>s.startsWith('a=candidate:')).map(s=>({candidate:s.slice(2),sdpMid:'0',sdpMLineIndex:0}));
        result={type:'answer',iceSession,sdp:remote.localDescription.sdp.split(/\r?\n/).filter(s=>!s.startsWith('a=candidate:')&&s!=='a=end-of-candidates').join('\r\n')};
      }else{assert.equal(v.command,'controlIce');assert.equal(v.args.iceSession,iceSession);icePolls++;result={iceSession,closed:false,candidates:lateCandidates};}
      response={status:'done',box:sealControl(phone.token,{id:phone.id,request:b.request,at:Date.now(),ok:true,result})};
      return Response.json({ok:true});
    }
    return Response.json(b.op==='ack'?{ok:true}:response);
  }});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(async()=>{await new Promise(r=>server.close(r));await remote.close();});
  const base='http://127.0.0.1:'+server.address().port,path=base+'/v1/devices/'+phone.id+'/commands',headers={Authorization:'Bearer '+secret,'Content-Type':'application/json'};
  for(const command of ['connectControl','controlIce']){assert.equal((await fetch(path,{method:'POST',headers,body:JSON.stringify({command,args:{iceSession,sdp:'v=0'}})})).status,400);}
  for(let i=0;i<2;i++){
    const accepted=await fetch(path,{method:'POST',headers,body:'{"command":"home"}'});assert.equal(accepted.status,202);const job=await accepted.json();assert.equal(job.transport,'webrtc');
    let r;for(let n=0;n<100;n++){r=await(await fetch(path+'/'+job.id,{headers})).json();if(r.status==='done')break;await new Promise(r=>setTimeout(r,10));}
    assert.equal(r.status,'done');assert.equal(r.result.result.performed,true);
    directory.states.get(phone.id).received=Date.now()-60000;
  }
  assert.equal(bootstraps,1);assert.equal(actions,2);assert.ok(icePolls>0);
  assert.equal((await(await fetch(base+'/v1/devices',{headers})).json()).devices[0].online,true);
  applyBlocked(directory,[phone.id]);assert.equal((await fetch(path,{method:'POST',headers,body:'{"command":"home"}'})).status,404);assert.equal(actions,2);
});
test('command contract rejects shell, invalid geometry and duration',()=>{
  assert.throws(()=>validateCommand('shell',{command:'id'}));assert.throws(()=>validateCommand('tap',{x:720,y:1,width:720,height:1280}));
  assert.throws(()=>validateCommand('swipe',{x1:0,y1:0,x2:1,y2:1,width:720,height:1280,durationMs:9999}));
  assert.throws(()=>validateCommand('launch',{package:'com.game; id'}));assert.throws(()=>validateCommand('tap',null));
  assert.equal(validateCommand('tap',{x:10,y:20,width:720,height:1280}).command,'tap');
});
test('HTTP gateway authentication, offline gate, encrypted enqueue and bound results',async t=>{
  const directory=new Directory(()=>{}),secret=hex(32),phone={id:hex(16),name:'Тест',token:hex(32)};
  directory.setAccount({version:1,feedToken:hex(32),privateKey:'test',blocked:[]});directory.setPhones([phone]);
  let received;
  const server=createControlServer({directory,secret,request:async(url,options)=>{
    const body=JSON.parse(options.body);received=body;
    if(body.op==='enqueue')return new Response(JSON.stringify({ok:true}));
    return new Response(JSON.stringify({id:body.request,status:'done',box:sealControl(phone.token,{id:phone.id,request:body.request,at:Date.now(),ok:true,result:{processUid:10000}})}));
  }});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{await new Promise(resolve=>server.close(resolve));await new Promise(resolve=>setTimeout(resolve,200));});
  const base='http://127.0.0.1:'+server.address().port,headers={Authorization:'Bearer '+secret,'Content-Type':'application/json'};
  assert.equal((await fetch(base+'/v1/devices')).status,401);
  assert.equal((await fetch(base+'/v1/devices',{headers:{...headers,Origin:'http://evil.test'}})).status,403);
  const path='/v1/devices/'+phone.id+'/commands';
  assert.equal((await fetch(base+path,{method:'POST',headers,body:'{"command":"status"}'})).status,409);
  directory.states.set(phone.id,{received:Date.now(),control:{api:1},versionName:'0.5.0',versionCode:15});
  assert.equal((await fetch(base+path,{method:'POST',headers,body:'{"command":"screenshot","args":{"format":"png"}}'})).status,409);
  const response=await fetch(base+path,{method:'POST',headers,body:'{"command":"status"}'});assert.equal(response.status,202);const job=await response.json();
  assert.equal(received.op,'enqueue');assert.equal(received.command,undefined);assert.equal(openControl(phone.token,received.box).command,'status');
  directory.states.set(phone.id,{received:Date.now(),control:{api:4,directControl:true,enabled:true},versionName:'0.8.13',versionCode:39});
  const snapshot=await fetch(base+path,{method:'POST',headers,body:JSON.stringify({command:'screenshot',args:{format:'jpg',quality:80},transport:'https'})});
  assert.equal(snapshot.status,202);assert.equal(openControl(phone.token,received.box).command,'screenshot');
  assert.equal((await fetch(base+path,{method:'POST',headers,body:JSON.stringify({command:'tap',args:{x:10,y:20,width:720,height:1280},transport:'https'})})).status,202);
  assert.equal(openControl(phone.token,received.box).command,'tap');
  directory.states.set(phone.id,{received:Date.now(),control:{api:1},versionName:'0.5.0',versionCode:15});
  const result=await (await fetch(base+path+'/'+job.id,{headers})).json();assert.equal(result.result.ok,true);assert.equal(result.box,undefined);
  const devices=await (await fetch(base+'/v1/devices',{headers})).json();assert.equal(devices.devices[0].versionCode,15);assert.equal(devices.devices[0].token,undefined);
  assert.throws(()=>applyBlocked(directory,['invalid']));assert.equal(directory.phones.length,1);
  applyBlocked(directory,[phone.id]);assert.equal(directory.phones.length,0);assert.equal((await fetch(base+path+'/'+job.id,{headers})).status,404);
});
