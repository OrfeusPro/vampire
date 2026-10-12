import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {applyBlocked,createControlServer,sealControl,openControl,validateCommand} from '../src/control-api.js';
import {Directory} from '../src/directory.js';
import {RTCPeerConnection} from '../src/native-peer.js';
const hex=n=>randomBytes(n).toString('hex');
test('control frames isolate devices and reject tampering',()=>{
  const token=hex(32),body={id:hex(16),request:hex(16),command:'tap',at:Date.now()};const box=sealControl(token,body);
  assert.deepEqual(openControl(token,box),body);assert.throws(()=>openControl(hex(32),box));
  const data=Buffer.from(box.data,'base64');data[0]^=1;assert.throws(()=>openControl(token,{...box,data:data.toString('base64')}));
});

test('HTTP API bootstraps authenticated native WebRTC once and survives catalog outage',async t=>{
  const directory=new Directory(()=>{}),secret=hex(32),phone={id:hex(16),name:'Direct',token:hex(32)};
  directory.setAccount({version:1,feedToken:hex(32),privateKey:'test',blocked:[]});directory.setPhones([phone]);
  directory.states.set(phone.id,{received:Date.now(),control:{api:3,directControl:true,enabled:true}});
  const remote=new RTCPeerConnection({iceServers:[]});let response,bootstraps=0,actions=0;
  remote.onDataChannel.subscribe(dc=>dc.onMessage.subscribe(raw=>{
    const v=JSON.parse(raw);if(v.type==='ping'){dc.send(JSON.stringify({type:'pong',request:v.request}));return;}
    actions++;const body=Buffer.from(JSON.stringify({id:phone.id,request:v.request,at:Date.now(),ok:true,result:{performed:true}})),b=Buffer.alloc(24+body.length);
    Buffer.from(v.request,'hex').copy(b);b.writeUInt32BE(body.length,16);b.writeUInt32BE(0,20);body.copy(b,24);dc.send(b);
  }));
  const server=createControlServer({directory,secret,request:async(_,options)=>{
    const b=JSON.parse(options.body);
    if(b.op==='enqueue'){
      const v=openControl(phone.token,b.box);assert.equal(v.command,'connectControl');bootstraps++;
      await remote.setRemoteDescription({type:'offer',sdp:v.args.sdp});await remote.setLocalDescription({type:'answer'});
      response={status:'done',box:sealControl(phone.token,{id:phone.id,request:b.request,at:Date.now(),ok:true,result:remote.localDescription})};
      return Response.json({ok:true});
    }
    return Response.json(b.op==='ack'?{ok:true}:response);
  }});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(async()=>{await new Promise(r=>server.close(r));await remote.close();});
  const base='http://127.0.0.1:'+server.address().port,path=base+'/v1/devices/'+phone.id+'/commands',headers={Authorization:'Bearer '+secret,'Content-Type':'application/json'};
  for(let i=0;i<2;i++){
    const accepted=await fetch(path,{method:'POST',headers,body:'{"command":"home"}'});assert.equal(accepted.status,202);const job=await accepted.json();assert.equal(job.transport,'webrtc');
    let r;for(let n=0;n<100;n++){r=await(await fetch(path+'/'+job.id,{headers})).json();if(r.status==='done')break;await new Promise(r=>setTimeout(r,10));}
    assert.equal(r.status,'done');assert.equal(r.result.result.performed,true);
    directory.states.get(phone.id).received=Date.now()-60000;
  }
  assert.equal(bootstraps,1);assert.equal(actions,2);
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
  const result=await (await fetch(base+path+'/'+job.id,{headers})).json();assert.equal(result.result.ok,true);assert.equal(result.box,undefined);
  const devices=await (await fetch(base+'/v1/devices',{headers})).json();assert.equal(devices.devices[0].versionCode,15);assert.equal(devices.devices[0].token,undefined);
  assert.throws(()=>applyBlocked(directory,['invalid']));assert.equal(directory.phones.length,1);
  applyBlocked(directory,[phone.id]);assert.equal(directory.phones.length,0);assert.equal((await fetch(base+path+'/'+job.id,{headers})).status,404);
});
