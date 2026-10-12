import test from 'node:test';
import assert from 'node:assert/strict';
import {DirectControl} from '../src/control-direct.js';
import {RTCPeerConnection} from '../src/native-peer.js';

test('real native WebRTC: bounded binary screenshot, parallel requests, loss without replay',async()=>{
  const id='a'.repeat(32),remote=new RTCPeerConnection({iceServers:[]});let dc,executed=0;
  remote.onDataChannel.subscribe(channel=>{
    dc=channel;channel.onMessage.subscribe(raw=>{
      const v=JSON.parse(raw);
      if(v.type==='ping'){channel.send(JSON.stringify({type:'pong',request:v.request}));return;}
      executed++;
      if(v.command==='lost'){channel.close();return;}
      const body=Buffer.from(JSON.stringify({id,request:v.request,at:Date.now(),ok:true,result:{image:Buffer.alloc(400000,executed).toString('base64')}}));
      for(let offset=0;offset<body.length;offset+=16384){const b=Buffer.alloc(24+Math.min(16384,body.length-offset));Buffer.from(v.request,'hex').copy(b);b.writeUInt32BE(body.length,16);b.writeUInt32BE(offset,20);body.copy(b,24,offset,offset+b.length-24);channel.send(b);}
    });
  });
  const direct=new DirectControl({id,Peer:class extends RTCPeerConnection{constructor(){super({iceServers:[]});}},bootstrap:async sdp=>{
    await remote.setRemoteDescription({type:'offer',sdp});await remote.setLocalDescription({type:'answer'});return remote.localDescription;
  }});
  try{
    await direct.connect();const jobs=[direct.send('screenshot',{}),direct.send('screenshot',{})];
    const end=Date.now()+5000;
    while(jobs.some(j=>direct.get(j.id).status!=='done')&&Date.now()<end)await new Promise(r=>setTimeout(r,10));
    for(const j of jobs){const v=direct.get(j.id);assert.equal(v.status,'done');assert.equal(Buffer.from(v.result.result.image,'base64').length,400000);}
    // More than the entire 8 MiB history: completed frames must be evicted,
    // while the live channel continues serving fresh captures.
    for(let i=0;i<40;i++){
      const j=direct.send('screenshot',{}),until=Date.now()+3000;
      while(direct.get(j.id).status!=='done'&&Date.now()<until)await new Promise(r=>setTimeout(r,5));
      assert.equal(direct.get(j.id).status,'done');assert.ok(direct.bytes<=8388608);
    }
    assert.equal(direct.get(jobs[0].id).status,'expired');assert.equal(direct.closed,false);
    const loss=direct.send('lost',{});await new Promise(r=>setTimeout(r,100));assert.equal(direct.get(loss.id).status,'expired');assert.equal(executed,43);
    assert.throws(()=>direct.send('screenshot',{}));assert.equal(executed,43);
  }finally{direct.close();dc?.close();await remote.close();}
});

test('direct result rejects oversized and out-of-order frames before allocation',()=>{
  for(const [total,offset]of [[2100001,0],[100,1]]){
    const d=new DirectControl({id:'a'.repeat(32),bootstrap:()=>{}}),request='b'.repeat(32);d.jobs.set(request,{until:Date.now()+1000});
    const b=Buffer.alloc(25);Buffer.from(request,'hex').copy(b);b.writeUInt32BE(total,16);b.writeUInt32BE(offset,20);d.receive(b);assert.equal(d.closed,true);assert.equal(d.bytes,0);
  }
});
