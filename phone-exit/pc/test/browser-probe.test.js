import test from 'node:test';
import assert from 'node:assert/strict';
import {runBrowserProbe} from '../src/browser-probe.js';
import {RTCPeerConnection} from '../src/native-peer.js';
import {LABEL,description,ipv4Sdp,candidate,safeReport} from '../../diagnostics/browser/shared.js';

test('browser diagnostic filters IPv6/TCP and redacts report metadata',()=>{
 const sdp='m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=candidate:x 1 udp 1 2001:db8::1 1 typ host\r\na=candidate:y 1 udp 1 8.8.8.8 1 typ srflx\r\n';
 assert(!ipv4Sdp(sdp).includes('2001:'));assert(ipv4Sdp(sdp).includes('8.8.8.8'));
 assert.throws(()=>description({type:'offer',sdp:'x'},'offer'));
 assert.throws(()=>candidate({candidate:'candidate:x 1 tcp 1 8.8.8.8 1 typ host',sdpMid:'0',sdpMLineIndex:0}));
 const report=safeReport({result:'failed',token:'secret',checks:{pairs:[{state:'failed',address:'secret-address',requestsSent:3,port:5555}]}});
 assert(!JSON.stringify(report).includes('secret'));assert(!JSON.stringify(report).includes('5555'));assert.equal(report.checks.pairs[0].requestsSent,3);
});

test('real native WebRTC crosses browser probe protocol with five echoes',async()=>{
 const remote=new RTCPeerConnection({iceServers:[]});const incoming=[];let id=0;
 remote.onDataChannel.subscribe(dc=>{assert.equal(dc.label,LABEL);dc.onMessage.subscribe(raw=>{
  const v=JSON.parse(raw);if(v.type==='ping')dc.send(JSON.stringify({type:'pong',seq:v.seq}));
  else if(v.type==='done'){dc.send('{"type":"doneAck"}');incoming.push({id:++id,message:{type:'candidate',value:null,probeReport:{result:'connected',pings:5}}});}
 });});
 try{
  const result=await runBrowserProbe({waitMs:15000,checkMs:10000,api:async body=>{
   if(body.op==='send'){
    await remote.setRemoteDescription(body.message.value);await remote.setLocalDescription({type:'answer'});
    incoming.push({id:++id,message:{type:'answer',value:remote.localDescription}});return {};
   }
   return {messages:incoming.filter(x=>x.id>body.after)};
  }});
  assert.equal(result.result,'connected');assert.equal(result.pongs,5);assert.equal(result.browser.pings,5);
 }finally{await remote.close();}
});

test('timeout closes an owned peer and a report alone cannot prove success',async()=>{
 let closed=false;const signal={subscribe(){}};
 class Peer{
  connectionStateChange=signal;localDescription={type:'offer',sdp:'m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n'};
  createDataChannel(){return {stateChange:signal,onMessage:signal,close(){},send(){}};}
  createOffer(){return {type:'offer'};}setLocalDescription(){}setRemoteDescription(){}close(){closed=true;}
 }
 const result=await runBrowserProbe({Peer,waitMs:100,api:async b=>b.op==='send'?{}:{messages:[{id:1,message:{type:'candidate',value:null,probeReport:{result:'connected',pings:5}}}]}});
 assert.equal(result.result,'failed');assert.equal(result.pongs,0);assert(closed);
});
