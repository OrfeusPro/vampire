import test from 'node:test';
import assert from 'node:assert/strict';
import {ControlIcePoller} from '../src/control-ice.js';
import {DirectControl} from '../src/control-direct.js';
import {RTCPeerConnection} from '../src/native-peer.js';

test('late ICE snapshots deduplicate, stop on session replacement and cancel without adding stale candidates',async()=>{
  const abort=new AbortController(),added=[];let calls=0;
  const candidate={candidate:'candidate:late',sdpMid:'0',sdpMLineIndex:0};
  const poller=new ControlIcePoller({peer:{addIceCandidate:async c=>added.push(c)},session:'s',signal:abort.signal,pauseMs:1,
    poll:async()=>++calls<3?{iceSession:'s',closed:false,candidates:[candidate,candidate]}:{iceSession:'new',candidates:[candidate]}});
  await poller.run();assert.equal(added.length,1);assert.equal(calls,3);
  const pending=new ControlIcePoller({peer:{addIceCandidate:async()=>assert.fail('stale candidate')},session:'s',signal:abort.signal,
    poll:async()=>{abort.abort();return {iceSession:'s',candidates:[candidate]};}});
  await pending.run();
});

test('real native channel opens using candidates delivered after the initial answer',async()=>{
  const remote=new RTCPeerConnection({iceServers:[]});let answer,candidates=[],polls=0,dc;
  const received=new Promise(resolve=>remote.onDataChannel.subscribe(c=>{dc=c;c.onMessage.subscribe(resolve);}));
  const direct=new DirectControl({id:'a'.repeat(32),Peer:class extends RTCPeerConnection{constructor(){super({iceServers:[]});}},
    bootstrap:async sdp=>{
      const stripped=sdp.split(/\r?\n/).filter(s=>!s.startsWith('a=candidate:')&&s!=='a=end-of-candidates').join('\r\n');
      await remote.setRemoteDescription({type:'offer',sdp:stripped});await remote.setLocalDescription({type:'answer'});
      answer=remote.localDescription.sdp;
      candidates=answer.split(/\r?\n/).filter(s=>s.startsWith('a=candidate:')).map(s=>({candidate:s.slice(2),sdpMid:'0',sdpMLineIndex:0}));
      assert.ok(candidates.length);
      return {type:'answer',iceSession:'b'.repeat(32),sdp:answer.split(/\r?\n/).filter(s=>!s.startsWith('a=candidate:')&&s!=='a=end-of-candidates').join('\r\n')};
    },pollIce:async(iceSession)=>{polls++;await new Promise(r=>setTimeout(r,150));return {iceSession,closed:false,candidates};}});
  try{
    await direct.connect();assert.ok(polls>0);assert.ok(direct.icePoller.added>0);assert.equal(direct.iceAbort.signal.aborted,true);
    direct.channel.send(Buffer.from([1,0,255]));assert.deepEqual(Buffer.from(await received),Buffer.from([1,0,255]));
  }finally{direct.close();dc?.close();await remote.close();}
});
