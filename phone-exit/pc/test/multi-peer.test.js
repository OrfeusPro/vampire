import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import {RTCPeerConnection as RemotePeer} from 'werift';
import {RTCPeerConnection as NativePeer} from '../src/native-peer.js';
import {MultiPeer} from '../src/multi-peer.js';
import {createSocksServer} from '../src/socks.js';
import {bridge} from '../src/bridge.js';

test('independent native peers: protected negotiation, binary distribution, UDP isolation and failure closes SOCKS',{timeout:60000},async t=>{
  const primary=new NativePeer({iceServers:[]}),remote=new RemotePeer({iceServers:[]});
  const remotes=new Map(),controls=new Map(),sockets=new Set(),used=new Set();let signal,queue=Promise.resolve(),socks,failure;
  const pool=new MultiPeer(primary,{count:4,config:{iceServers:[]},onFailure:error=>{failure=error;socks?.shutdown();}});
  const echo=net.createServer({allowHalfOpen:true},socket=>{sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));socket.on('data',data=>socket.write(data));socket.on('end',()=>socket.end());});
  echo.listen(0,'127.0.0.1');await once(echo,'listening');
  t.after(async()=>{pool.close();socks?.shutdown();for(const socket of sockets)socket.destroy();echo.close();await Promise.all([primary.close(),remote.close(),...[...remotes.values()].map(p=>p.close())]);});
  remote.onDataChannel.subscribe(dc=>{
    if(dc.label!=='phone-exit-links-v1')return;signal=dc;
    dc.onMessage.subscribe(data=>{queue=queue.then(async()=>{
      const msg=JSON.parse(data);
      if(msg.type==='offer'){
        const peer=new RemotePeer({iceServers:[]});remotes.set(msg.lane,peer);
        peer.onIceCandidate.subscribe(c=>{if(c)signal.send(JSON.stringify({type:'candidate',lane:msg.lane,value:c.toJSON()}));});
        peer.onDataChannel.subscribe(channel=>{
          if(channel.label==='phone-exit-lane-v1'){
            controls.set(msg.lane,channel);
            channel.onopen=()=>channel.send(JSON.stringify({type:'lane-ready',lane:msg.lane}));
            channel.onMessage.subscribe(value=>{const m=JSON.parse(value);if(m.type==='ping'&&channel.readyState==='open')channel.send(JSON.stringify({type:'pong',id:m.id}));});return;
          }
          used.add(msg.lane);
          channel.onMessage.once(value=>{
            const open=JSON.parse(value);assert.equal(open.port,echo.address().port);
            // Loopback is permitted only by this local fake exit.
            const socket=net.connect({host:'127.0.0.1',port:open.port,allowHalfOpen:true});sockets.add(socket);socket.on('close',()=>sockets.delete(socket));
            socket.once('connect',()=>{bridge(socket,channel,{initiallyReady:true,sendWindow:2097152});channel.send(JSON.stringify({type:'ready'}));});
          });
        });
        await peer.setRemoteDescription(msg.value);await peer.setLocalDescription(await peer.createAnswer());
        signal.send(JSON.stringify({type:'answer',lane:msg.lane,value:peer.localDescription}));
      }else await remotes.get(msg.lane).addIceCandidate(msg.value);
    });queue.catch(error=>pool.failure(error));});
  });
  primary.createDataChannel('bootstrap');await primary.setLocalDescription(await primary.createOffer());
  await remote.setRemoteDescription(primary.localDescription);await remote.setLocalDescription(await remote.createAnswer());await primary.setRemoteDescription(remote.localDescription);
  if(primary.connectionState!=='connected')await new Promise(resolve=>primary.connectionStateChange.subscribe(s=>{if(s==='connected')resolve();}));
  await pool.start();assert.equal(pool.lanes.length,3);assert.equal(pool.iceTransports.length,4);
  socks=createSocksServer(pool,{port:0,receiveWindow:2097152,sendBuffer:524288});const address=await socks.start();
  async function connect(){
    const socket=net.connect({host:'127.0.0.1',port:address.port,allowHalfOpen:true});sockets.add(socket);socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));
    let bytes=Buffer.alloc(0),wake,closed=false;socket.on('data',data=>{bytes=Buffer.concat([bytes,data]);wake?.();});socket.on('close',()=>{closed=true;wake?.();});
    const read=async n=>{while(bytes.length<n){if(closed)throw Error('closed');await new Promise(r=>wake=r);}const out=bytes.subarray(0,n);bytes=bytes.subarray(n);wake=undefined;return out;};
    await once(socket,'connect');socket.write(Buffer.from([5,1,0]));assert.deepEqual(await read(2),Buffer.from([5,0]));
    const request=Buffer.from([5,1,0,1,127,0,0,1,0,0]);request.writeUInt16BE(echo.address().port,8);socket.write(request);assert.equal((await read(10))[1],0);return {socket,read};
  }
  await Promise.all(Array.from({length:6},async()=>{const {socket,read}=await connect();const payload=randomBytes(1000000);socket.end(payload);assert.deepEqual(await read(payload.length),payload);socket.destroy();}));
  assert.deepEqual([...used].sort(),[1,2,3]);
  const before=pool.next,udp=pool.createDataChannel('phone-exit-udp-v1-999',{ordered:false,maxRetransmits:0});assert.equal(pool.next,before);udp.close();
  const {socket}=await connect();const ended=once(socket,'end');controls.get(2).close();await ended;socket.destroy();
  assert.ok(failure);assert.equal(pool.closed,true);
});
