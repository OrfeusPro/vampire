import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { RTCPeerConnection } from 'werift';
import { createSocksServer } from '../src/socks.js';
import { bridge } from '../src/bridge.js';
import {observeTransport} from '../src/transport-probe.js';
import {RTCPeerConnection as NativePeer} from '../src/native-peer.js';
import {DiagnosticCapture} from '../src/diagnostic-capture.js';
import {readCapture} from '../src/capture-inspect.js';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

for(const Transport of [RTCPeerConnection,NativePeer])test(`SOCKS5 over real WebRTC (${Transport===NativePeer?'native':'werift'}): binary, parallel streams, half-close, rejection`, {timeout:60000}, async t => {
  const echo = net.createServer({allowHalfOpen:true}, s => {
    s.on('error',()=>{}); s.on('data',data => s.write(data)); s.on('end',() => s.end(Buffer.from('END')));
  });
  echo.listen(0,'127.0.0.1'); await once(echo,'listening');
  const captureRoot=await mkdtemp(join(tmpdir(),'phone-exit-webrtc-capture-'));
  const diagnostics=new DiagnosticCapture({root:captureRoot,onStatus:()=>{throw Error('UI unavailable');}});
  const captureId=await diagnostics.start([{host:'127.0.0.1',port:echo.address().port}]);
  const a = new Transport({iceServers:[]}), b = new RTCPeerConnection({iceServers:[]});
  const flowWindow=Transport===NativePeer?2097152:1048576;
  const sendBuffer=Transport===NativePeer?524288:1048576;
  const socks = createSocksServer(a,{port:0,diagnostics,frameSize:4096,receiveWindow:flowWindow,sendBuffer,phoneReceiveBuffer:1048576,flowProbe:true});
  a.connectionStateChange.subscribe(state => { if(state==='closed'||state==='failed') socks.shutdown(); });
  const remoteSockets = new Set();
  t.after(async () => { socks.shutdown(); for (const s of remoteSockets) s.destroy(); echo.close(); await Promise.all([a.close(),b.close()]);await diagnostics.stop();await rm(captureRoot,{recursive:true,force:true}); });
  let controlResolve; const controlOpen = new Promise(r => controlResolve = r);
  b.onDataChannel.subscribe(dc => {
    if (dc.label === 'control') { dc.onopen = controlResolve; return; }
    dc.onMessage.once(data => {
      const message = JSON.parse(data);
      // The fake exit permits loopback exclusively inside this in-process test.
      assert.equal(message.host,'127.0.0.1'); assert.equal(message.port,echo.address().port);
      assert.equal(message.frameSize,4096);
      assert.equal(message.sendBuffer,sendBuffer);assert.equal(message.flowProbe,true);
      assert.equal(message.receiveBuffer,1048576);
      if(Transport===NativePeer)assert.equal(message.tcpWindow,2097152);
      const s = net.connect({host:message.host,port:message.port,allowHalfOpen:true});
      remoteSockets.add(s); s.once('close',()=>remoteSockets.delete(s));
      s.once('connect',() => { bridge(s,dc,{initiallyReady:true,sendWindow:flowWindow}); dc.send(JSON.stringify({type:'ready'})); });
    });
  });
  a.createDataChannel('control');
  await a.setLocalDescription(await a.createOffer()); const probe=observeTransport(a);await b.setRemoteDescription(a.localDescription);
  await b.setLocalDescription(await b.createAnswer()); await a.setRemoteDescription(b.localDescription);
  await controlOpen;
  const address = await socks.start();
  function reader(socket) {
    let buf = Buffer.alloc(0), waiting, failed;
    socket.on('data', d => { buf = Buffer.concat([buf,d]); waiting?.(); });
    socket.on('error', e => { failed = e; waiting?.(); });
    socket.on('close', () => { failed ||= Error('closed before response'); waiting?.(); });
    return async n => {
      while (buf.length < n) { if (failed) throw failed; await new Promise(resolve => { waiting = resolve; }); }
      const result = buf.subarray(0,n); buf = buf.subarray(n); waiting = undefined; return result;
    };
  }
  async function connect(command=1) {
    const s = net.connect({host:'127.0.0.1',port:address.port,allowHalfOpen:true});
    const read = reader(s); await once(s,'connect');
    s.write(Buffer.from([5])); s.write(Buffer.from([1,0])); assert.deepEqual(await read(2),Buffer.from([5,0]));
    const request = Buffer.from([5,command,0,1,127,0,0,1,0,0]); request.writeUInt16BE(echo.address().port,8);
    s.write(request); const reply = await read(10); return {s,read,reply};
  }
  const payloads=[];
  await Promise.all([0,1,2].map(async () => {
    const {s,read,reply} = await connect(); assert.equal(reply[1],0);
    const payload = randomBytes(Transport===NativePeer?5000000:700000);payloads.push(payload); s.write(payload); s.end();
    assert.deepEqual(await read(payload.length+3),Buffer.concat([payload,Buffer.from('END')])); s.destroy();
  }));
  await diagnostics.stop();
  const captured=await readCapture(join(captureRoot,captureId,'traffic.jsonl'));
  assert.equal(captured.summary.finalized,true);assert.ok(captured.summary.bytes>0);
  for(const f of captured.flows.values()){
    const sent=Buffer.concat(f.c2s),received=Buffer.concat(f.s2c);
    if(!sent.length)continue;
    const original=payloads.find(p=>p.subarray(0,sent.length).equals(sent));assert.ok(original,'Captured request matches original bytes');
    assert.ok(Buffer.concat([original,Buffer.from('END')]).subarray(0,received.length).equals(received),'Captured reply matches original bytes');
    if(Transport===RTCPeerConnection)assert.equal(sent.length,700000);
  }
  if(Transport===RTCPeerConnection){assert.ok(probe().bytes>=2100000);assert.ok(probe().sacks>0);}
  else assert.ok(a.iceTransports[0].connection.nominated,'Native selected ICE pair');
  for (const cmd of [2,3]) { const {s,reply} = await connect(cmd); assert.equal(reply[1],7); s.destroy(); }
  const {s} = await connect(); const ended = once(s,'end'); await a.close(); await ended; s.destroy();
});
