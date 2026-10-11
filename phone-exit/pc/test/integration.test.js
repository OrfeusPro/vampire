import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { RTCPeerConnection } from 'werift';
import { createSocksServer } from '../src/socks.js';
import { bridge } from '../src/bridge.js';

test('SOCKS5 over real WebRTC: binary, parallel streams, half-close, rejection', {timeout:60000}, async t => {
  const echo = net.createServer({allowHalfOpen:true}, s => {
    s.on('error',()=>{}); s.on('data',data => s.write(data)); s.on('end',() => s.end(Buffer.from('END')));
  });
  echo.listen(0,'127.0.0.1'); await once(echo,'listening');
  const a = new RTCPeerConnection({iceServers:[]}), b = new RTCPeerConnection({iceServers:[]});
  const socks = createSocksServer(a,{port:0});
  a.connectionStateChange.subscribe(state => { if(state==='closed'||state==='failed') socks.shutdown(); });
  const remoteSockets = new Set();
  t.after(async () => { socks.shutdown(); for (const s of remoteSockets) s.destroy(); echo.close(); await Promise.all([a.close(),b.close()]); });
  let controlResolve; const controlOpen = new Promise(r => controlResolve = r);
  b.onDataChannel.subscribe(dc => {
    if (dc.label === 'control') { dc.onopen = controlResolve; return; }
    dc.onMessage.once(data => {
      const message = JSON.parse(data);
      // The fake exit permits loopback exclusively inside this in-process test.
      assert.equal(message.host,'127.0.0.1'); assert.equal(message.port,echo.address().port);
      const s = net.connect({host:message.host,port:message.port,allowHalfOpen:true});
      remoteSockets.add(s); s.once('close',()=>remoteSockets.delete(s));
      s.once('connect',() => { bridge(s,dc,{initiallyReady:true}); dc.send(JSON.stringify({type:'ready'})); });
    });
  });
  a.createDataChannel('control');
  await a.setLocalDescription(await a.createOffer()); await b.setRemoteDescription(a.localDescription);
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
  await Promise.all([0,1,2].map(async () => {
    const {s,read,reply} = await connect(); assert.equal(reply[1],0);
    const payload = randomBytes(700000); s.write(payload); s.end();
    assert.deepEqual(await read(payload.length+3),Buffer.concat([payload,Buffer.from('END')])); s.destroy();
  }));
  for (const cmd of [2,3]) { const {s,reply} = await connect(cmd); assert.equal(reply[1],7); s.destroy(); }
  const {s} = await connect(); const ended = once(s,'end'); await a.close(); await ended; s.destroy();
});
