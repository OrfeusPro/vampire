import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { RTCPeerConnection } from 'werift';
import { createSocksServer } from './socks.js';

const endpoint = new URL(process.env.PHONE_EXIT_SIGNAL || 'https://demochko.com/hosting-webrtc-probe/signal.php');
if (endpoint.protocol !== 'https:') throw Error('Сигнализация требует HTTPS');
const port = Number(process.env.PHONE_EXIT_PORT || 1080);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error('Некорректный порт');
const token = randomBytes(32).toString('hex');
const bindAddress=process.env.PHONE_EXIT_BIND_V4;
if(bindAddress&&isIP(bindAddress)!==4)throw Error('Invalid physical interface address');
const peer = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun.cloudflare.com:3478'}],
  ...(bindAddress?{iceInterfaceAddresses:{udp4:bindAddress},iceUseIpv6:false}:{})});
let cursor = 0, stopped = false, connected = false, server, queue = Promise.resolve();
let heartbeat, lastSeen = 0, heartbeatSequence = 0;
const pings = new Map();
async function api(op,message) {
  const response = await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,role:'pc',op,message,after:cursor}),signal:AbortSignal.timeout(10000)});
  if (!response.ok) throw Error('Сигнализация: HTTP ' + response.status);
  return response.json();
}
const send = message => { queue = queue.then(() => stopped || connected ? null : api('send',message)); queue.catch(fail); return queue; };
async function stop() {
  if (stopped) return; stopped = true; clearTimeout(deadline); clearTimeout(disconnectTimer); clearInterval(heartbeat);
  server?.shutdown();
  if (control.readyState === 'open') {
    try { control.send(JSON.stringify({type:'bye'})); await new Promise(resolve=>setTimeout(resolve,100)); } catch {}
  }
  // This module is the CLI entry point; bound shutdown even if a library timer
  // or an in-flight ICE/HTTP operation outlives the closed proxy.
  const forceExit=setTimeout(() => process.exit(process.exitCode || 0),3000);
  try { await peer.close(); } finally { clearTimeout(forceExit); process.exit(process.exitCode || 0); }
}
function fail(error) { console.error(error.message || 'Соединение потеряно'); process.exitCode = 1; stop(); }
let disconnectTimer;
peer.connectionStateChange.subscribe(state => {
  console.log('WebRTC:',state);
  if (state === 'failed' || state === 'closed') { if (!stopped) fail(Error('Нет прямой связи с телефоном')); }
  if (state === 'disconnected') disconnectTimer = setTimeout(() => fail(Error('Телефон отключён')),10000);
  if (state === 'connected') clearTimeout(disconnectTimer);
});
peer.onIceCandidate.subscribe(candidate => { if (candidate) send({type:'candidate',value:candidate.toJSON()}); });
const control = peer.createDataChannel('phone-exit-control-v1',{ordered:true});
control.onMessage.subscribe(async data => {
  try {
    if (typeof data !== 'string' || data.length > 1024 || stopped) return;
    const hello = JSON.parse(data);
    if(connected) {
      if(hello.type==='bye') { fail(Error('Телефон остановил выход')); return; }
      if(hello.type==='pong' && pings.has(hello.id)) {
        const now=performance.now(), rtt=Math.max(0,Math.round(now-pings.get(hello.id)));
        pings.delete(hello.id); lastSeen=now;
        if(process.env.PHONE_EXIT_DESKTOP==='1') console.log(JSON.stringify({event:'ping',rtt}));
      }
      return;
    }
    if (hello.type !== 'hello' || hello.version !== 1) throw Error('Несовместимое приложение');
    connected = true; clearTimeout(deadline); server = createSocksServer(peer,{port,maxStreams:hello.limits?.tcp===128?192:hello.limits?.tcp===64?80:32,udpEnabled:hello.features?.includes('udp-v1')===true});
    // Peer-reflexive candidates can exist only on the selected pair, rather than
    // in the signaled candidates list. Bypass their exact endpoints before TUN.
    const addresses=peer.iceTransports.flatMap(t=>[
      ...t.connection.remoteCandidates.map(c=>c.host),
      ...t.connection.candidatePairs.map(p=>p.remoteCandidate.host),
      t.connection.nominated?.remoteAddr?.[0],
    ]).filter(Boolean);
    console.log(JSON.stringify({event:'transport',addresses:[...new Set(addresses)],udp:hello.features?.includes('udp-v1')===true}));
    lastSeen=performance.now();
    heartbeat=setInterval(() => {
      if(process.env.PHONE_EXIT_DESKTOP==='1') console.log(JSON.stringify({event:'metrics',...server.metrics()}));
      if(performance.now()-lastSeen>8000 || control.readyState!=='open') { fail(Error('Телефон не отвечает, прокси остановлен')); return; }
      const id=String(++heartbeatSequence); pings.set(id,performance.now());
      while(pings.size>8) pings.delete(pings.keys().next().value);
      try { control.send(JSON.stringify({type:'ping',id})); } catch(error) { fail(error); }
    },2000);
    await server.start(); console.log(`Готово: SOCKS5 127.0.0.1:${port}. DNS через телефон (socks5h).`);
  } catch (error) { fail(error); }
});
control.onclose = () => { if (!stopped) fail(Error('Телефон остановил выход')); };
const deadline = setTimeout(() => fail(Error('Истекло время сопряжения')),600000);
process.on('SIGINT',stop); process.on('SIGTERM',stop);
// The desktop parent owns this pipe. Closing its window must stop the proxy.
if (process.env.PHONE_EXIT_DESKTOP === '1') {
  process.stdin.setEncoding('utf8');
  let commands = '';
  process.stdin.on('data', chunk => {
    commands += chunk;
    if (commands.length > 1024) { stop(); return; }
    let end;
    while ((end = commands.indexOf('\n')) >= 0) {
      const command = commands.slice(0,end).trim(); commands = commands.slice(end+1);
      if (command === 'stop') stop();
    }
  });
  process.stdin.on('end',stop);
}
// Pairing code is a capability: display once for manual entry, never write to disk.
console.log('Открой приложение Phone Exit на Android и вставь код сопряжения:');
console.log(JSON.stringify({version:1,signal:endpoint.href,token}));
console.log('Ожидаю телефон. В этой версии доступен TCP SOCKS, системные режимы ещё разрабатываются.');
try {
  await peer.setLocalDescription(await peer.createOffer());
  await send({type:'offer',value:peer.localDescription});
  const candidates = [];
  while (!stopped && !connected) {
    const result = await api('poll');
    for (const item of result.messages) {
      const message = item.message;
      if (message.type === 'candidate') {
        if (peer.remoteDescription) await peer.addIceCandidate(message.value); else candidates.push(message.value);
      } else if (message.type === 'answer' && !peer.remoteDescription) {
        await peer.setRemoteDescription(message.value);
        for (const c of candidates) await peer.addIceCandidate(c); candidates.length = 0;
      }
      cursor = Math.max(cursor,item.id);
    }
    if (!stopped && !connected) await new Promise(resolve => setTimeout(resolve,1000));
  }
} catch(error) { fail(error); }
