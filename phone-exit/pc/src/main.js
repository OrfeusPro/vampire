import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { RTCPeerConnection as NativePeer } from './native-peer.js';
import { createSocksServer } from './socks.js';
import {downloadProbeResult} from './download-probe.js';
import {observeTransport} from './transport-probe.js';
import {addTestLatency} from './latency-probe.js';
import {MultiPeer} from './multi-peer.js';
import {DiagnosticCapture} from './diagnostic-capture.js';
import {join} from 'node:path';
import {homedir} from 'node:os';

const diagnostics=new DiagnosticCapture({root:process.env.PHONE_EXIT_DIAGNOSTICS_DIR||join(process.env.LOCALAPPDATA||homedir(),'PhoneExit','diagnostics'),
  onStatus:value=>{if(process.env.PHONE_EXIT_DESKTOP==='1')console.log(JSON.stringify({event:'diagnostics',...value}));}});
let diagnosticCommands=Promise.resolve();

const endpoint = new URL(process.env.PHONE_EXIT_SIGNAL || 'https://demochko.com/hosting-webrtc-probe/signal.php');
if (endpoint.protocol !== 'https:') throw Error('Сигнализация требует HTTPS');
const port = Number(process.env.PHONE_EXIT_PORT || 1080);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error('Некорректный порт');
const token = randomBytes(32).toString('hex');
const bindAddress=process.env.PHONE_EXIT_BIND_V4;
if(bindAddress&&isIP(bindAddress)!==4)throw Error('Invalid physical interface address');
// Werift remains available for controlled comparisons, never as a silent relay/fallback.
const RTCPeerConnection=process.env.PHONE_EXIT_TRANSPORT==='werift'?(await import('werift')).RTCPeerConnection:NativePeer;
const requestedPeers=process.env.PHONE_EXIT_PEERS===undefined?null:Number(process.env.PHONE_EXIT_PEERS);
if(requestedPeers!==null&&(![1,2,4].includes(requestedPeers)||requestedPeers>1&&process.env.PHONE_EXIT_TRANSPORT==='werift'))throw Error('Дополнительные соединения требуют нативный транспорт и число 2 или 4');
let peerCount=1;
const stunServers=process.env.PHONE_EXIT_STUN_SERVERS?JSON.parse(process.env.PHONE_EXIT_STUN_SERVERS):['stun:stun.l.google.com:19302','stun:stun.cloudflare.com:3478'];
if(!Array.isArray(stunServers)||!stunServers.length||stunServers.length>16||stunServers.some(s=>typeof s!=='string'||!/^stun:(?:[0-9.]+|stun\.l\.google\.com|stun\.cloudflare\.com):(19302|3478)$/.test(s)))throw Error('Invalid STUN bootstrap servers');
const peerConfig={iceServers:stunServers.map(urls=>({urls})),
  ...(bindAddress?{iceInterfaceAddresses:{udp4:bindAddress},iceUseIpv6:false}:{})};
const peer = new RTCPeerConnection(peerConfig);
let pool;
let cursor = 0, stopped = false, connected = false, server, queue = Promise.resolve();
let heartbeat, lastSeen = 0, heartbeatSequence = 0;
const pings = new Map();
let probeSupported=false,probeId,uploadSupported=false,uploadId,flowSupported=false,flowId;
let transportProbe;
async function api(op,message) {
  const response = await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,role:'pc',op,message,after:cursor}),signal:AbortSignal.timeout(10000)});
  if (!response.ok) throw Error(response.status===429 && endpoint.pathname==='/hosting-webrtc-probe/signal.php'
    ? 'Старый сервер сигнализации переполнен (429). Установите APK 0.4.1 поверх старого на выбранном телефоне.'
    : 'Сервер сигнализации: HTTP ' + response.status);
  return response.json();
}
const send = message => { queue = queue.then(() => stopped || connected ? null : api('send',message)); queue.catch(fail); return queue; };
async function stop() {
  if (stopped) return; stopped = true; clearTimeout(deadline); clearTimeout(disconnectTimer); clearInterval(heartbeat);
  server?.shutdown();
  pool?.close();
  if (control.readyState === 'open') {
    try { control.send(JSON.stringify({type:'bye'})); await new Promise(resolve=>setTimeout(resolve,100)); } catch {}
  }
  // This module is the CLI entry point; bound shutdown even if a library timer
  // or an in-flight ICE/HTTP operation outlives the closed proxy.
  const forceExit=setTimeout(() => process.exit(process.exitCode || 0),3000);
  await diagnostics.stop('transport_stopped');
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
      if(hello.type==='flow-probe'&&flowId&&hello.id===flowId){
        const fields=['bytes','frames','creditWaits','bufferWaits','waitMs','maxBuffer',...(hello.socketBuffer!==undefined?['socketBuffer']:[])];
        if(fields.every(key=>Number.isSafeInteger(hello[key])&&hello[key]>=0)&&hello.maxBuffer<=1064960&&process.env.PHONE_EXIT_DESKTOP==='1')console.log(JSON.stringify({event:'flow-probe',...Object.fromEntries(fields.map(key=>[key,hello[key]]))}));return;
      }
      if(hello.type==='download-probe'&&probeId){const result=downloadProbeResult(hello,probeId);if(result&&process.env.PHONE_EXIT_DESKTOP==='1')console.log(JSON.stringify({event:'download-probe',...result}));return;}
      if(hello.type==='upload-probe'&&uploadId){const result=downloadProbeResult(hello,uploadId,'upload-probe');if(result&&process.env.PHONE_EXIT_DESKTOP==='1')console.log(JSON.stringify({event:'upload-probe',...result}));return;}
      if(hello.type==='bye') { fail(Error('Телефон остановил выход')); return; }
      if(hello.type==='pong' && pings.has(hello.id)) {
        const now=performance.now(), rtt=Math.max(0,Math.round(now-pings.get(hello.id)));
        pings.delete(hello.id); lastSeen=now;
        if(process.env.PHONE_EXIT_DESKTOP==='1') console.log(JSON.stringify({event:'ping',rtt}));
        if(transportProbe)console.log(JSON.stringify({event:'transport-probe',...transportProbe()}));
      }
      return;
    }
    if (hello.type !== 'hello' || hello.version !== 1) throw Error('Несовместимое приложение');
    probeSupported=hello.features?.includes('download-probe-v1')===true;
    uploadSupported=hello.features?.includes('upload-probe-v1')===true;
    flowSupported=hello.features?.includes('flow-probe-v1')===true;
    const advancedFlow=flowSupported&&hello.limits?.maxTcpWindow===4194304;
    const receiveWindow=advancedFlow?Number(process.env.PHONE_EXIT_TCP_WINDOW||2097152):hello.limits?.tcpWindow===1048576?1048576:262144;
    if(![262144,1048576,2097152,4194304].includes(receiveWindow)||(advancedFlow&&receiveWindow===262144))throw Error('Некорректное окно TCP');
    const sendBuffer=flowSupported?Number(process.env.PHONE_EXIT_TCP_BUFFER||(advancedFlow?524288:262144)):262144;
    const phoneReceiveBuffer=advancedFlow?Number(process.env.PHONE_EXIT_PHONE_RCVBUF||0):0;
    const multiSupported=hello.features?.includes('multi-peer-v1')&&hello.limits?.maxPeers===4;
    peerCount=requestedPeers??(multiSupported&&RTCPeerConnection===NativePeer?4:1);
    if(peerCount>1&&!multiSupported)throw Error('Для дополнительных соединений установите APK 0.4.7');
    connected = true; clearTimeout(deadline);
    pool=new MultiPeer(peer,{count:peerCount,config:peerConfig,onFailure:fail});
    // Peer-reflexive candidates can exist only on the selected pair, rather than
    // in the signaled candidates list. Bypass their exact endpoints before TUN.
    lastSeen=performance.now();
    heartbeat=setInterval(() => {
      if(process.env.PHONE_EXIT_DESKTOP==='1'&&server) console.log(JSON.stringify({event:'metrics',...server.metrics(),peerCount,lanePings:pool.lastPings}));
      if(performance.now()-lastSeen>8000 || control.readyState!=='open') { fail(Error('Телефон не отвечает, прокси остановлен')); return; }
      const id=String(++heartbeatSequence); pings.set(id,performance.now());
      while(pings.size>8) pings.delete(pings.keys().next().value);
      try { control.send(JSON.stringify({type:'ping',id})); } catch(error) { fail(error); }
    },2000);
    await pool.start();
    if(stopped)return;
    server = createSocksServer(pool,{port,diagnostics,maxStreams:hello.limits?.tcp===128?192:hello.limits?.tcp===64?80:32,udpEnabled:hello.features?.includes('udp-v1')===true,frameSize:Number(process.env.PHONE_EXIT_FRAME_SIZE||16384),receiveWindow,sendBuffer,phoneReceiveBuffer,flowProbe:flowSupported&&process.env.PHONE_EXIT_DIAG_PARALLEL==='1'});
    const addresses=pool.iceTransports.flatMap(t=>[
      ...t.connection.remoteCandidates.map(c=>c.host),...t.connection.candidatePairs.map(p=>p.remoteCandidate.host),t.connection.nominated?.remoteAddr?.[0],
    ]).filter(Boolean);
    console.log(JSON.stringify({event:'transport',addresses:[...new Set(addresses)],peerCount,udp:hello.features?.includes('udp-v1')===true,downloadProbe:probeSupported,uploadProbe:uploadSupported,flowProbe:flowSupported,advancedFlow,tcpWindow:receiveWindow,sendBuffer,phoneReceiveBuffer}));
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
    if (commands.length > 8192) { stop(); return; }
    let end;
    while ((end = commands.indexOf('\n')) >= 0) {
      const command = commands.slice(0,end).trim(); commands = commands.slice(end+1);
      if (command === 'stop') stop();
      if(command==='probe-download'&&connected&&probeSupported&&!probeId){probeId=randomBytes(8).toString('hex');control.send(JSON.stringify({type:'download-probe',id:probeId}));}
      if(command==='probe-upload'&&connected&&uploadSupported&&!uploadId){uploadId=randomBytes(8).toString('hex');control.send(JSON.stringify({type:'upload-probe',id:uploadId}));}
      if(command==='probe-flow'&&connected&&flowSupported&&!flowId){flowId=randomBytes(8).toString('hex');control.send(JSON.stringify({type:'flow-probe',id:flowId}));}
      if(command==='probe-stats'&&transportProbe)console.log(JSON.stringify({event:'transport-probe',...transportProbe()}));
      if(command.startsWith('{'))diagnosticCommands=diagnosticCommands.then(async()=>{
        try {
          const request=JSON.parse(command);
          if(request.op==='capture-start'){
            if(stopped||!connected||!server)throw Error('Transport unavailable');
            await diagnostics.start(request.filters,{mode:request.mode});
            if(stopped)await diagnostics.stop('transport_stopped');
          }else if(request.op==='capture-stop')await diagnostics.stop();
          else if(request.op==='capture-status')console.log(JSON.stringify({event:'diagnostics',...diagnostics.status()}));
        }catch{console.log(JSON.stringify({event:'diagnostics-command-error'}));}
      });
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
  if(process.env.PHONE_EXIT_TEST_LATENCY_MS){if(!peer.sctpTransport)throw Error('Диагностическая задержка требует PHONE_EXIT_TRANSPORT=werift');addTestLatency(peer,Number(process.env.PHONE_EXIT_TEST_LATENCY_MS));}
  if(process.env.PHONE_EXIT_TRANSPORT_PROBE==='1')transportProbe=observeTransport(peer);
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
