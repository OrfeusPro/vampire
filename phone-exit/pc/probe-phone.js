import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createInterface} from 'node:readline';
import {readFileSync,writeFileSync} from 'node:fs';
import {vpnConfig} from './src/vpn-config.js';
import net from 'node:net';
import dgram from 'node:dgram';
import assert from 'node:assert/strict';
import {lookup} from 'node:dns/promises';
import {once} from 'node:events';
import {Directory} from './src/directory.js';
import {envelope,decodeDatagram} from './src/udp.js';
const directory=new Directory(()=>{});directory.setAccount(JSON.parse(readFileSync(0,'utf8').replace(/^\uFEFF/,'')));directory.setPhones([]);
const loadStreams=(process.env.PHONE_EXIT_DIAG_STREAMS||'1,4').split(',').map(Number);
assert.ok(loadStreams.length>0&&loadStreams.length<=4&&new Set(loadStreams).size===loadStreams.length&&loadStreams.every(n=>[1,4,8,16].includes(n)),'Invalid load stream counts');
const loadBytes=process.env.PHONE_EXIT_DIAG_TOTAL_BYTES?Number(process.env.PHONE_EXIT_DIAG_TOTAL_BYTES):0;
assert.ok(loadBytes===0||[20000000,32000000].includes(loadBytes),'Invalid total load bytes');
const discoveryDeadline=performance.now()+60000;
let phone;for(let attempt=0;attempt<15&&performance.now()<discoveryDeadline;attempt++){await timeout(directory.poll(),25000);phone=directory.phones.find(p=>p.name.includes(process.argv[2]||'V2061'));if(phone&&directory.states.get(phone.id)?.busy===false)break;await new Promise(r=>setTimeout(r,2000));}
assert.ok(phone,'Phone not discovered');assert.ok(directory.states.get(phone.id)&&Date.now()-directory.states.get(phone.id).at<45000,'Phone offline');assert.equal(directory.states.get(phone.id).busy,false,'Phone busy');
if(process.env.PHONE_EXIT_EXPECT_PRODUCT_SIGNAL==='1')assert.equal(phone.signal,'https://demochko.com/phone-exit/signal.php','Phone must advertise product signaling');
const child=spawn(process.execPath,['src/main.js'],{stdio:['pipe','pipe','pipe'],windowsHide:true,env:{...process.env,PHONE_EXIT_DESKTOP:'1',PHONE_EXIT_SIGNAL:phone.signal}});
child.stderr.on('data',()=>{});const lines=createInterface({input:child.stdout});
let transport,tcp,udp,engine,transportStats,udpProxyPort;
const pingSamples=[];
const lanePingSamples=[];
let resolveDirect;const directDownload=new Promise(r=>resolveDirect=r);
let resolveUpload;const directUpload=new Promise(r=>resolveUpload=r);
let resolveFlow;const flowStats=new Promise(r=>resolveFlow=r);
function timeout(p,ms=45000){let timer;return Promise.race([p,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('Probe timeout')),ms))]).finally(()=>clearTimeout(timer));}
let resolvePair,resolveReady,resolvePing;const pair=new Promise(r=>resolvePair=r),ready=new Promise(r=>resolveReady=r),ping=new Promise(r=>resolvePing=r);
lines.on('line',line=>{if(line.startsWith('{')){const event=JSON.parse(line);if(event.version===1)resolvePair(event);if(event.event==='transport')transport=event;if(event.event==='metrics'&&Array.isArray(event.lanePings))lanePingSamples.push(...event.lanePings.filter(Number.isInteger));if(event.event==='transport-probe')transportStats=event;if(event.event==='download-probe')resolveDirect(event);if(event.event==='upload-probe')resolveUpload(event);if(event.event==='flow-probe')resolveFlow(event);if(event.event==='ping'){pingSamples.push(event.rtt);resolvePing(event.rtt);}}if(line.startsWith('Готово: SOCKS5'))resolveReady();});
try{
  await directory.connect(phone.id,await timeout(pair,10000));await timeout(ready,90000);
  if(Number(process.env.PHONE_EXIT_TCP_BUFFER||262144)!==262144)assert.ok(transport.flowProbe,'Update selected phone to APK 0.4.5 before tuning send buffer');
  if(process.env.PHONE_EXIT_TCP_WINDOW||process.env.PHONE_EXIT_PHONE_RCVBUF)assert.ok(transport.advancedFlow,'Update selected phone to APK 0.4.6 before tuning TCP window or receive buffer');
  const rtt=await timeout(ping,10000);assert.ok(Number.isInteger(rtt)&&rtt>=0&&rtt<8000,'Invalid phone heartbeat RTT');
  console.log('PASS: real WebRTC phone heartbeat RTT: '+rtt+' ms');
  if(transport.peerCount>1)console.log('PASS: independent WebRTC associations ready: '+transport.peerCount);
  await promisify(execFile)('curl.exe',['--silent','--fail','--max-time','20','--socks5-hostname','127.0.0.1:1080','https://example.com'],{windowsHide:true});
  console.log('PASS: native phone HTTPS through WebRTC; transport addresses captured: '+transport.addresses.length);
  if(process.env.PHONE_EXIT_CHAIN==='1'){
    const cfg=vpnConfig();cfg.inbounds=[{type:'mixed',listen:'127.0.0.1',listen_port:1081}];cfg.route.rules=[];
    writeFileSync('../.tools/chain-check.json',JSON.stringify(cfg));engine=spawn('../.tools/sing-box/sing-box.exe',['run','-c','../.tools/chain-check.json'],{stdio:'ignore',windowsHide:true});await new Promise(r=>setTimeout(r,1500));
    for(const flag of ['--socks5-hostname','--socks5']){await promisify(execFile)('curl.exe',['--silent','--show-error','--fail','--max-time','15',flag,'127.0.0.1:1081','https://api.ipify.org'],{windowsHide:true});console.log('PASS: sing-box TCP chain '+flag);}
  }
  if(!transport.udp){console.log('INFO: phone APK supports TCP only; upgrade required for VPN');}
  else {
    tcp=net.connect(1080,'127.0.0.1');await timeout(once(tcp,'connect'),5000);
    let response=once(tcp,'data');tcp.write(Buffer.from([5,1,0]));assert.deepEqual((await timeout(response,5000))[0],Buffer.from([5,0]));
    response=once(tcp,'data');tcp.write(Buffer.from([5,3,0,1,0,0,0,0,0,0]));const bound=(await timeout(response,15000))[0];assert.equal(bound[1],0);udpProxyPort=bound.readUInt16BE(8);
    udp=dgram.createSocket('udp4');udp.bind(0,'127.0.0.1');await once(udp,'listening');
    const query=Buffer.from('123401000001000000000000076578616d706c6503636f6d0000010001','hex');
    response=once(udp,'message');udp.send(envelope('1.1.1.1',53,query),bound.readUInt16BE(8),'127.0.0.1');
    const answer=decodeDatagram((await timeout(response,15000))[0]);assert.ok(answer);assert.equal(answer.port,53);assert.equal(answer.payload.readUInt16BE(0),0x1234);assert.ok(answer.payload[2]&0x80);assert.ok(answer.payload.readUInt16BE(6)>0);
    console.log('PASS: native UDP DNS response through phone Wi-Fi; packet boundary and transaction ID verified');
    const stun=Buffer.from('000100002112a442010203040506070809101112','hex');const target=await lookup('stun.l.google.com',{family:4});let stunReply;
    for(let retry=0;retry<3&&!stunReply;retry++){const response=once(udp,'message');udp.send(envelope(target.address,19302,stun),bound.readUInt16BE(8),'127.0.0.1');try{stunReply=decodeDatagram((await timeout(response,3000))[0]);}catch{}}
    assert.ok(stunReply,'No public STUN response');assert.equal(stunReply.payload.readUInt16BE(0),0x101);assert.deepEqual(stunReply.payload.subarray(8,20),stun.subarray(8,20));console.log('PASS: native UDP STUN on port 19302');
  }
  let direct;
  if(process.env.PHONE_EXIT_DIAG_PARALLEL==='1'){
    assert.ok(udp&&tcp,'UDP support required for load test');
    const phases=[];
    for(const [phaseIndex,streams] of loadStreams.entries()){
      const bytesPerStream=loadBytes?loadBytes/streams:streams===1&&process.env.PHONE_EXIT_DIAG_LONG==='1'?20000000:5000000;
      const pending=new Map(),udpRtts=[];let sent=0,received=0,sequence=phaseIndex*16384;
      const pingStart=pingSamples.length;
      const lanePingStart=lanePingSamples.length;
      const receive=packet=>{const reply=decodeDatagram(packet);if(!reply||reply.host!=='1.1.1.1'||reply.port!==53||reply.payload.length<12)return;
        const id=reply.payload.readUInt16BE(0),started=pending.get(id);if(started===undefined)return;
        pending.delete(id);received++;udpRtts.push(Math.round(performance.now()-started));};
      udp.on('message',receive);
      const sample=()=>{
        const now=performance.now();for(const [id,started] of pending)if(now-started>3000)pending.delete(id);
        if(pending.size>=4||sent>=180)return;
        const query=Buffer.from('123401000001000000000000076578616d706c6503636f6d0000010001','hex');
        const id=(++sequence)&65535;query.writeUInt16BE(id);pending.set(id,now);sent++;
        udp.send(envelope('1.1.1.1',53,query),udpProxyPort,'127.0.0.1');
      };
      const timer=setInterval(sample,1000);sample();const started=performance.now();
      const abort=new AbortController();let downloads=[];
      try{
        downloads=Array.from({length:streams},()=>promisify(execFile)('curl.exe',['--silent','--show-error','--fail','--max-time','90','--socks5-hostname','127.0.0.1:1080','--output','NUL','--write-out','{"bytes":%{size_download},"seconds":%{time_total}}','https://speed.cloudflare.com/__down?bytes='+bytesPerStream],{windowsHide:true,signal:abort.signal}).then(result=>JSON.parse(result.stdout)));
        const results=await Promise.all(downloads);
        const elapsed=(performance.now()-started)/1000;
        for(const result of results)assert.equal(result.bytes,bytesPerStream);
        clearInterval(timer);await new Promise(resolve=>setTimeout(resolve,Math.min(3000,pending.size?3000:0)));
        const pings=pingSamples.slice(pingStart);
        const phase={streams,bytes:results.reduce((total,result)=>total+result.bytes,0),seconds:elapsed,mbps:Number((streams*bytesPerStream*8/elapsed/1e6).toFixed(3)),heartbeat:{samples:pings.length,min:Math.min(...pings),max:Math.max(...pings),average:Math.round(pings.reduce((a,b)=>a+b,0)/pings.length)},udp:{sent,received,missing:sent-received,min:Math.min(...udpRtts),max:Math.max(...udpRtts),average:Math.round(udpRtts.reduce((a,b)=>a+b,0)/udpRtts.length)}};
        const lanePings=lanePingSamples.slice(lanePingStart);if(lanePings.length)phase.laneHeartbeat={samples:lanePings.length,min:Math.min(...lanePings),max:Math.max(...lanePings),average:Math.round(lanePings.reduce((a,b)=>a+b,0)/lanePings.length)};
        phase.downloadSeconds=results.map(result=>result.seconds);
        phases.push(phase);console.log('Load comparison '+JSON.stringify(phase));
      }finally{clearInterval(timer);udp.removeListener('message',receive);abort.abort();await Promise.allSettled(downloads);}
    }
    let flow;
    if(transport.flowProbe){child.stdin.write('probe-flow\n');flow=await timeout(flowStats,5000);console.log('Phone flow aggregate '+JSON.stringify(flow));}
    writeFileSync('../.tools/load-comparison.json',JSON.stringify({transport:process.env.PHONE_EXIT_TRANSPORT||'native',peerCount:transport.peerCount||1,sendBuffer:transport.sendBuffer,tcpWindow:transport.tcpWindow,phoneReceiveBuffer:transport.phoneReceiveBuffer,frameSize:Number(process.env.PHONE_EXIT_FRAME_SIZE||16384),phases,flow},null,2));
  }
  if(process.env.PHONE_EXIT_DIAG_UPLINK==='1'){
    assert.ok(transport.uploadProbe,'Update selected phone to APK 0.4.3');child.stdin.write('probe-upload\n');
    const upload=await timeout(directUpload,70000);assert.equal(upload.success,true,'Direct phone upload failed');console.log('PASS: direct phone Wi-Fi upload '+JSON.stringify(upload));
  }
  if(process.env.PHONE_EXIT_DIAG_COMPARE==='1'){
    assert.ok(transport.downloadProbe,'Update selected phone to APK 0.4.2');child.stdin.write('probe-download\n');
    direct=await timeout(directDownload,70000);assert.equal(direct.success,true,'Direct phone download failed');console.log('PASS: direct phone Wi-Fi download '+JSON.stringify(direct));
  }
  if(process.env.PHONE_EXIT_DIAG_DOWNLOAD==='1'||direct){
    const result=await promisify(execFile)('curl.exe',['--silent','--show-error','--fail','--max-time','60','--socks5-hostname','127.0.0.1:1080','--output','NUL','--write-out','{"bytes":%{size_download},"seconds":%{time_total},"bytesPerSecond":%{speed_download}}','https://speed.cloudflare.com/__down?bytes=5000000'],{windowsHide:true});
    const stats=JSON.parse(result.stdout);assert.equal(stats.bytes,5000000);console.log('PASS: real phone 5 MB HTTPS download '+JSON.stringify(stats));
    if(process.env.PHONE_EXIT_TRANSPORT_PROBE==='1'){child.stdin.write('probe-stats\n');await new Promise(r=>setTimeout(r,100));}
    console.log('Heartbeat during probe '+JSON.stringify({samples:pingSamples.length,min:Math.min(...pingSamples),max:Math.max(...pingSamples),average:Math.round(pingSamples.reduce((a,b)=>a+b,0)/pingSamples.length)}));
    if(transportStats)console.log('SCTP aggregate '+JSON.stringify(transportStats));
    if(direct){const comparison={direct:{bytes:direct.bytes,seconds:direct.seconds,bytesPerSecond:direct.bytesPerSecond},tunnel:stats,tunnelToDirectRatio:stats.bytesPerSecond/direct.bytesPerSecond};writeFileSync('../.tools/network-comparison.json',JSON.stringify(comparison,null,2));console.log('Comparison '+JSON.stringify(comparison));}
  }
}finally{
  engine?.kill();tcp?.destroy();udp?.close();child.stdin.end('stop\n');await timeout(once(child,'exit'),7000).catch(()=>child.kill());lines.close();
}
