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
let phone;for(let attempt=0;attempt<15;attempt++){await directory.poll();phone=directory.phones.find(p=>p.name.includes(process.argv[2]||'V2061'));if(phone&&directory.states.get(phone.id)?.busy===false)break;await new Promise(r=>setTimeout(r,2000));}
assert.ok(phone,'Phone not discovered');assert.ok(directory.states.get(phone.id)&&Date.now()-directory.states.get(phone.id).at<45000,'Phone offline');assert.equal(directory.states.get(phone.id).busy,false,'Phone busy');
const child=spawn(process.execPath,['src/main.js'],{stdio:['pipe','pipe','pipe'],windowsHide:true,env:{...process.env,PHONE_EXIT_DESKTOP:'1'}});
child.stderr.on('data',()=>{});const lines=createInterface({input:child.stdout});
let transport,tcp,udp,engine;
function timeout(p,ms=45000){let timer;return Promise.race([p,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('Probe timeout')),ms))]).finally(()=>clearTimeout(timer));}
let resolvePair,resolveReady,resolvePing;const pair=new Promise(r=>resolvePair=r),ready=new Promise(r=>resolveReady=r),ping=new Promise(r=>resolvePing=r);
lines.on('line',line=>{if(line.startsWith('{')){const event=JSON.parse(line);if(event.version===1)resolvePair(event);if(event.event==='transport')transport=event;if(event.event==='ping')resolvePing(event.rtt);}if(line.startsWith('Готово: SOCKS5'))resolveReady();});
try{
  await directory.connect(phone.id,await timeout(pair,10000));await timeout(ready);
  const rtt=await timeout(ping,10000);assert.ok(Number.isInteger(rtt)&&rtt>=0&&rtt<8000,'Invalid phone heartbeat RTT');
  console.log('PASS: real WebRTC phone heartbeat RTT: '+rtt+' ms');
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
    response=once(tcp,'data');tcp.write(Buffer.from([5,3,0,1,0,0,0,0,0,0]));const bound=(await timeout(response,15000))[0];assert.equal(bound[1],0);
    udp=dgram.createSocket('udp4');udp.bind(0,'127.0.0.1');await once(udp,'listening');
    const query=Buffer.from('123401000001000000000000076578616d706c6503636f6d0000010001','hex');
    response=once(udp,'message');udp.send(envelope('1.1.1.1',53,query),bound.readUInt16BE(8),'127.0.0.1');
    const answer=decodeDatagram((await timeout(response,15000))[0]);assert.ok(answer);assert.equal(answer.port,53);assert.equal(answer.payload.readUInt16BE(0),0x1234);assert.ok(answer.payload[2]&0x80);assert.ok(answer.payload.readUInt16BE(6)>0);
    console.log('PASS: native UDP DNS response through phone Wi-Fi; packet boundary and transaction ID verified');
    const stun=Buffer.from('000100002112a442010203040506070809101112','hex');const target=await lookup('stun.l.google.com',{family:4});let stunReply;
    for(let retry=0;retry<3&&!stunReply;retry++){const response=once(udp,'message');udp.send(envelope(target.address,19302,stun),bound.readUInt16BE(8),'127.0.0.1');try{stunReply=decodeDatagram((await timeout(response,3000))[0]);}catch{}}
    assert.ok(stunReply,'No public STUN response');assert.equal(stunReply.payload.readUInt16BE(0),0x101);assert.deepEqual(stunReply.payload.subarray(8,20),stun.subarray(8,20));console.log('PASS: native UDP STUN on port 19302');
  }
}finally{
  engine?.kill();tcp?.destroy();udp?.close();child.stdin.end('stop\n');await timeout(once(child,'exit'),7000).catch(()=>child.kill());lines.close();
}
