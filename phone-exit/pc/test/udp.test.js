import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { RTCPeerConnection } from 'werift';
import {RTCPeerConnection as NativePeer} from '../src/native-peer.js';
import { createSocksServer } from '../src/socks.js';
import { decodeDatagram,envelope } from '../src/udp.js';
import { vpnConfig } from '../src/vpn-config.js';

test('UDP envelope rejects fragmentation, truncation, malformed names and oversized datagrams',()=>{
  const original=envelope('1.1.1.1',53,Buffer.from('dns'));assert.equal(decodeDatagram(original).host,'1.1.1.1');
  const frag=Buffer.from(original);frag[2]=1;assert.equal(decodeDatagram(frag),null);
  assert.equal(decodeDatagram(original.subarray(0,9)),null);assert.equal(decodeDatagram(Buffer.alloc(1401)),null);
  assert.equal(decodeDatagram(envelope('bad/name',53,Buffer.from('a'))),null);
});
test('VPN modes preserve transport paths, tunnel DNS, and never use a direct fallback for all traffic',()=>{
  const full=vpnConfig({transportAddresses:['1.2.3.4','not-an-ip'],nodePath:'C:\\runtime\\node.exe'});
  assert.equal(full.route.final,'phone');assert.equal(full.dns.servers[0].detour,'phone');
  assert.deepEqual(full.inbounds[0].route_exclude_address,['1.2.3.4/32']);assert.equal(full.inbounds[0].strict_route,true);
  const selected=vpnConfig({mode:'apps',applications:['C:\\Game\\game.exe']});assert.equal(selected.route.final,'direct');assert.equal(selected.dns.servers[0].detour,undefined);assert.equal(selected.dns.servers[1].type,'fakeip');assert.equal(selected.route.default_domain_resolver,'direct-dns');
  assert.ok(selected.route.rules.some(r=>r.process_path_regex?.some(p=>p.startsWith('(?i)^')&&p.endsWith('$'))&&r.outbound==='phone'));
  assert.throws(()=>vpnConfig({mode:'apps',applications:[]}));assert.throws(()=>vpnConfig({mode:'apps',applications:['relative.exe']}));
  const live=vpnConfig({mode:'apps',applications:['C:\\Game\\game.exe'],applicationRuleFile:'C:\\PhoneExit\\applications-rules.json'});
  assert.equal(live.route.rule_set[0].type,'local');assert.equal(live.route.rule_set[0].format,'source');
  assert.ok(live.route.rules.some(r=>r.rule_set?.includes('selected-applications')&&r.outbound==='phone'));
  assert.equal(live.dns.rules[0].server,'direct-dns');assert.ok(live.dns.rules[0].domain.includes('demochko.com'));
  assert.equal(full.dns.rules[0].server,'direct-dns');assert.equal(full.dns.final,'phone-dns');
  assert.ok(full.route.rules[0].process_path_regex[0].startsWith('(?i)^'));
  assert.throws(()=>vpnConfig({mode:'apps',applications:['C:\\Game\\game.exe'],applicationRuleFile:'relative.json'}));
});
for(const Transport of [RTCPeerConnection,NativePeer])test(`real WebRTC UDP (${Transport===NativePeer?'native':'werift'}): SOCKS association, boundaries, source pinning, lifecycle`, {timeout:30000},async t=>{
  const a=new Transport({iceServers:[]}),b=new RTCPeerConnection({iceServers:[]});
  const socks=createSocksServer(a,{port:0,udpEnabled:true});const udp=dgram.createSocket('udp4');const stray=dgram.createSocket('udp4');let tcp;
  t.after(async()=>{tcp?.destroy();socks.shutdown();udp.close();stray.close();await Promise.all([a.close(),b.close()]);});
  let resolve;const opened=new Promise(r=>resolve=r);
  b.onDataChannel.subscribe(dc=>{
    if(dc.label==='control'){dc.onopen=resolve;return;}
    dc.onMessage.subscribe(data=>{if(typeof data==='string')dc.send(JSON.stringify({type:'ready'}));else dc.send(data);});
  });
  a.createDataChannel('control');await a.setLocalDescription(await a.createOffer());await b.setRemoteDescription(a.localDescription);
  await b.setLocalDescription(await b.createAnswer());await a.setRemoteDescription(b.localDescription);await opened;
  const address=await socks.start();tcp=net.connect(address.port,'127.0.0.1');await once(tcp,'connect');
  const greeting=once(tcp,'data');tcp.write(Buffer.from([5,1,0]));assert.deepEqual((await greeting)[0],Buffer.from([5,0]));
  const reply=once(tcp,'data');tcp.write(Buffer.from([5,3,0,1,0,0,0,0,0,0]));const response=(await reply)[0];assert.equal(response[1],0);const port=response.readUInt16BE(8);
  udp.bind(0,'127.0.0.1');await once(udp,'listening');stray.bind(0,'127.0.0.1');await once(stray,'listening');
  for(const size of [1,19,1200]){const packet=envelope('1.1.1.1',53,Buffer.alloc(size,77));const got=once(udp,'message');udp.send(packet,port,'127.0.0.1');assert.deepEqual((await got)[0],packet);}
  let leaked=false;stray.on('message',()=>leaked=true);stray.send(envelope('1.1.1.1',53,Buffer.from('stray')),port,'127.0.0.1');
  await new Promise(r=>setTimeout(r,100));assert.equal(leaked,false);
  tcp.destroy();await new Promise(r=>setTimeout(r,100));
  let afterClose=false;udp.on('message',()=>afterClose=true);udp.send(envelope('1.1.1.1',53,Buffer.from('closed')),port,'127.0.0.1');await new Promise(r=>setTimeout(r,100));assert.equal(afterClose,false);
});
