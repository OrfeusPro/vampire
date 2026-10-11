import dgram from 'node:dgram';
import net from 'node:net';
export const UDP_MTU = 1400;
// SOCKS5 UDP envelopes are also the wire format. Fragmentation is not supported.
export function decodeDatagram(data) {
  if (!Buffer.isBuffer(data) || data.length < 7 || data.length > UDP_MTU || data[0] || data[1] || data[2]) return null;
  let host, offset;
  if (data[3] === 1) { if(data.length<10)return null;host=[...data.subarray(4,8)].join('.');offset=8; }
  else if(data[3]===4) { if(data.length<22)return null;host=Array.from({length:8},(_,i)=>data.readUInt16BE(4+i*2).toString(16)).join(':');offset=20; }
  else if(data[3]===3) { offset=5+data[4];if(!data[4]||data.length<offset+2)return null;host=data.subarray(5,offset).toString('ascii');if(!/^[a-zA-Z0-9._-]+$/.test(host))return null; }
  else return null;
  const port=data.readUInt16BE(offset);if(!port||data.length<=offset+2)return null;
  return {host,port,payload:data.subarray(offset+2)};
}
export function envelope(host,port,payload) {
  const ip=net.isIP(host); let header;
  if(ip===4)header=Buffer.from([0,0,0,1,...host.split('.').map(Number),0,0]);
  else { const name=Buffer.from(host);if(name.length>253)throw Error('address');header=Buffer.concat([Buffer.from([0,0,0,3,name.length]),name,Buffer.alloc(2)]); }
  header.writeUInt16BE(port,header.length-2);return Buffer.concat([header,payload]);
}
export function udpAssociation(socket,peer,label,onReady,onError,onMetric=()=>{}) {
  const udp=dgram.createSocket('udp4');
  const channel=peer.createDataChannel(label,{ordered:false,maxRetransmits:0});
  let endpoint,ready=false,closed=false,retry;
  const deadline=setTimeout(()=>{onError();close();},15000);
  function close() {if(closed)return;closed=true;clearTimeout(deadline);clearInterval(retry);try{udp.close();}catch{}channel.close();socket.destroy();}
  socket.on('close',close);socket.on('error',close);
  channel.stateChange.subscribe(state=>{if(state==='closed')close();});
  channel.onMessage.subscribe(data=>{
    if(closed)return;
    if(typeof data==='string') {
      if(data.length>256){close();return;}
      try {const msg=JSON.parse(data);if(msg.type==='ready'&&!ready){ready=true;clearTimeout(deadline);clearInterval(retry);onReady(udp.address().port);}else if(msg.type==='error'){onError();close();}}catch{close();}
    } else if(ready&&endpoint&&decodeDatagram(data)){onMetric('udpResponse');udp.send(data,endpoint.port,'127.0.0.1',()=>{});}
  });
  udp.on('error',()=>{onError();close();});
  udp.on('message',(data,info)=>{
    if(info.address!=='127.0.0.1'){onMetric('udpSourceRejected');return;}
    if(!ready||!decodeDatagram(data))return;
    if(!endpoint)endpoint={port:info.port};
    if(endpoint.port!==info.port||channel.readyState!=='open'||channel.bufferedAmount>65536)return;
    try{channel.send(data);onMetric('udpSent');}catch{close();}
  });
  udp.bind(0,'127.0.0.1',()=>{
    const open=()=>{if(!closed&&!ready&&channel.readyState==='open')channel.send(JSON.stringify({type:'open'}));};
    channel.onopen=open;if(channel.readyState==='open')open();retry=setInterval(open,500);
  });
  return {close};
}
