import net from 'node:net';
import { udpAssociation } from './udp.js';

export function createSocksServer(peer, {port = 1080, maxStreams = 32, udpEnabled = false} = {}) {
  let sequence = 0;
  const sockets = new Set();
  let associations=0, rejected=0, opened=0, readyCount=0, errorCount=0;
  const udpMetrics={udpSent:0,udpResponse:0,udpSourceRejected:0};
  const server = net.createServer({allowHalfOpen:true}, socket => {
    if (sockets.size >= maxStreams) { rejected++;socket.destroy(); return; }
    opened++;
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.setTimeout(120000, () => socket.destroy());
    let buffer = Buffer.alloc(0), stage = 'greeting';
    const deadline = setTimeout(() => socket.destroy(), 15000);
    socket.once('close', () => clearTimeout(deadline));
    const reply = code => socket.write(Buffer.from([5,code,0,1,0,0,0,0,0,0]));
    function fail(code) { reply(code); socket.end(); socket.removeListener('data', parse); }
    function parse(data) {
      buffer = Buffer.concat([buffer,data]);
      if (buffer.length > 65536) return socket.destroy();
      if (stage === 'greeting') {
        if (buffer.length < 2) return;
        if (buffer[0] !== 5 || buffer[1] === 0) return socket.destroy();
        const size = 2 + buffer[1]; if (buffer.length < size) return;
        if (!buffer.subarray(2,size).includes(0)) { socket.end(Buffer.from([5,255])); return; }
        socket.write(Buffer.from([5,0])); buffer = buffer.subarray(size); stage = 'request';
      }
      if (buffer.length < 4) return;
      if (buffer[0] !== 5 || buffer[2] !== 0) return fail(1);
      const command=buffer[1];
      if (command !== 1 && !(command===3&&udpEnabled)) return fail(7);
      const type = buffer[3]; let length, offset, host;
      if (type === 1) { length = 10; offset = 8; }
      else if (type === 3) { if (buffer.length < 5) return; if (!buffer[4]) return fail(8); offset = 5 + buffer[4]; length = offset + 2; }
      else if (type === 4) { length = 22; offset = 20; }
      else return fail(8);
      if (buffer.length < length) return;
      if (type === 1) host = Array.from(buffer.subarray(4,8)).join('.');
      else if (type === 3) { host = buffer.subarray(5,offset).toString('ascii'); if (!/^[a-zA-Z0-9._-]+$/.test(host)) return fail(8); }
      else host = Array.from({length:8}, (_,i) => buffer.readUInt16BE(4+i*2).toString(16)).join(':');
      const destPort = buffer.readUInt16BE(offset); if (!destPort&&command===1) return fail(1);
      if (peer.connectionState !== 'connected') return fail(1);
      if(command===1&&sockets.size-associations>(maxStreams>=192?128:maxStreams>=80?64:maxStreams))return fail(1);
      clearTimeout(deadline); socket.pause(); socket.setTimeout(0);
      socket.removeListener('data',parse);
      if(command===3) {
        if(associations>=(maxStreams>=192?64:maxStreams>=80?16:4))return fail(1);
        associations++;socket.once('close',()=>associations--);
        let replied=false;
        udpAssociation(socket,peer,'phone-exit-udp-v1-'+(++sequence),udpPort=>{
          if(socket.destroyed)return;replied=true;const answer=Buffer.from([5,0,0,1,127,0,0,1,0,0]);answer.writeUInt16BE(udpPort,8);socket.write(answer);socket.resume();
        },()=>{if(!replied&&!socket.destroyed){replied=true;reply(1);}},key=>{udpMetrics[key]++;});
        socket.on('data',()=>socket.destroy());socket.on('end',()=>socket.destroy());
        return;
      }
      const remainder = buffer.subarray(length); if (remainder.length) socket.unshift(remainder);
      const channel = peer.createDataChannel('phone-exit-tcp-v1-' + (++sequence), {ordered:true});
      import('./bridge.js').then(({bridge}) => {
        if (socket.destroyed) { channel.close(); return; }
        let replied = false;
        bridge(socket,channel,{onReady:() => { if (!replied) { readyCount++;replied = true; reply(0); } }, onError:code => {errorCount++; if (!replied && !socket.destroyed) { replied = true; reply(code); } }});
        const open = () => channel.send(JSON.stringify({type:'open',host,port:destPort}));
        if (channel.readyState === 'open') open(); else channel.onopen = open;
      }).catch(() => socket.destroy());
    }
    socket.on('data',parse);
    socket.on('error', () => {});
  });
  server.shutdown = () => { for (const socket of sockets) socket.destroy(); server.close(); };
  server.metrics=()=>({active:sockets.size,rejected,opened,ready:readyCount,errors:errorCount,udp:associations,...udpMetrics});
  server.start = () => new Promise((resolve,reject) => {
    server.once('error',reject); server.listen(port,'127.0.0.1',() => { server.removeListener('error',reject); resolve(server.address()); });
  });
  return server;
}
