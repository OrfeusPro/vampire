import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {once} from 'node:events';
import {createSocksServer} from '../src/socks.js';

test('rejected SOCKS requests release their slot while the caller keeps its write side open', {timeout:5000}, async t=>{
  const server=createSocksServer({connectionState:'disconnected'},{port:0,maxStreams:4});
  const clients=[];
  t.after(()=>{for(const client of clients)client.destroy();server.shutdown();});
  const address=await server.start();
  for(let i=0;i<12;i++){
    const client=net.connect({host:'127.0.0.1',port:address.port,allowHalfOpen:true});
    clients.push(client);client.on('error',()=>{});
    await once(client,'connect');
    const greeting=once(client,'data');client.write(Buffer.from([5,1,0]));
    assert.deepEqual((await greeting)[0],Buffer.from([5,0]));
    const response=once(client,'data');
    client.write(Buffer.from([5,i%2?2:1,0,1,1,1,1,1,1,187]));
    assert.equal((await response)[0][1],i%2?7:1);
    // The client deliberately never sends FIN; the server owns rejection cleanup.
    const deadline=Date.now()+500;
    while(server.metrics().active&&Date.now()<deadline)await new Promise(r=>setTimeout(r,10));
    assert.equal(server.metrics().active,0);
  }
  assert.equal(server.metrics().rejected,0);
});
