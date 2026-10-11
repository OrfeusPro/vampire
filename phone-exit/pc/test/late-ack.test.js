import test from 'node:test';
import assert from 'node:assert/strict';
import { RTCSctpTransport } from 'werift';
test('late DCEP ACK cannot terminate transport or reopen cancelled channels',async()=>{
 const transport=new RTCSctpTransport();
 await transport.datachannelReceive(42,50,Buffer.from([2]));
 for(const readyState of ['closing','closed']){
  transport.dataChannels[42]={readyState,setReadyState(){assert.fail('cancelled channel reopened');}};
  await transport.datachannelReceive(42,50,Buffer.from([2]));
 }
 let opened=false;
 transport.dataChannels[42]={readyState:'connecting',setReadyState(state){opened=state==='open';}};
 await transport.datachannelReceive(42,50,Buffer.from([2]));assert.equal(opened,true);
});
