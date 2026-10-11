// Test-only added outbound propagation delay; does not serialize packets.
export function addTestLatency(peer,ms){
  if(!Number.isInteger(ms)||ms<1||ms>500)throw Error('Invalid test latency');
  const sctp=peer.sctpTransport.sctp,transport=sctp.transport,send=transport.send.bind(transport),timers=new Set();
  const stop=sctp.stop.bind(sctp);
  transport.send=data=>{
    if(sctp.isStopped)return Promise.resolve();
    if(timers.size>=4096)return Promise.reject(Error('Test latency queue full'));
    const timer=setTimeout(()=>{timers.delete(timer);if(!sctp.isStopped)send(data).catch(()=>{});},ms);
    timers.add(timer);return Promise.resolve();
  };
  sctp.stop=async()=>{for(const timer of timers)clearTimeout(timer);timers.clear();await stop();};
}
