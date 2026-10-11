// Opt-in, bounded aggregate SCTP diagnostics. No addresses or payloads are stored.
export function observeTransport(peer){
  const stats={chunks:0,bytes:0,duplicates:0,gapArrivals:0,maxGap:0,sacks:0};
  const seen=new Set();let highest;
  const sctp=peer.sctpTransport?.sctp;
  if(!sctp)return ()=>null;
  const receive=sctp.receiveDataChunk.bind(sctp),sack=sctp.sendSack.bind(sctp);
  sctp.receiveDataChunk=chunk=>{
    stats.chunks++;stats.bytes+=chunk.userData.length;
    if(seen.has(chunk.tsn))stats.duplicates++;
    else{
      seen.add(chunk.tsn);if(seen.size>4096)seen.delete(seen.values().next().value);
      const delta=highest===undefined?0:(chunk.tsn-highest)>>>0;
      if(highest===undefined||(delta>0&&delta<0x80000000)){
        if(highest!==undefined&&delta>1){stats.gapArrivals++;stats.maxGap=Math.max(stats.maxGap,delta-1);}highest=chunk.tsn;
      }
    }
    return receive(chunk);
  };
  sctp.sendSack=()=>{stats.sacks++;return sack();};
  return ()=>({...stats,receiverWindow:sctp.advertisedRwnd,peerWindow:sctp.peerAdvertisedRwnd,congestionWindow:sctp.cwnd,rtoMs:Math.round(sctp.rto*1000),srttMs:Math.round((sctp.srtt||0)*1000)});
}
