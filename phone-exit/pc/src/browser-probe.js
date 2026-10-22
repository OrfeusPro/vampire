import {RTCPeerConnection} from './native-peer.js';
import {LABEL,description,candidate,safeReport} from '../../diagnostics/browser/shared.js';

// Owns one native peer; no proxy, routes, account access or background reconnect.
export async function runBrowserProbe({api,onPhase=()=>{},waitMs=600000,checkMs=90000,Peer=RTCPeerConnection}){
  const peer=new Peer({iceServers:[{urls:['stun:stun.l.google.com:19302','stun:stun.cloudflare.com:3478']}]});
  const dc=peer.createDataChannel(LABEL);let after=0,remote=false,received=0,pongs=0,next=0,deadline=Date.now()+waitMs,ack=false,report;
  const abort=new AbortController();let timer;
  const result={result:'timeout',pongs:0};
  const fail=()=>{result.result='failed';deadline=Math.min(deadline,Date.now()+3000);};
  const ping=()=>{try{if(dc.bufferedAmount>4096)throw Error();dc.send(JSON.stringify({type:'ping',seq:++next}));}catch{fail();}};
  dc.stateChange.subscribe(state=>{if(state==='open'){onPhase('channel_open');ping();}});
  dc.onMessage.subscribe(raw=>{
    try{
      if(typeof raw!=='string'||raw.length>256)throw Error();const v=JSON.parse(raw);
      if(v.type==='pong'&&v.seq===next&&next===pongs+1&&pongs<5){pongs++;if(pongs===5)dc.send('{"type":"done"}');else ping();}
      else if(v.type==='doneAck'&&pongs===5){ack=true;result.result='connected';deadline=Math.min(deadline,Date.now()+5000);onPhase('five_echoes_passed');}
      else throw Error();
    }catch{fail();}
  });
  peer.connectionStateChange.subscribe(state=>{if(['connected','failed','closed','disconnected'].includes(state))onPhase('peer_'+state);});
  try{
    await peer.setLocalDescription(await peer.createOffer());
    await api({op:'send',message:{type:'offer',value:description(peer.localDescription,'offer')}},abort.signal);onPhase('offer_ready');
    timer=setTimeout(()=>abort.abort(),waitMs+15000);
    const pending=[];
    while(Date.now()<deadline&&!report){
      const response=await api({op:'poll',after},abort.signal);
      for(const item of response.messages??[]){
        after=Math.max(after,item.id);const m=item.message;
        if(m?.type==='answer'&&!remote){remote=true;await peer.setRemoteDescription(description(m.value,'answer'));deadline=Math.min(deadline,Date.now()+checkMs);onPhase('browser_answer_received');
          for(const c of pending)await peer.addIceCandidate(c);pending.length=0;}
        else if(m?.type==='candidate'){
          if(m.probeReport)report=safeReport(m.probeReport);
          if(m.value&&received++<32){const c=candidate(m.value);if(remote)await peer.addIceCandidate(c);else pending.push(c);}
        }
      }
      if(!report)await new Promise(r=>setTimeout(r,500));
    }
    if(!ack&&report?.result==='connected')await new Promise(r=>setTimeout(r,1000));
    if(!ack&&report)result.result=report.result==='connected'?'failed':report.result;
    result.pongs=pongs;result.browser=report??null;result.answerReceived=remote;
    // A browser claim alone is never proof: five authenticated echoes + doneAck required.
    if(!ack&&result.result==='connected')result.result='failed';
    return result;
  }catch{result.result='https_or_signal_failed';result.pongs=pongs;result.answerReceived=remote;return result;}
  finally{abort.abort();clearTimeout(timer);dc.close();await peer.close();}
}
