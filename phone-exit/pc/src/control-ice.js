// Late candidates travel in the existing encrypted mailbox, never in logs.
export class ControlIcePoller {
  constructor({peer,session,poll,signal,initialSdp='',pauseMs=700}){
    this.peer=peer;this.session=session;this.poll=poll;this.signal=signal;this.pauseMs=pauseMs;
    this.known=new Set(initialSdp.split(/\r?\n/).filter(s=>s.startsWith('a=candidate:')).map(s=>s.slice(2)));
    this.added=0;this.failures=0;
  }
  async run(){
    for(let attempt=0;attempt<40&&!this.signal.aborted;attempt++){
      try{
        const value=await this.poll(this.session,this.signal);
        if(this.signal.aborted)return;
        if(value.iceSession!==this.session||value.closed)return;
        if(!Array.isArray(value.candidates)||value.candidates.length>32)throw Error('invalid ICE snapshot');
        for(const c of value.candidates){
          if(this.signal.aborted)return;
          if(typeof c.candidate!=='string'||!c.candidate.startsWith('candidate:')||c.candidate.length>2048||
            typeof c.sdpMid!=='string'||c.sdpMid.length>32||!Number.isInteger(c.sdpMLineIndex)||c.sdpMLineIndex<0||c.sdpMLineIndex>8)throw Error('invalid ICE candidate');
          if(this.known.has(c.candidate))continue;
          if(this.known.size>=64)return;
          await this.peer.addIceCandidate(c);this.known.add(c.candidate);this.added++;
        }
      }catch{if(this.signal.aborted||++this.failures>=3)return;}
      await new Promise(resolve=>{
        if(this.signal.aborted){resolve();return;}
        const finish=()=>{clearTimeout(timer);this.signal.removeEventListener('abort',finish);resolve();};
        const timer=setTimeout(finish,this.pauseMs);this.signal.addEventListener('abort',finish,{once:true});
      });
    }
  }
}
