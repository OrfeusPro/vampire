import {RTCPeerConnection} from './native-peer.js';
import {randomBytes} from 'node:crypto';
import {ControlIcePoller} from './control-ice.js';

// Binary result: request UUID (16), total u32 BE, offset u32 BE, <=16 KiB payload.
export class DirectControl {
  constructor({id,bootstrap,pollIce,Peer=RTCPeerConnection}){this.id=id;this.bootstrap=bootstrap;this.pollIce=pollIce;this.Peer=Peer;this.jobs=new Map();this.closed=false;this.bytes=0;}
  async connect(){
    this.phase='gathering';
    const peer=this.peer=new this.Peer({iceServers:[{urls:['stun:stun.l.google.com:19302','stun:stun.cloudflare.com:3478']}]});
    const channel=this.channel=peer.createDataChannel('phone-exit-automation-v1');
    channel.onMessage.subscribe(v=>this.receive(v));
    channel.stateChange.subscribe(s=>{if(s==='closed')this.close();});
    peer.connectionStateChange.subscribe(s=>{if(['failed','closed','disconnected'].includes(s))this.close();});
    let deadline;
    try{
      const ready=new Promise((resolve,reject)=>{this.rejectReady=reject;channel.stateChange.subscribe(s=>{if(s==='open')resolve();});deadline=setTimeout(()=>reject(Error('direct connection timeout')),60000);});
      // Prevent an unhandled rejection while the encrypted HTTP offer is in flight.
      ready.catch(()=>{});
      await peer.setLocalDescription(await peer.createOffer());
      const summary=sdp=>Object.fromEntries(['host','srflx','prflx','relay'].map(type=>[type,(sdp.match(new RegExp(' typ '+type+'(?: |\\r|\\n)','g'))??[]).length]));
      this.candidates={pc:summary(peer.localDescription.sdp)};
      if(this.closed)throw Error('direct closed');
      this.phase='offer';
      const answer=await this.bootstrap(peer.localDescription.sdp);
      this.candidates.phone=summary(answer.sdp);
      // Structural diagnostics only: never expose SDP, addresses or ICE secrets.
      const structure=sdp=>({mediaSections:(sdp.match(/^m=/gm)??[]).length,rejectedSections:(sdp.match(/^m=\S+ 0 /gm)??[]).length,iceCredentials:(sdp.match(/^a=ice-ufrag:/gm)??[]).length});
      this.sdpStructure={pc:structure(peer.localDescription.sdp),phone:structure(answer.sdp)};
      if(this.closed)throw Error('direct closed');
      this.phase='channel';
      await peer.setRemoteDescription({type:answer.type,sdp:answer.sdp});
      if(this.pollIce&&/^[a-f0-9]{32}$/.test(answer.iceSession??'')&&!this.closed){
        this.iceAbort=new AbortController();
        this.icePoller=new ControlIcePoller({peer,session:answer.iceSession,poll:this.pollIce,signal:this.iceAbort.signal,initialSdp:answer.sdp});
        this.icePoller.run().catch(()=>{});
      }
      await ready;this.iceAbort?.abort();
      this.phase='connected';
      this.seen=Date.now();this.lastPing=0;
      this.timer=setInterval(()=>{
        if(Date.now()-this.seen>10000){this.close();return;}
        try{this.lastPing=Date.now();channel.send(JSON.stringify({type:'ping',request:String(this.lastPing)}));}catch{this.close();}
      },2000);this.timer.unref();
      this.cleanTimer=setInterval(()=>this.clean(),500);this.cleanTimer.unref();return this;
    }catch(e){this.phase='failed';this.failure=e.message;this.close();throw e;}finally{clearTimeout(deadline);this.rejectReady=null;}
  }
  clean(){for(const[k,j]of this.jobs)if(j.until<Date.now()){this.bytes-=j.size||0;this.jobs.delete(k);}}
  evict(required=0){
    for(const[k,j]of this.jobs){if(this.jobs.size<256&&this.bytes+required<=8388608)break;
      if(j.value){this.bytes-=j.size||0;this.jobs.delete(k);}
    }
  }
  send(command,args){
    this.clean();this.evict();if(this.closed||this.channel.readyState!=='open')throw Error('direct closed');
    if(this.jobs.size>=256||[...this.jobs.values()].filter(j=>!j.value).length>=4)throw Object.assign(Error('direct busy'),{status:429});
    const request=randomBytes(16).toString('hex'),frame=JSON.stringify({id:this.id,request,at:Date.now(),command,args});
    if(Buffer.byteLength(frame)>12000||this.channel.bufferedAmount>262144)throw Object.assign(Error('direct busy'),{status:429});
    const j={until:Date.now()+(command==='bot'&&args?.op==='install'?150000:30000)};this.jobs.set(request,j);
    try{this.channel.send(frame);}catch{this.close();}
    return {id:request,status:'queued',transport:'webrtc'};
  }
  receive(frame){
    if(this.closed)return;
    try{
      if(typeof frame==='string'){
        if(frame.length>256)throw Error();const p=JSON.parse(frame);
        if(p.type==='pong'&&p.request===String(this.lastPing)){this.seen=Date.now();this.rttMs=this.seen-this.lastPing;}return;
      }
      const b=Buffer.from(frame);if(b.length<25||b.length>16408)throw Error();
      const request=b.subarray(0,16).toString('hex'),total=b.readUInt32BE(16),offset=b.readUInt32BE(20),j=this.jobs.get(request);
      if(!j||j.value||total<1||total>2100000||offset+(b.length-24)>total)throw Error();
      if(!j.frame){this.evict(total);if(offset!==0||this.bytes+total>8388608)throw Error();j.frame=Buffer.alloc(total);j.size=total;this.bytes+=total;j.offset=0;}
      if(total!==j.size||offset!==j.offset)throw Error();b.copy(j.frame,offset,24);j.offset+=b.length-24;
      if(j.offset===total){
        const r=JSON.parse(j.frame.toString('utf8'));if(r.id!==this.id||r.request!==request||typeof r.ok!=='boolean'||!Number.isSafeInteger(r.at)||Math.abs(r.at-Date.now())>180000)throw Error();
        j.value={status:'done',result:r,transport:'webrtc'};j.frame=null;j.until=Date.now()+(r.result?.image?30000:120000);
      }
    }catch{this.close();}
  }
  get(request){this.clean();const j=this.jobs.get(request);return j?.value??{status:j&&!this.closed?'delivered':'expired',transport:'webrtc',error:this.closed?'channel lost; action not repeated':undefined};}
  close(){
    if(this.closed)return;this.closed=true;this.iceAbort?.abort();clearInterval(this.timer);clearInterval(this.cleanTimer);this.rejectReady?.(Error('direct closed'));
    for(const j of this.jobs.values())if(!j.value){this.bytes-=j.size||0;j.size=0;j.frame=null;j.value={status:'expired',transport:'webrtc',error:'channel lost; action not repeated'};}
    this.channel?.close();this.peer?.close();
  }
}
