import {RTCPeerConnection as NativePeer} from './native-peer.js';

// Extra ICE/DTLS/SCTP associations are negotiated inside the authenticated
// primary channel. They do not create additional catalog requests or relays.
export class MultiPeer {
  constructor(primary,{count=1,config,onFailure=()=>{},Peer=NativePeer}={}) {
    if(![1,2,4].includes(count))throw Error('Invalid peer count');
    this.primary=primary;this.count=count;this.config=config;this.onFailure=onFailure;this.Peer=Peer;
    this.lanes=[];this.next=0;this.closed=false;this.lastPings=[];
  }
  get connectionState(){return this.closed?'closed':this.primary.connectionState;}
  get iceTransports(){return [this.primary,...this.lanes.map(l=>l.peer)].flatMap(p=>p.iceTransports);}
  createDataChannel(label,options){
    if(this.closed)throw Error('Peer pool closed');
    // Keep voice/game UDP and the primary heartbeat away from bulk TCP queues.
    const peer=label.startsWith('phone-exit-tcp-v1-')&&this.lanes.length
      ?this.lanes[this.next++%this.lanes.length].peer:this.primary;
    return peer.createDataChannel(label,options);
  }
  failure(error){if(!this.closed){this.onFailure(error);this.close();}}
  send(message){if(this.closed||this.signal?.readyState!=='open')throw Error('Negotiation channel closed');
    const body=JSON.stringify(message);if(Buffer.byteLength(body)>32768)throw Error('Negotiation frame too large');this.signal.send(body);}
  async start(){
    if(this.count===1)return;
    this.signal=this.primary.createDataChannel('phone-exit-links-v1',{ordered:true});
    let signalReady;const opened=new Promise(r=>signalReady=r);
    this.signal.onopen=signalReady;this.signal.onclose=()=>this.failure(Error('Канал настройки соединений закрыт'));
    this.signal.onMessage.subscribe(data=>{
      if(this.closed)return;
      this.handle(data).catch(error=>this.failure(error));
    });
    this.timeout=setTimeout(()=>this.failure(Error('Истекло время настройки дополнительных соединений')),40000);
    const failed=new Promise((_,reject)=>this.rejectStart=reject);
    try {
      await Promise.race([opened,failed]);
      for(let id=1;id<this.count;id++){
        const peer=new this.Peer(this.config);let ready;
        const lane={id,peer,control:peer.createDataChannel('phone-exit-lane-v1',{ordered:true}),pending:[],remote:[],pings:new Map(),lastSeen:performance.now(),sequence:0,ready:new Promise(r=>ready=r)};
        lane.resolve=ready;this.lanes.push(lane);
        peer.connectionStateChange.subscribe(state=>{if(['failed','closed','disconnected'].includes(state)&&!this.closed)this.failure(Error('Дополнительное соединение потеряно'));});
        peer.onIceCandidate.subscribe(candidate=>{if(candidate){const value=candidate.toJSON();if(lane.sent){try{this.send({type:'candidate',lane:id,value});}catch(error){this.failure(error);}}else if(lane.pending.length<64)lane.pending.push(value);else this.failure(Error('Too many local candidates'));}});
        lane.control.onclose=()=>this.failure(Error('Телефон закрыл дополнительное соединение'));
        lane.control.onMessage.subscribe(data=>{
          if(this.closed||typeof data!=='string'||Buffer.byteLength(data)>1024)return;
          try{const msg=JSON.parse(data);
            if(msg.type==='lane-ready'&&msg.lane===id){lane.lastSeen=performance.now();lane.resolve();}
            if(msg.type==='pong'&&lane.pings.has(msg.id)){const now=performance.now();lane.lastSeen=now;this.lastPings[id-1]=Math.round(now-lane.pings.get(msg.id));lane.pings.delete(msg.id);}
          }catch(error){this.failure(error);}
        });
        await Promise.race([peer.setLocalDescription(await peer.createOffer()),failed]);
        this.send({type:'offer',lane:id,value:peer.localDescription});lane.sent=true;
        for(const value of lane.pending)this.send({type:'candidate',lane:id,value});lane.pending=[];
      }
      await Promise.race([Promise.all(this.lanes.map(l=>l.ready)),failed]);
      for(const lane of this.lanes)lane.lastSeen=performance.now();
      this.heartbeat=setInterval(()=>{
        for(const lane of this.lanes){
          if(performance.now()-lane.lastSeen>8000||lane.control.readyState!=='open'){this.failure(Error('Дополнительное соединение не отвечает'));return;}
          const id=String(++lane.sequence);lane.pings.set(id,performance.now());while(lane.pings.size>8)lane.pings.delete(lane.pings.keys().next().value);
          try{lane.control.send(JSON.stringify({type:'ping',id}));}catch(error){this.failure(error);return;}
        }
      },2000);
    }finally{clearTimeout(this.timeout);}
  }
  async handle(data){
    if(typeof data!=='string'||Buffer.byteLength(data)>32768)throw Error('Invalid negotiation frame');
    const msg=JSON.parse(data),lane=this.lanes.find(l=>l.id===msg.lane);
    if(!lane||!['answer','candidate'].includes(msg.type))throw Error('Invalid negotiation lane');
    // Serialize each peer's SDP and trickle candidates independently.
    lane.queue=(lane.queue||Promise.resolve()).then(async()=>{
      if(this.closed)return;
      if(msg.type==='answer'){
        if(lane.answered||msg.value?.type!=='answer'||typeof msg.value.sdp!=='string')throw Error('Invalid lane answer');
        lane.answered=true;await lane.peer.setRemoteDescription(msg.value);
        for(const c of lane.remote)await lane.peer.addIceCandidate(c);lane.remote=[];
      }else if(lane.peer.remoteDescription)await lane.peer.addIceCandidate(msg.value);
      else {if(lane.remote.length>=64)throw Error('Too many lane candidates');lane.remote.push(msg.value);}
    });await lane.queue;
  }
  close(){
    if(this.closed)return;this.closed=true;clearTimeout(this.timeout);clearInterval(this.heartbeat);
    this.rejectStart?.(Error('Peer pool stopped'));
    this.signal?.close();for(const lane of this.lanes){lane.control.close();lane.peer.close();}
  }
}
