import native from 'node-datachannel';
import {isIP} from 'node:net';
// Minimal transport adapter for the bounded Phone Exit protocol. No TURN or raw logs.
native.initLogger('Fatal',()=>{});
class Signal {
  callbacks=new Set();
  subscribe(fn){this.callbacks.add(fn);return {unSubscribe:()=>this.callbacks.delete(fn)};}
  once(fn){const wrapped=(...args)=>{this.callbacks.delete(wrapped);fn(...args);};return this.subscribe(wrapped);}
  emit(...args){for(const fn of this.callbacks)fn(...args);}
}
class Channel {
  onMessage=new Signal();stateChange=new Signal();bufferedAmountLow=new Signal();
  constructor(dc){
    this.dc=dc;this.label=dc.getLabel();this.readyState=dc.isOpen()?'open':'connecting';
    dc.onOpen(()=>{this.readyState='open';this.stateChange.emit('open');this.onopen?.();});
    dc.onClosed(()=>{this.readyState='closed';this.stateChange.emit('closed');this.onclose?.();});
    dc.onError(()=>this.close());
    dc.onMessage(msg=>this.onMessage.emit(msg instanceof ArrayBuffer?Buffer.from(msg):msg));
    dc.onBufferedAmountLow(()=>this.bufferedAmountLow.emit());
  }
  get bufferedAmount(){return this.dc.bufferedAmount();}
  set bufferedAmountLowThreshold(value){this.dc.setBufferedAmountLowThreshold(value);}
  send(value){if(this.readyState!=='open')throw Error('Native channel closed');
    if(typeof value==='string')this.dc.sendMessage(value);else this.dc.sendMessageBinary(value);}
  close(){if(this.readyState==='closed')return;this.readyState='closed';this.dc.close();}
}
export class RTCPeerConnection {
  connectionStateChange=new Signal();onIceCandidate=new Signal();onDataChannel=new Signal();
  connectionState='new';remoteDescription=null;localDescription=null;remoteAddresses=new Set();
  constructor(config){
    const bindAddress=config.iceInterfaceAddresses?.udp4;
    if(bindAddress&&isIP(bindAddress)!==4)throw Error('Invalid native interface address');
    this.pc=new native.PeerConnection('PhoneExit',{iceServers:config.iceServers.flatMap(s=>s.urls),disableAutoNegotiation:true,enableIceTcp:false,maxMessageSize:65536,...(bindAddress?{bindAddress}:{})});
    this.pc.onStateChange(state=>{this.connectionState=state;this.connectionStateChange.emit(state);});
    this.pc.onLocalCandidate((candidate,mid)=>this.onIceCandidate.emit({toJSON:()=>({candidate,sdpMid:mid,sdpMLineIndex:0})}));
    this.pc.onLocalDescription((sdp,type)=>{this.localDescription={type,sdp};this.descriptionResolve?.(this.localDescription);});
    this.pc.onGatheringStateChange(state=>{if(state==='complete'){this.gathered=true;this.gatherResolve?.();}});
    this.pc.onDataChannel(dc=>this.onDataChannel.emit(new Channel(dc)));
  }
  rememberCandidate(candidate){const host=candidate.trim().split(/\s+/)[4];if(isIP(host))this.remoteAddresses.add(host);}
  get iceTransports(){const pair=this.pc.getSelectedCandidatePair();return [{connection:{remoteCandidates:[...this.remoteAddresses].map(host=>({host})),candidatePairs:[],nominated:pair?{remoteAddr:[pair.remote.address,pair.remote.port]}:null}}];}
  createDataChannel(label,options={}){return new Channel(this.pc.createDataChannel(label,{unordered:options.ordered===false,...(options.maxRetransmits!==undefined?{maxRetransmits:options.maxRetransmits}:{})}));}
  async createOffer(){return {type:'offer'};}
  async setLocalDescription(description){
    const ready=new Promise(resolve=>this.descriptionResolve=resolve);
    const gathered=new Promise(resolve=>{this.gatherResolve=resolve;if(this.gathered)resolve();});
    let timer;const deadline=new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('Native ICE gathering timeout')),15000));
    try {this.pc.setLocalDescription(description.type);await Promise.race([Promise.all([ready,gathered]),deadline]);this.localDescription=this.pc.localDescription();}
    finally {clearTimeout(timer);this.descriptionResolve=undefined;this.gatherResolve=undefined;}
  }
  async setRemoteDescription(description){this.remoteDescription=description;for(const line of description.sdp.split(/\r?\n/)){if(line.startsWith('a=candidate:'))this.rememberCandidate(line.slice(2));}this.pc.setRemoteDescription(description.sdp,description.type);}
  async addIceCandidate(candidate){if(candidate?.candidate){this.rememberCandidate(candidate.candidate);this.pc.addRemoteCandidate(candidate.candidate,candidate.sdpMid||'0');}}
  async close(){this.pc.close();}
}
