// Explicit local TCP observation. Never enabled by environment or reconnect.
import {createWriteStream} from 'node:fs';
import {mkdir, writeFile} from 'node:fs/promises';
import {finished} from 'node:stream/promises';
import {join, resolve} from 'node:path';
import {isIP} from 'node:net';
import {randomBytes} from 'node:crypto';

export const CAPTURE_LIMITS={
  endpoints:{maxBytes:8388608,maxFileBytes:12582912,maxPendingBytes:2097152,maxRecords:32768,maxFlows:16,durationMs:180000},
  'all-tcp':{maxBytes:33554432,maxFileBytes:50331648,maxPendingBytes:2097152,maxRecords:131072,maxFlows:1024,durationMs:180000}
};
const DEFAULTS=CAPTURE_LIMITS.endpoints;
function hostName(host) {
  if(typeof host!=='string'||host.length>253||!host.length||!/^[a-zA-Z0-9.-]+$/.test(host))throw Error('Invalid capture endpoint');
  if(isIP(host)===4)return host;
  if(!host.replace(/\.$/,'').split('.').every(s=>/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(s)))throw Error('Invalid capture endpoint');
  return host.toLowerCase().replace(/\.$/,'');
}
export function captureFilters(filters) {
  if(!Array.isArray(filters)||filters.length<1||filters.length>16)throw Error('Expected 1..16 capture endpoints');
  return filters.map(f=>{
    if(!f||typeof f!=='object'||!Number.isInteger(f.port)||f.port<1||f.port>65535)throw Error('Invalid capture endpoint');
    return {host:hostName(f.host),port:f.port};
  });
}

export class DiagnosticCapture {
  constructor({root,onStatus=()=>{},limits={}}) {
    this.root=resolve(root);this.onStatus=onStatus;this.limits={...DEFAULTS,...limits};this.overrides={...limits};
    for(const [key,max] of Object.entries(CAPTURE_LIMITS['all-tcp']))if(!Number.isInteger(this.limits[key])||this.limits[key]<1||this.limits[key]>max)throw Error('Invalid capture limits');
    this.current=null;this.busy=false;this.last={state:'off',bytes:0,flows:0};
  }
  status(){return {...this.last};}
  emit(value){this.last=value;try{this.onStatus({...value});}catch{/* Diagnostics must not affect transport. */}}
  async start(filters,{mode='endpoints'}={}) {
    if(this.current||this.busy)throw Error('Capture already active or closing');
    if(!Object.hasOwn(CAPTURE_LIMITS,mode))throw Error('Invalid capture mode');
    if(mode==='all-tcp'){
      if(filters!==undefined&&(!Array.isArray(filters)||filters.length))throw Error('All TCP mode cannot have endpoint filters');
      filters=[];
    }else filters=captureFilters(filters);
    const limits=Object.fromEntries(Object.entries(CAPTURE_LIMITS[mode]).map(([key,max])=>[key,Math.min(max,this.overrides[key]??max)]));this.busy=true;
    try {
      const id=randomBytes(16).toString('hex'),folder=join(this.root,id);
      await mkdir(folder,{recursive:true,mode:0o700});
      const stream=createWriteStream(join(folder,'traffic.jsonl'),{flags:'wx',mode:0o600,highWaterMark:65536});
      const done=finished(stream);done.catch(()=>{});
      const s={id,folder,stream,done,filters,mode,limits,started:performance.now(),bytes:0,fileBytes:0,records:0,flows:0};
      stream.on('error',()=>{if(this.current===s)void this.stop('io_error');});
      await new Promise((yes,no)=>{stream.once('open',yes);stream.once('error',no);});
      this.current=s;this.busy=false;
      s.timer=setTimeout(()=>void this.stop('time_limit'),s.limits.durationMs);s.timer.unref();
      s.ticker=setInterval(()=>{if(this.current===s)this.emit(this.view(s,'active'));},1000);s.ticker.unref();
      this.append(s,{type:'start',version:1,startedUtc:new Date().toISOString(),filters,mode,limits:s.limits,
        point:'SOCKS application bytes before/after WebRTC; not proof of remote receipt',secrets:true});
      if(this.current===s)this.emit(this.view(s,'active'));
      return id;
    }catch {this.busy=false;this.emit({state:'failed',reason:'io_error',bytes:0,flows:0});throw Error('Cannot start local capture');}
  }
  view(s,state,reason){return {state,id:s.id,mode:s.mode,remainingMs:Math.max(0,Math.ceil(s.limits.durationMs-(performance.now()-s.started))),bytes:s.bytes,flows:s.flows,...(reason?{reason}:{})};}
  append(s,record) {
    if(this.current!==s)return false;
    if(performance.now()-s.started>=s.limits.durationMs){void this.stop('time_limit');return false;}
    const line=JSON.stringify(record)+'\n',size=Buffer.byteLength(line);
    let reason;
    if(s.records>=s.limits.maxRecords)reason='record_limit';
    else if(s.fileBytes+size+2048>s.limits.maxFileBytes)reason='file_limit';
    else if(s.stream.writableLength+size>s.limits.maxPendingBytes)reason='queue_limit';
    if(reason){void this.stop(reason);return false;}
    try{s.stream.write(line);s.records++;s.fileBytes+=size;return true;}
    catch{void this.stop('io_error');return false;}
  }
  open(host,port) {
    const s=this.current;if(!s)return null;
    let normalized;try{normalized=hostName(host);}catch{return null;}
    if(s.mode==='endpoints'&&!s.filters.some(f=>f.host===normalized&&f.port===port))return null;
    if(s.flows>=s.limits.maxFlows){void this.stop('flow_limit');return null;}
    const flow=s.flows+1,offsets={c2s:0,s2c:0};let closed=false;
    if(!this.append(s,{type:'open',flow,host:normalized,port,ms:performance.now()-s.started}))return null;
    s.flows=flow;
    return {
      record:(direction,data)=>{
        if(closed||this.current!==s)return;
        if(!Buffer.isBuffer(data)||!Object.hasOwn(offsets,direction)){void this.stop('observer_error');return;}
        if(s.bytes+data.length>s.limits.maxBytes){void this.stop('byte_limit');return;}
        if(this.append(s,{type:'data',flow,direction,offset:offsets[direction],ms:performance.now()-s.started,length:data.length,data:data.toString('base64')})){
          offsets[direction]+=data.length;s.bytes+=data.length;
        }
      },
      close:()=>{if(!closed){closed=true;this.append(s,{type:'close',flow,ms:performance.now()-s.started,...offsets});}}
    };
  }
  async stop(reason='manual') {
    const s=this.current;if(!s)return this.closing;
    this.current=null;this.busy=true;clearTimeout(s.timer);clearInterval(s.ticker);
    this.emit(this.view(s,'stopping',reason));
    this.closing=(async()=>{
      const end={type:'end',reason,bytes:s.bytes,flows:s.flows,records:s.records,ms:performance.now()-s.started};
      let failed=reason==='io_error';
      try{s.stream.end(JSON.stringify(end)+'\n');await s.done;}catch{failed=true;}
      try{await writeFile(join(s.folder,'summary.json'),JSON.stringify({...end,version:1,id:s.id,mode:s.mode,complete:!failed&&reason==='manual',
        note:'Raw private capture; incomplete streams possible at stop. No automatic decryption.'},null,2)+'\n',{flag:'wx',mode:0o600});}catch{failed=true;}
      this.busy=false;this.emit(this.view(s,failed?'failed':'stopped',failed?'io_error':reason));
    })();
    return this.closing;
  }
}
