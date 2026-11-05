// Explicit, bounded Chromium navigation diagnostics. No HTTP bodies or headers.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';

const args=process.argv.slice(2),option=name=>args[args.indexOf(name)+1];
if(!args.includes('--output'))throw Error('Explicit private output directory required');
const output=path.resolve(option('--output'));
const ports=(args.includes('--ports')?option('--ports'):'17951,17952').split(',').map(Number);
if(ports.length>2||ports.some(p=>![17951,17952].includes(p)))throw Error('Unsupported diagnostic port');
fs.mkdirSync(output,{recursive:true});
const ownerFile=path.join(output,'owner.json'),eventsFile=path.join(output,'navigation.jsonl');
if(fs.existsSync(ownerFile)||fs.existsSync(eventsFile))throw Error('Diagnostic output already exists');
const owner={id:randomUUID(),pid:process.pid,started:new Date().toISOString(),deadline:new Date(Date.now()+600000).toISOString(),ports,scope:'explicit-netmarble-chromium-navigation',bodies:false,headers:false};
fs.writeFileSync(ownerFile,JSON.stringify(owner));
const stream=fs.createWriteStream(eventsFile,{flags:'wx'}),sessions=new Map(),seen=new Set();
let count=0,bytes=0,stopped=false,reason='timeout',busy=false;
const status=()=>fs.writeFileSync(path.join(output,'status.json'),JSON.stringify({id:owner.id,pid:process.pid,running:!stopped,connected:sessions.size,events:count,bytes,reason:stopped?reason:null,updated:new Date().toISOString()}));
function record(event){
 if(stopped||typeof event.url!=='string'||event.url.length>16384)return;
 let url;try{url=new URL(event.url);}catch{return;}
 if(url.protocol!=='https:'||!(url.hostname==='netmarble.com'||url.hostname.endsWith('.netmarble.com')))return;
 const key=event.kind+'|'+event.url+'|'+(event.status||'');if(seen.has(key))return;seen.add(key);
 const line=JSON.stringify({utc:new Date().toISOString(),...event})+'\n';
 if(count>=4096||bytes+Buffer.byteLength(line)>4*1024*1024){reason='limit';stop();return;}
 count++;bytes+=Buffer.byteLength(line);stream.write(line);
}
function attach(target){
 if(!target.webSocketDebuggerUrl||sessions.has(target.id))return;
 const endpoint=new URL(target.webSocketDebuggerUrl);
 if(endpoint.protocol!=='ws:'||!['127.0.0.1','localhost'].includes(endpoint.hostname)||!ports.includes(Number(endpoint.port)))return;
 const socket=new WebSocket(endpoint);sessions.set(target.id,socket);
 record({kind:'target',url:target.url||'',target:target.id});
 socket.addEventListener('open',()=>{
  socket.send(JSON.stringify({id:1,method:'Network.enable',params:{maxPostDataSize:0}}));
  socket.send(JSON.stringify({id:2,method:'Page.enable'}));status();
 });
 socket.addEventListener('message',message=>{
  if(typeof message.data!=='string'||message.data.length>2*1024*1024)return;
  let event;try{event=JSON.parse(message.data);}catch{return;}
  const data=event.params||{};
  if(event.method==='Network.requestWillBeSent')record({kind:'request',url:data.request?.url,method:data.request?.method,target:target.id});
  if(event.method==='Network.responseReceived')record({kind:'response',url:data.response?.url,status:data.response?.status,target:target.id});
  if(event.method==='Page.frameNavigated')record({kind:'navigation',url:data.frame?.url,target:target.id});
 });
 socket.addEventListener('close',()=>{sessions.delete(target.id);status();});
 socket.addEventListener('error',()=>{sessions.delete(target.id);});
}
async function poll(){
 if(busy||stopped)return;busy=true;
 try{
  if(fs.existsSync(path.join(output,'STOP'))){reason='user_stop';stop();return;}
  for(const port of ports){
   try{
    const response=await fetch(`http://127.0.0.1:${port}/json/list`,{signal:AbortSignal.timeout(1000)});
    const raw=await response.text();if(raw.length>1024*1024)continue;
    const targets=JSON.parse(raw);if(!Array.isArray(targets)||targets.length>32)continue;
    for(const target of targets)if(['page','webview','iframe'].includes(target.type))attach(target);
   }catch{}
  }
  status();
 }finally{busy=false;}
}
function stop(){
 if(stopped)return;stopped=true;clearInterval(timer);clearTimeout(deadline);
 for(const socket of sessions.values())socket.close();sessions.clear();status();stream.end();
 setTimeout(()=>process.exit(0),1000).unref();
}
const timer=setInterval(poll,1000),deadline=setTimeout(stop,600000);
process.once('SIGINT',()=>{reason='user_stop';stop();});process.once('SIGTERM',()=>{reason='user_stop';stop();});
stream.on('error',()=>{reason='write_error';stop();});status();await poll();
