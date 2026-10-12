import {createCipheriv,createDecipheriv,createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {createServer} from 'node:http';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {DirectControl} from './control-direct.js';
import {Directory} from './directory.js';
import {catalogKey} from './catalog.js';
import {authenticateVmos,createVmosCompat} from './vmos-compat.js';
export const CONTROL='https://demochko.com/hosting-webrtc-probe/phone-exit-api/control.php';
const label=Buffer.from('phone-exit-control-v1');
function key(token){if(!/^[a-f0-9]{64}$/.test(token))throw Error('invalid key');return createHash('sha256').update(label).update(Buffer.from(token,'hex')).digest();}
export function sealControl(token,value){const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',key(token),iv);c.setAAD(label);return {iv:iv.toString('base64'),data:Buffer.concat([c.update(JSON.stringify(value)),c.final(),c.getAuthTag()]).toString('base64')};}
export function openControl(token,box){if(!box||typeof box.data!=='string'||box.data.length>2800000||typeof box.iv!=='string'||box.iv.length!==16)throw Error('invalid frame');const iv=Buffer.from(box.iv,'base64'),data=Buffer.from(box.data,'base64');if(iv.length!==12||data.length<16)throw Error('invalid frame');const c=createDecipheriv('aes-256-gcm',key(token),iv);c.setAAD(label);c.setAuthTag(data.subarray(-16));return JSON.parse(Buffer.concat([c.update(data.subarray(0,-16)),c.final()]).toString('utf8'));}
export function validateCommand(command,args={}){
  if(!args||typeof args!=='object'||Array.isArray(args))throw Error('invalid arguments');
  if(!['status','screenshot','tap','swipe','back','home','launch','checkUpdate','installUpdate','deviceInfo','apps','foreground','keyevent','inputText','longPress','gesture','connectControl'].includes(command))throw Error('unsupported command');
  if(command==='connectControl'&&(typeof args.sdp!=='string'||args.sdp.length>11000||!args.sdp.startsWith('v=0')))throw Error('invalid offer');
  if(command==='launch'&&(typeof args.package!=='string'||!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(args.package)||args.package.length>200))throw Error('invalid package');
  if(command==='launch'&&args.activity!==undefined&&(typeof args.activity!=='string'||args.activity.length>250||!/^\.?[A-Za-z][A-Za-z0-9_.$]*$/.test(args.activity)))throw Error('invalid activity');
  if(command==='inputText'&&(typeof args.text!=='string'||args.text.length>4096))throw Error('invalid text');
  if(command==='keyevent'&&![3,4,187,24,25,66,67].includes(args.key))throw Error('unsupported key');
  if(command==='apps'){
    if(args.package!==undefined&&(typeof args.package!=='string'||!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(args.package)))throw Error('invalid package');
    for(const [field,min,max]of [['offset',0,8192],['limit',1,256]])if(args[field]!==undefined&&(!Number.isInteger(args[field])||args[field]<min||args[field]>max))throw Error('invalid pagination');
  }
  if(command==='screenshot'){
    if(args.format!==undefined&&!['jpg','png'].includes(args.format)||args.quality!==undefined&&(!Number.isInteger(args.quality)||args.quality<0||args.quality>100))throw Error('invalid screenshot');
    if((args.width===undefined)!==(args.height===undefined))throw Error('invalid screenshot geometry');
    for(const field of ['width','height'])if(args[field]!==undefined&&(!Number.isInteger(args[field])||args[field]<1||args[field]>1280))throw Error('invalid screenshot geometry');
  }
  if(['tap','swipe','longPress','gesture'].includes(command)){
    for(const field of ['width','height'])if(!Number.isInteger(args[field])||args[field]<1||args[field]>1280)throw Error('invalid geometry');
    const point=p=>{for(const field of ['x','y'])if(!Number.isInteger(p[field])||p[field]<0||p[field]>=(field==='x'?args.width:args.height))throw Error('invalid coordinate');};
    if(command==='gesture'){
      if(!Array.isArray(args.strokes)||args.strokes.length<1||args.strokes.length>10)throw Error('invalid gesture');
      for(const s of args.strokes){if(!Number.isInteger(s.startMs)||s.startMs<0||!Number.isInteger(s.durationMs)||s.durationMs<1||s.startMs+s.durationMs>5000||!Array.isArray(s.points)||s.points.length<1||s.points.length>64)throw Error('invalid stroke');s.points.forEach(point);}
    }else if(command==='swipe'){point({x:args.x1,y:args.y1});point({x:args.x2,y:args.y2});}else point(args);
    if(command==='swipe'&&(!Number.isInteger(args.durationMs)||args.durationMs<100||args.durationMs>3000))throw Error('invalid duration');
    if(command==='longPress'&&(!Number.isInteger(args.durationMs)||args.durationMs<100||args.durationMs>5000))throw Error('invalid duration');
  }
  if(Buffer.byteLength(JSON.stringify({command,args}),'utf8')>11000)throw Error('command frame too large');
  return {command,args};
}
export function applyBlocked(directory,blocked){
  if(!directory?.account||!Array.isArray(blocked)||blocked.length>1024||!blocked.every(id=>typeof id==='string'&&/^[a-f0-9]{32}$/.test(id)))throw Error('invalid blocked ids');
  directory.account.blocked=[...blocked];directory.phones=directory.phones.filter(p=>!blocked.includes(p.id));
}
export function createControlServer({directory,secret,request=fetch,vmosWaitMs=20000}){
  if(!/^[0-9a-f]{64}$/.test(secret))throw Error('invalid local key');
  let active=0;
  const results=new Map();let resultBytes=0;
  const cleanResults=()=>{for(const[k,v]of results)if(v.until<Date.now()){resultBytes-=v.size;results.delete(k);}};
  const resultTimer=setInterval(cleanResults,500);resultTimer.unref();
  const api=async(body)=>{
    const response=await request(CONTROL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token:catalogKey(directory.account.feedToken),...body}),signal:AbortSignal.timeout(10000)});
    const raw=await response.text();if(raw.length>3000000)throw Error('large response');
    if(!response.ok){const e=Error('remote unavailable');e.status=response.status;throw e;}return JSON.parse(raw);
  };
  const phoneFor=id=>{const p=directory.phones.find(p=>p.id===id);if(!p||directory.account.blocked.includes(id))throw Object.assign(Error('unknown device'),{status:404});return p;};
  const devices=()=>{let phones=[];const original=directory.emit;try{directory.emit=e=>{if(e.event==='phones')phones=e.phones;};directory.publish();}finally{directory.emit=original;}return phones.map(p=>{const d=peers.get(p.id)?.peer;return d&&!d.closed&&d.channel?.readyState==='open'?{...p,online:true,controlTransport:'webrtc',controlRttMs:d.rttMs??null}:d?{...p,controlTransport:d.phase??'closed',controlCandidates:d.candidates,controlSdpStructure:d.sdpStructure,controlError:d.failure&&/^[a-z_ ]{1,80}$/.test(d.failure)?d.failure:undefined}:p;});};
  const enqueueHttp=async(id,command,args={})=>{
    const phone=phoneFor(id),state=directory.states.get(id);if(!state||Date.now()-state.received>=45000)throw Object.assign(Error('device offline'),{status:409});
    if(!state.control?.api||state.control.api<2&&(['deviceInfo','apps','foreground','keyevent','inputText','longPress','gesture'].includes(command)||command==='screenshot'&&Object.keys(args).length>0))throw Object.assign(Error('update APK first'),{status:409});
    validateCommand(command,args);const requestId=randomBytes(16).toString('hex');await api({op:'enqueue',id,request:requestId,box:sealControl(phone.token,{id,request:requestId,at:Date.now(),command,args})});return {id:requestId,status:'queued'};
  };
  const get=async(id,requestId)=>{
    const phone=phoneFor(id),cacheKey=id+':'+requestId;cleanResults();const cached=results.get(cacheKey);if(cached)return cached.value;
    const value=await api({op:'get',id,request:requestId});phoneFor(id);
    if(value.box){const result=openControl(phone.token,value.box);if(result.id!==id||result.request!==requestId||!Number.isSafeInteger(result.at)||Math.abs(result.at-Date.now())>180000)throw Error('invalid result');value.result=result;delete value.box;
      const size=Buffer.byteLength(JSON.stringify(value));while(results.size>=256||resultBytes+size>8388608){const first=results.keys().next().value;if(first===undefined)break;resultBytes-=results.get(first).size;results.delete(first);}
      const previous=results.get(cacheKey);if(previous)resultBytes-=previous.size;
      results.set(cacheKey,{value,size,until:Date.now()+(result.result?.image?30000:120000)});resultBytes+=size;
      // Acknowledgement only after authenticated decryption and a bounded local cache.
      try{await api({op:'ack',id,request:requestId});}catch{/* Retrieval remains successful; broker TTL still bounds the frame. */}
    }else if(value.status==='done'&&value.consumed){value.status='expired';value.error='result cache expired; action not repeated';}
    return value;
  };
  const peers=new Map(),directJobs=new Map();
  const directTimer=setInterval(()=>{
    for(const[k,j]of directJobs)if(j.until<Date.now())directJobs.delete(k);
    for(const[id,p]of peers)if(directory.account.blocked.includes(id)||!directory.phones.some(v=>v.id===id)){p.peer?.close();peers.delete(id);}
  },500);directTimer.unref();
  const enqueue=async(id,command,args={})=>{
    phoneFor(id);validateCommand(command,args);
    const state=directory.states.get(id);
    const linked=peers.get(id)?.peer;
    if((!state||Date.now()-state.received>=45000)&&(!linked||linked.closed||linked.channel?.readyState!=='open'))throw Object.assign(Error('device offline'),{status:409});
    if(state.control?.api<3||!state.control?.directControl||['checkUpdate','installUpdate'].includes(command))return enqueueHttp(id,command,args);
    if(!state.control.enabled)throw Object.assign(Error('control disabled'),{status:409});
    let entry=peers.get(id);
    if(!entry||entry.peer?.closed){
      if(!entry&&peers.size>=32)throw Object.assign(Error('too many connections'),{status:429});
      entry={};peers.set(id,entry);
      const direct=entry.peer=new DirectControl({id,bootstrap:async sdp=>{
        const job=await enqueueHttp(id,'connectControl',{sdp}),end=Date.now()+45000;
        while(Date.now()<end){const r=await get(id,job.id);if(r.status==='done'){
          if(!r.result.ok)throw Error(r.result.error);return r.result.result;
        }if(['unknown','expired'].includes(r.status))throw Error('direct offer expired');await new Promise(r=>setTimeout(r,350));}
        throw Error('direct offer timeout');
      }});
      entry.ready=direct.connect();entry.ready.catch(()=>{});
    }
    await entry.ready;phoneFor(id);
    for(const[k,j]of directJobs){if(directJobs.size<1024)break;
      if(['done','expired'].includes(j.peer.get(k.slice(k.lastIndexOf(':')+1)).status))directJobs.delete(k);
    }
    if(directJobs.size>=1024)throw Object.assign(Error('too many tasks'),{status:429});
    const job=entry.peer.send(command,args);directJobs.set(id+':'+job.id,{peer:entry.peer,until:Date.now()+120000});return job;
  };
  const getAny=async(id,request)=>{phoneFor(id);const j=directJobs.get(id+':'+request);return j?j.peer.get(request):get(id,request);};
  const vmos=createVmosCompat({directory,enqueue,get:getAny,devices,validate:validateCommand,waitMs:vmosWaitMs});
  const server=createServer(async(req,res)=>{
    const send=(status,body)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(body));};
    if(req.headers.origin)return send(403,{error:'browser origins forbidden'});
    if(req.method==='GET'&&req.url.startsWith('/vmos-preview/')){const p=vmos.preview(req.url);if(!p)return send(404,{error:'preview expired'});res.writeHead(200,{'Content-Type':p.mime,'Content-Length':p.bytes.length,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(p.bytes);return;}
    const isVmos=/^\/vcpcloud\/api\/padApi\/[A-Za-z]+$/.test(req.url);
    let raw='';if(isVmos&&req.method==='POST'){try{for await(const chunk of req){raw+=chunk;if(raw.length>16384)return send(413,{error:'large request'});}}catch{return send(400,{error:'invalid request'});}}
    const got=Buffer.from(req.headers.authorization||''),wanted=Buffer.from('Bearer '+secret),bearer=got.length===wanted.length&&timingSafeEqual(got,wanted);
    if(!bearer&&!(isVmos&&req.method==='POST'&&authenticateVmos(req,raw,secret)))return send(401,{error:'unauthorized'});
    if(active>=8)return send(429,{error:'busy'});active++;
    try{
      if(isVmos){if(req.method!=='POST')return send(405,{error:'method not allowed'});try{const data=await vmos.handle(req.url.split('/').at(-1),JSON.parse(raw||'{}'),'http://127.0.0.1:'+res.socket.localPort);return send(200,{code:200,msg:'success',ts:Date.now(),data});}catch(e){return send(200,{code:(Number.isInteger(e.code)&&e.code>=100?e.code:e.status??1104),msg:e.message,ts:Date.now(),data:e.taskId?[{taskId:e.taskId}]:[],supported:e.code===501?false:undefined});}}
      if(req.method==='GET'&&req.url==='/v1/devices'){
        return send(200,{devices:devices()});
      }
      const match=/^\/v1\/devices\/([a-f0-9]{32})\/commands(?:\/([a-f0-9]{32}))?$/.exec(req.url);
      if(!match)return send(404,{error:'not found'});
      const phone=directory.phones.find(p=>p.id===match[1]);
      if(!phone||directory.account.blocked.includes(phone.id))return send(404,{error:'unknown device'});
      if(req.method==='POST'&&!match[2]){
        let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>16384)return send(413,{error:'large request'});}
        let input;try{input=JSON.parse(raw);if(input.command==='connectControl')throw Error();validateCommand(input.command,input.args);}catch{return send(400,{error:'invalid command or arguments'});}
        return send(202,await enqueue(phone.id,input.command,input.args));
      }
      if(req.method==='GET'&&match[2]){
        return send(200,await getAny(phone.id,match[2]));
      }
      send(405,{error:'method not allowed'});
    }catch(e){send([404,409,429].includes(e.status)?e.status:502,{error:'phone service unavailable'});}finally{active--;}
  });
  server.once('close',()=>{vmos.close();clearInterval(resultTimer);clearInterval(directTimer);for(const p of peers.values())p.peer?.close();directJobs.clear();results.clear();});return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const lines=createInterface({input:process.stdin,crlfDelay:Infinity});let server,timer,directory;
  lines.once('line',line=>{
    try{const config=JSON.parse(line.replace(/^\uFEFF/,''));directory=new Directory(()=>{});directory.setAccount(config.account);directory.setPhones(config.phones);server=createControlServer({directory,secret:config.secret});server.requestTimeout=15000;server.headersTimeout=10000;server.listen(17842,'127.0.0.1',()=>process.stdout.write('HTTP API: 127.0.0.1:17842\n'));server.on('error',()=>{process.stderr.write('API port unavailable\n');process.exit(1);});directory.poll();timer=setInterval(()=>directory.poll(),6000);}catch{process.stderr.write('API profile unavailable\n');process.exit(1);}
  });
  lines.on('line',line=>{try{const c=JSON.parse(line.replace(/^\uFEFF/,''));if(c.op!=='blocked')return;applyBlocked(directory,c.blocked);}catch{process.stderr.write('API profile update rejected\n');process.exit(1);}});
  lines.on('close',()=>{clearInterval(timer);server?.close();process.exit(0);});
}
