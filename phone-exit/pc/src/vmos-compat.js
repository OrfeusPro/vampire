import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
const sha=value=>createHash('sha256').update(value).digest('hex');
const mac=(key,value)=>createHmac('sha256',key).update(value).digest();
const signed='content-type;host;x-content-sha256;x-date';
export function vmosSignature(secret,host,date,raw){
  const scope=date.slice(0,8)+'/armcloud-paas/request';
  const canonical=`host:${host}\nx-date:${date}\ncontent-type:application/json;charset=UTF-8\nsignedHeaders:${signed}\nx-content-sha256:${sha(raw)}`;
  return mac(mac(mac(mac(secret,date.slice(0,8)),'armcloud-paas'),'request'),`HMAC-SHA256\n${date}\n${scope}\n${sha(canonical)}`).toString('hex');
}
export function authenticateVmos(req,raw,secret,now=Date.now()){
  const h=req.headers,d=h['x-date'];if(typeof d!=='string'||!/^\d{8}T\d{6}Z$/.test(d))return false;
  const iso=`${d.slice(0,4)}-${d.slice(4,6)}-${d.slice(6,8)}T${d.slice(9,11)}:${d.slice(11,13)}:${d.slice(13,15)}Z`;
  const at=Date.parse(iso);if(!Number.isFinite(at)||Math.abs(at-now)>45000||h['x-host']!==h.host||h['content-type']!=='application/json;charset=UTF-8'||h['x-content-sha256']!==sha(raw))return false;
  const prefix=`HMAC-SHA256 Credential=phone-exit/${d.slice(0,8)}/armcloud-paas/request, SignedHeaders=${signed}, Signature=`;
  const a=h.authorization||'';if(!a.startsWith(prefix)||!/^[a-f0-9]{64}$/.test(a.slice(prefix.length)))return false;
  return timingSafeEqual(Buffer.from(a.slice(prefix.length)),Buffer.from(vmosSignature(secret,h.host,d,raw)));
}
export class VmosError extends Error {constructor(message,code=1104){super(message);this.code=code;}}
const unsupported=()=>{throw new VmosError('Команда недоступна обычному APK без дополнительных прав',501);};
const pkg='[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+';
export function translateScript(script){
  if(typeof script!=='string'||script.length>8192)throw new VmosError('Некорректная команда');
  const s=script.trim();let m;
  if(s==='wm size')return {command:'deviceInfo',output:'size',emulated:true};
  if((m=new RegExp(`^pm list packages(?: (${pkg}))?$`).exec(s)))return {command:'apps',args:m[1]?{package:m[1]}:{},output:'packages'};
  if(s==='dumpsys window'||s==='dumpsys window | grep -E "mCurrentFocus|mFocusedApp" | tail -20')return {command:'foreground',output:'foreground',emulated:true};
  if((m=/^input tap (\d+) (\d+)$/.exec(s)))return {command:'tap',args:{x:+m[1],y:+m[2]},map:true};
  if((m=/^input swipe (\d+) (\d+) (\d+) (\d+)(?: (\d+))?$/.exec(s)))return {command:'swipe',args:{x1:+m[1],y1:+m[2],x2:+m[3],y2:+m[4],durationMs:m[5]?+m[5]:300},map:true};
  if((m=/^input keyevent (\d+|KEYCODE_(?:HOME|BACK|APP_SWITCH|VOLUME_UP|VOLUME_DOWN|ENTER|DEL))$/.exec(s))){const keys={HOME:3,BACK:4,APP_SWITCH:187,VOLUME_UP:24,VOLUME_DOWN:25,ENTER:66,DEL:67};const key=m[1].startsWith('KEYCODE_')?keys[m[1].slice(8)]:+m[1];if(![3,4,187,24,25,66,67].includes(key))unsupported();return {command:'keyevent',args:{key}};}
  if((m=/^input text (.+)$/.exec(s))){let text=m[1];if(text.startsWith('"')&&text.endsWith('"')||text.startsWith("'")&&text.endsWith("'"))text=text.slice(1,-1);if(/[;|&`$<>\r\n]/.test(text))unsupported();return {command:'inputText',args:{text:text.replace(/%s/g,' ')}};}
  if((m=new RegExp(`^monkey -p (${pkg}) -c android\\.intent\\.category\\.LAUNCHER 1$`).exec(s)))return {command:'launch',args:{package:m[1]}};
  if((m=new RegExp(`^am start -n (${pkg})/([A-Za-z.][A-Za-z0-9_.$]*)$`).exec(s)))return {command:'launch',args:{package:m[1],activity:m[2]}};
  unsupported();
}
export function mapCoordinates(args,info,width,height){
  width=width??(info.width>info.height?1280:720);height=height??(info.width>info.height?720:1280);
  if(!Number.isInteger(width)||width<1||width>8192||!Number.isInteger(height)||height<1||height>8192)throw new VmosError('Некорректные размеры');
  const convert=(value,axis)=>{const size=axis==='x'?width:height,target=axis==='x'?info.frameWidth:info.frameHeight;if(!Number.isFinite(value)||value<0||value>=size)throw new VmosError('Координаты вне экрана');return Math.min(target-1,Math.floor(value*target/size));};
  const out={...args,width:info.frameWidth,height:info.frameHeight};for(const field of ['x','y','x1','y1','x2','y2'])if(field in out)out[field]=convert(out[field],field[0]);
  if(out.strokes)out.strokes=out.strokes.map(s=>({...s,points:s.points.map(p=>({x:convert(p.x,'x'),y:convert(p.y,'y')}))}));
  return out;
}
export function touchPlan(body){
  if((body.pointCount??1)!==1)throw new VmosError('simulateTouch: поддерживается один палец и законченные пути',501);
  if(!Array.isArray(body.positions)||body.positions.length<2||body.positions.length>64)throw new VmosError('Нужны down → move → up');
  const strokes=[];let current,time=0;
  for(const p of body.positions){if(!p||!Number.isFinite(p.x)||!Number.isFinite(p.y)||!Number.isInteger(p.actionType))throw new VmosError('Некорректный touch');
    if(p.touchType||p.keyCode||p.swipe)throw new VmosError('Параметры touch не поддерживаются',501);
    if(p.actionType===0){if(current)throw new VmosError('Повторный down');current={startMs:time,points:[]};}
    if(!current||![0,1,2].includes(p.actionType))throw new VmosError('Незаконченный touch');current.points.push({x:p.x,y:p.y});
    if(p.actionType===1){current.durationMs=Math.max(1,time-current.startMs);strokes.push(current);current=null;}
    const wait=p.nextPositionWaitTime??0;if(!Number.isInteger(wait)||wait<0||wait>5000)throw new VmosError('Некорректная задержка');time+=wait;
    if(time>5000||strokes.length>10)throw new VmosError('Слишком длинный жест');
  }
  if(current||!strokes.length)throw new VmosError('Нужен завершающий up');return {strokes};
}
export function createVmosCompat({directory,enqueue,get,devices,validate=()=>{},waitMs=20000}){
  const jobs=new Map(),previews=new Map();let sequence=Date.now(),localBase;
  const known=id=>{const p=directory.phones.find(p=>p.id===id);if(!p||directory.account.blocked.includes(id))throw new VmosError('Неизвестный телефон',404);return p;};
  const clean=()=>{for(const [id,j]of jobs)if(Date.now()-j.created>120000)jobs.delete(id);for(const[id,p]of previews)if(Date.now()>p.expireAt)previews.delete(id);};
  const cleanupTimer=setInterval(clean,500);cleanupTimer.unref();
  const ids=b=>{const a=b.padCodes??(b.padCode?[b.padCode]:[]);if(!Array.isArray(a)||!a.length||a.length>16||new Set(a).size!==a.length)throw new VmosError('Нужны padCodes');a.forEach(known);return a;};
  const start=async(id,plan)=>{clean();known(id);for(const[k,v]of jobs){if(jobs.size<256)break;if(v.final)jobs.delete(k);}if(jobs.size>=256)throw new VmosError('Слишком много заданий',429);const j={taskId:++sequence,padCode:id,created:Date.now(),plan};jobs.set(j.taskId,j);try{const accepted=await enqueue(id,plan.command,plan.args??{});j.request=accepted.id;j.transport=accepted.transport;}catch(e){jobs.delete(j.taskId);throw e;}return j;};
  const output=(j,r)=>{switch(j.plan.output){case 'size':return `Physical size: ${r.width>r.height?'1280x720':'720x1280'}\n`;case 'packages':return r.apps.map(a=>'package:'+a.package).join('\n')+'\n';case 'foreground':return `mCurrentFocus=Window{PhoneExit u0 ${r.package}/unknown}\n`;default:return '';}};
  const refresh=async j=>{known(j.padCode);if(j.final)return j.final;const v=await get(j.padCode,j.request);let taskStatus=v.status==='delivered'?2:1,taskResult=null,errorMsg=null;
    if(v.status==='done'){taskStatus=v.result.ok?3:-1;taskResult=v.result.ok?'success':'failed';errorMsg=v.result.ok?output(j,v.result.result):v.result.error;}
    else if(v.status==='expired'||v.status==='unknown'){taskStatus=-4;taskResult='timeout';errorMsg='Исход неизвестен; повтор действий не выполнен';}
    const r={taskId:j.taskId,padCode:j.padCode,taskStatus,taskResult,errorMsg,endTime:taskStatus<0||taskStatus===3?Date.now():null,vmStatus:directory.states.get(j.padCode)?.received>Date.now()-45000?1:0,emulated:!!j.plan.emulated};
    if(taskStatus<0||taskStatus===3){j.value=v.result?.result;j.final=r;if(taskStatus===3&&j.plan.command==='screenshot')preview(j,localBase);}return r;};
  const wait=async j=>{const end=Date.now()+waitMs;while(true){const r=await refresh(j);if(r.taskStatus<0||r.taskStatus===3)return r;if(Date.now()>=end)throw Object.assign(new VmosError('Истекло ожидание; запросите padTaskDetail',110012),{taskId:j.taskId});await new Promise(r=>setTimeout(r,j.transport==='webrtc'?10:350));}};
  const info=async id=>{const j=await start(id,{command:'deviceInfo'}),r=await wait(j);if(r.taskStatus!==3)throw new VmosError(r.errorMsg,409);return j.value;};
  const preview=(j,base)=>{if(j.final?.taskStatus!==3)return null;if(j.preview){if(previews.has(j.preview))return previews.get(j.preview).entry;throw new VmosError('Кадр истёк; запросите новый screenshot',404);}
    const r=j.value;if(!r?.image)throw new VmosError('Кадр отсутствует',502);const bytes=Buffer.from(r.image,'base64');if(bytes.length>1400000)throw new VmosError('Кадр слишком большой',413);
    clean();let total=Array.from(previews.values()).reduce((n,p)=>n+p.bytes.length,0);while(previews.size>=8||total+bytes.length>8*1024*1024){const key=previews.keys().next().value;total-=previews.get(key).bytes.length;previews.delete(key);}
    const key=randomBytes(32).toString('hex'),expireAt=Date.now()+30000,entry={padCode:j.padCode,url:base+'/vmos-preview/'+key,expireAt,success:true,reason:null};previews.set(key,{bytes,expireAt,padCode:j.padCode,mime:r.format==='png'?'image/png':'image/jpeg',entry});j.preview=key;delete r.image;return entry;};
  return {
    close(){clearInterval(cleanupTimer);jobs.clear();previews.clear();},
    preview(path){clean();const m=/^\/vmos-preview\/([a-f0-9]{64})$/.exec(path);if(!m)return null;const p=previews.get(m[1]);if(!p)return null;try{known(p.padCode);}catch{previews.delete(m[1]);return null;}return p;},
    async handle(method,b,base){localBase=base;clean();if(!b||typeof b!=='object'||Array.isArray(b))throw new VmosError('Некорректное тело');
      if(['userPadList','padInfo','padDetail'].includes(method)){let list=devices().map(p=>({...p,padCode:p.id,padName:p.name,status:p.online?1:0}));if(b.padCode){known(b.padCode);list=list.filter(p=>p.id===b.padCode);}return list;}
      if(['padTaskDetail','executeScriptInfo','screenshotInfo'].includes(method)){const a=b.taskIds??(b.taskId?[b.taskId]:[]);if(!Array.isArray(a)||!a.length||a.length>32)throw new VmosError('Нужны taskIds');return Promise.all(a.map(async id=>{const j=jobs.get(id);if(!j)throw new VmosError('Неизвестное задание',404);const r=await refresh(j);return method==='screenshotInfo'?{...r,...preview(j,base)}:r;}));}
      const supported=['padProperties','listInstalledApp','getListInstalledApp','startApp','inputText','syncCmd','asyncCmd','getLongGenerateUrl','generatePreview','screenshot','simulateClick','simulateSwipe','simulateLongPress','simulateTouch'];if(!supported.includes(method))unsupported();
      const selected=ids(b);
      // Validate every target and payload before any side-effect in a multi-device call.
      const plans=await Promise.all(selected.map(async id=>{let plan;
        if(method==='padProperties')plan={command:'deviceInfo'};
        else if(['listInstalledApp','getListInstalledApp'].includes(method))plan={command:'apps',args:{offset:b.offset??0,limit:b.limit??256,...(b.pkgName?{package:b.pkgName}:{})}};
        else if(method==='startApp')plan={command:'launch',args:{package:b.pkgName}};
        else if(method==='inputText')plan={command:'inputText',args:{text:b.text}};
        else if(['syncCmd','asyncCmd'].includes(method))plan=translateScript(b.scriptContent);
        else if(['getLongGenerateUrl','generatePreview','screenshot'].includes(method)){const args={format:b.format??'png',quality:b.quality===undefined?80:Number(b.quality)};if(b.width!==undefined||b.height!==undefined){args.width=Number(b.width);args.height=Number(b.height);}plan={command:'screenshot',args};}
        else{let args,command;
          if(method==='simulateClick'||method==='simulateLongPress'){command=method==='simulateClick'?'tap':'longPress';args={x:b.x,y:b.y,...(command==='longPress'?{durationMs:b.holdMs??600}:{})};}
          else if(method==='simulateTouch'){command='gesture';args=touchPlan(b);}
          else{command='swipe';const w=b.width??1080,h=b.height??1920,directions={LEFT_TO_RIGHT:[.2,.5,.8,.5],RIGHT_TO_LEFT:[.8,.5,.2,.5],TOP_TO_BOTTOM:[.5,.2,.5,.8],BOTTOM_TO_TOP:[.5,.8,.5,.2]};const d=directions[b.direction];if(!d)throw new VmosError('Некорректное направление');args={x1:b.startX??w*d[0],y1:b.startY??h*d[1],x2:b.endX??w*d[2],y2:b.endY??h*d[3],durationMs:500};}
          plan={command,args,map:true,container:[b.width??(method==='simulateSwipe'?1080:720),b.height??(method==='simulateSwipe'?1920:1280)]};
        }
        if(plan.map)plan.args=mapCoordinates(plan.args,await info(id),...(plan.container??[]));return {id,plan};}));
      for(const {id,plan} of plans){validate(plan.command,plan.args??{});const state=directory.states.get(id);if(!devices().some(p=>p.id===id&&p.online))throw new VmosError('Телефон offline',409);if(!state.control?.api||state.control.api<2&&['deviceInfo','apps','foreground','keyevent','inputText','longPress','gesture','screenshot'].includes(plan.command))throw new VmosError('Сначала обновите APK до 0.6.0',409);}
      const out=[];for(const {id,plan} of plans){try{const j=await start(id,plan);
        if(['syncCmd','padProperties','listInstalledApp','getListInstalledApp','getLongGenerateUrl','generatePreview'].includes(method)){const r=await wait(j);
          if(method==='syncCmd'&&r.taskStatus===3&&plan.output==='packages'&&j.value.nextOffset!=null)throw new VmosError('Список превышает страницу: используйте listInstalledApp с offset/limit',501);
          if(method==='syncCmd')out.push(r);else if(r.taskStatus!==3)throw new VmosError(r.errorMsg,409);else if(['getLongGenerateUrl','generatePreview'].includes(method))out.push(preview(j,base));else out.push({padCode:id,...j.value});}
        else out.push({padCode:id,taskId:j.taskId,vmStatus:1,taskStatus:1});
        }catch(e){if(selected.length===1)throw e;out.push({padCode:id,taskId:e.taskId??null,taskStatus:e.code===110012?-4:-1,taskResult:'failed',errorMsg:e.message,code:e.code??e.status??502});}}
      return out;
    }
  };
}
