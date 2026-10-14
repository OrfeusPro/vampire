import {createHash,randomBytes} from 'node:crypto';
import {readFile,writeFile,mkdir,rename,readdir} from 'node:fs/promises';
import path from 'node:path';
import {createBotErrors} from './bot-errors.js';

export function validateBotSettings(value){
  if(!value||value.settingsVersion!==1||!Array.isArray(value.farm_map_spots)||value.farm_map_spots.length>256)throw Error('invalid settings');
  const ids=new Set();const point=p=>{if(!Array.isArray(p)||p.length!==2||p.some(n=>!Number.isFinite(n)||n<0||n>=1))throw Error('invalid point');};
  for(const spot of value.farm_map_spots){if(!spot||typeof spot.id!=='string'||spot.id.length>128||ids.has(spot.id)||typeof spot.map_id!=='string'||spot.map_id.length>128)throw Error('invalid spot');ids.add(spot.id);
    if(spot.teleport_point)point(spot.teleport_point);if(!Array.isArray(spot.map_points)||spot.map_points.length>256)throw Error('invalid points');spot.map_points.forEach(point);
    for(const key of ['enabled','run_after_teleport'])if(key in spot&&typeof spot[key]!=='boolean')throw Error('invalid spot switch');
    if('travel_plan' in spot&&spot.travel_plan!==null){const plan=spot.travel_plan;if(typeof plan!=='object'||Array.isArray(plan))throw Error('invalid travel plan');
      if('enabled' in plan&&typeof plan.enabled!=='boolean')throw Error('invalid travel switch');
      if(plan.enabled!==false){if(plan.type==='tyriosa_floor_chain'){if(!['1F','2F','3F'].includes(plan.target_floor))throw Error('invalid target floor');}
        else if(plan.type==='deadmans_district_chain'){if(!['1','2','3'].includes(String(plan.target_district)))throw Error('invalid target district');}
        else throw Error('unknown travel plan');}
    }
  }
  if(value.active_farm_map_spot_id&&!ids.has(value.active_farm_map_spot_id))throw Error('unknown active spot');
  for(const key of ['farm_enabled','recovery_enabled','auto_dismantle_enabled','autostart_enabled'])if(typeof value[key]!=='boolean')throw Error('invalid switch');
  if('confirm_rare_dismantle_enabled' in value&&typeof value.confirm_rare_dismantle_enabled!=='boolean')throw Error('invalid switch');
  if(value.editor_request&&(!['point','capture'].includes(value.editor_request.kind)||typeof value.editor_request.map_id!=='string'||value.editor_request.map_id.length>128))throw Error('invalid editor request');
  if(value.current_location_templates){
    if(typeof value.current_location_templates!=='object'||Array.isArray(value.current_location_templates)||Object.keys(value.current_location_templates).length>256)throw Error('invalid location templates');
    for(const [map,data]of Object.entries(value.current_location_templates)){
      if(!/^[a-z0-9_-]{1,128}$/.test(map)||typeof data!=='string'||data.length>87384)throw Error('invalid location template');
      const png=Buffer.from(data,'base64');if(png.length<24||png.length>65536||!png.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'))||png.readUInt32BE(16)<1||png.readUInt32BE(16)>1024||png.readUInt32BE(20)<1||png.readUInt32BE(20)>256)throw Error('invalid location PNG');
    }
  }
  if(Buffer.byteLength(JSON.stringify(value))>1048576)throw Error('large settings');return value;
}
const defaults=()=>({settingsVersion:1,farm_enabled:false,recovery_enabled:false,auto_dismantle_enabled:false,autostart_enabled:false,farm_map_spots:[],active_farm_map_spot_id:null});
export function createBotApi({enqueue,get,devices,profilePath,root=path.resolve(import.meta.dirname,'../../bots')}){
  const jobs=new Map(),busy=new Set();let profiles={},load,closed=false;
  const errors=createBotErrors(profilePath),recording=new Set(),recordRetry=new Map(),recorded=new Set();let errorInit;
  async function collectErrors(device){
    if(!profilePath||closed||(!device.control?.bot?.botId&&!profiles[device.id]?.botId)||recording.has(device.id)||busy.has(device.id)||Date.now()<(recordRetry.get(device.id)||0))return;
    if(!device.control?.botDiagnostics&&(!device.control?.bot?.error||device.control?.bot?.status!=='error'))return;
    recording.add(device.id);const phone={...device,profile:profiles[device.id]};
    try{
      if(!errorInit)errorInit=errors.list().then(result=>{for(const r of result.records){if(r.errorKey)recorded.add(r.errorKey);if(r.phoneRecordId)recorded.add(r.phoneRecordId);}});await errorInit;
      if(device.control?.botDiagnostics){
        const result=await command(device.id,{op:'diagnosticsList'});let count=0;
        for(const record of result.records||[]){if(recorded.has(record.id)||count>=8)continue;const full=await command(device.id,{op:'diagnosticsGet',id:record.id});await errors.save(phone,{...full,phoneRecordId:record.id},full.image);recorded.add(record.id);count++;}
        recordRetry.set(device.id,Date.now()+60000);
      }else{
        const report=device.control.bot,key=createHash('sha256').update(device.id+':'+report.error+':'+report.step+':'+report.updatedAt).digest('hex');
        if(!recorded.has(key)){let image=null;try{const job=await enqueue(device.id,'screenshot',{format:'jpg',quality:80}),end=Date.now()+30000;while(!closed&&Date.now()<end){const response=await get(device.id,job.id);if(response.status==='done'){if(response.result?.ok)image=response.result.result?.image;break;}if(['expired','unknown'].includes(response.status))break;await new Promise(r=>setTimeout(r,250));}}catch{}
          await errors.save(phone,{...report,errorKey:key,screenshotUnavailable:image?undefined:'capture_unavailable'},image,'snapshot_after_pause');recorded.add(key);}
        recordRetry.set(device.id,Date.now()+30000);
      }
    }catch{recordRetry.set(device.id,Date.now()+30000);}finally{recording.delete(device.id);while(recorded.size>10000)recorded.delete(recorded.values().next().value);}
  }
  const file=profilePath&&path.join(profilePath,'bot-profiles.json');
  async function init(){if(!load)load=(async()=>{if(file)try{const raw=await readFile(file,'utf8');if(raw.length>16000000)throw Error();profiles=JSON.parse(raw);if(!profiles||typeof profiles!=='object'||Array.isArray(profiles))profiles={};let recovered=false;for(const p of Object.values(profiles))if(p.editorBackup){p.settings=p.editorBackup;delete p.editorBackup;p.revision=(p.revision||0)+1;p.pending=true;p.editorRecovery=true;recovered=true;}if(recovered)await save();}catch(e){if(e.code!=='ENOENT')throw Error('bot profiles unavailable');}})();return load;}
  let saving=Promise.resolve();function save(){if(!file)return Promise.resolve();const text=JSON.stringify(profiles);saving=saving.catch(()=>{}).then(async()=>{await mkdir(profilePath,{recursive:true});const tmp=file+'.'+randomBytes(6).toString('hex')+'.tmp';await writeFile(tmp,text,{mode:0o600});await rename(tmp,file);});return saving;}
  const phone=id=>{const p=devices().find(p=>p.id===id);if(!p)throw Object.assign(Error('unknown phone'),{status:404});return p;};
  async function command(id,args){const p=phone(id);if(p.control?.botApi!==1)throw Error('update phone to bot engine APK');const job=await enqueue(id,'bot',args),end=Date.now()+(args.op==='install'?150000:65000);
    while(!closed&&Date.now()<end){const result=await get(id,job.id);if(result.status==='done'){if(!result.result?.ok)throw Error(result.result?.error||'bot operation failed');return result.result.result;}
      if(['expired','unknown'].includes(result.status))throw Error('bot operation outcome unknown; refresh status');await new Promise(r=>setTimeout(r,250));}throw Error('bot operation timeout');
  }
  async function sync(id){const p=profiles[id];if(!p?.pending)return;if(p.editorRecovery){await command(id,{op:'pause'});delete p.editorRecovery;await save();}const state=await command(id,{op:'status'});if(state.botId!==p.botId)throw Error('assign bot before settings');
    const bytes=Buffer.from(JSON.stringify(p.settings)),sha256=createHash('sha256').update(bytes).digest('hex');
    if(state.receivedRevision===p.revision&&state.settingsSha256===sha256&&state.settingsStatus!=='receiving'){p.pending=false;delete p.lastError;await save();return;}
    if(state.receivedRevision>=p.revision&&state.settingsStatus!=='receiving'){p.revision=state.receivedRevision+1;await save();}
    await command(id,{op:'settingsBegin',revision:p.revision,size:bytes.length,sha256});
    for(let offset=0;offset<bytes.length;offset+=4096)await command(id,{op:'settingsChunk',revision:p.revision,offset,data:bytes.subarray(offset,offset+4096).toString('base64')});
    await command(id,{op:'settingsCommit',revision:p.revision});p.pending=false;delete p.lastError;await save();
  }
  function launch(id,task){if(busy.has(id))throw Object.assign(Error('phone bot operation busy'),{status:409});if(jobs.size>=256){for(const[k,j]of jobs)if(j.status!=='running')jobs.delete(k);if(jobs.size>=256)throw Object.assign(Error('too many bot jobs'),{status:429});}
    const jobId=randomBytes(16).toString('hex'),job={id:jobId,status:'running',at:Date.now()};jobs.set(jobId,job);busy.add(id);
    Promise.resolve().then(task).then(result=>{job.status='done';job.result=result;},error=>{job.status='failed';job.error=error.message;}).finally(()=>busy.delete(id));return job;
  }
  const retry=new Map();
  const timer=setInterval(()=>{if(closed)return;init().then(()=>{errors.prune().catch(()=>{});for(const device of devices())if(device.online&&device.control?.botApi===1)collectErrors(device);for(const p of devices())if(p.online&&p.control?.botApi===1&&profiles[p.id]?.pending&&!busy.has(p.id)&&Date.now()>=(retry.get(p.id)||0))launch(p.id,async()=>{try{await sync(p.id);retry.delete(p.id);}catch(error){profiles[p.id].lastError=error.message;retry.set(p.id,Date.now()+30000);await save();throw error;}});}).catch(()=>{});for(const[k,j]of jobs)if(j.status!=='running'&&Date.now()-j.at>180000)jobs.delete(k);},5000);timer.unref();
  return {
    async handle(method,url,body){await init();
      if(method==='GET'&&url==='/bot/v1/errors')return errors.list();
      if(method==='GET'&&url==='/bot/v1/catalog'){const bots=[];for(const id of await readdir(root)){if(!/^[a-z][a-z0-9_-]{0,40}$/.test(id))continue;try{bots.push(JSON.parse(await readFile(path.join(root,id,'manifest.json'),'utf8')));}catch{}}return {bots};}
      if(method==='GET'&&url==='/bot/v1/phones')return {phones:devices().map(p=>({...p,profile:profiles[p.id]||null,bot:p.control?.bot||null,botStatusStale:p.controlTransport!=='webrtc'&&!p.online}))};
      const asset=/^\/bot\/v1\/assets\/([a-z][a-z0-9_-]{0,40})\/(index\.json|[a-zA-Z0-9_.-]+\.png)$/.exec(url);
      if(method==='GET'&&asset)return {binary:await readFile(path.join(root,asset[1],'maps',asset[2])),mime:asset[2].endsWith('.json')?'application/json':'image/png'};
      const jobMatch=/^\/bot\/v1\/jobs\/([a-f0-9]{32})$/.exec(url);if(method==='GET'&&jobMatch){const job=jobs.get(jobMatch[1]);if(!job)throw Object.assign(Error('unknown bot job'),{status:404});return job;}
      const match=/^\/bot\/v1\/devices\/([a-f0-9]{32})\/(profile|action|settings|copy|identity)$/.exec(url);if(!match)throw Object.assign(Error('not found'),{status:404});const id=match[1];phone(id);
      if(method==='GET'&&match[2]==='profile')return profiles[id]||{botId:'lordnine',revision:0,settings:defaults(),pending:false};
      if(method!=='POST')throw Object.assign(Error('method not allowed'),{status:405});
      if(match[2]==='identity'){
        if(typeof body.characterName!=='string'||body.characterName.length>80||/[\x00-\x1f]/.test(body.characterName)||!['','VMOS','UgPhone','LDCloud','Другое'].includes(body.provider))throw Error('invalid phone identity');
        const p=profiles[id]||{revision:0,settings:defaults(),pending:false};p.identity={characterName:body.characterName.trim(),provider:body.provider};profiles[id]=p;await save();return {saved:true,identity:p.identity};
      }
      if(match[2]==='settings'){
        if(busy.has(id))throw Object.assign(Error('phone bot operation busy'),{status:409});const settings=validateBotSettings(body.settings),p=profiles[id]||{botId:'lordnine',revision:0};
        p.settings=settings;p.revision=Math.max(p.revision||0,phone(id).control?.bot?.receivedRevision||0)+1;p.pending=true;profiles[id]=p;await save();return {saved:true,revision:p.revision,status:'pending'};
      }
      if(match[2]==='copy'){
        const source=profiles[id];if(!source?.settings)throw Error('source settings missing');if(!Array.isArray(body.targets)||body.targets.length>256||body.targets.some(target=>busy.has(target)))throw Error('invalid or busy targets');body.targets.forEach(phone);
        for(const target of body.targets){profiles[target]={...profiles[target],botId:source.botId,settings:structuredClone(source.settings),revision:Math.max(profiles[target]?.revision||0,phone(target).control?.bot?.receivedRevision||0)+1,pending:true};}await save();return {saved:body.targets.length,status:'pending'};
      }
      if(match[2]==='action')return launch(id,async()=>{
        if(body.op==='update'){
          const before=await command(id,{op:'status'});
          if(!before.botId)throw Error('assign bot before update');
          const catalog=await command(id,{op:'catalog'});
          const versionParts=v=>{if(typeof v!=='string'||!/^\d{1,9}\.\d{1,9}\.\d{1,9}$/.test(v))throw Error('invalid bot release version');return v.split('.').map(Number);};
          const compare=(a,b)=>{const x=versionParts(a),y=versionParts(b);for(let i=0;i<3;i++)if(x[i]!==y[i])return Math.sign(x[i]-y[i]);return 0;};
          const releases=(catalog.bots||[]).map(entry=>JSON.parse(entry.payload)).filter(meta=>meta.id===before.botId&&Number.isInteger(meta.engineVersion)&&meta.engineVersion>=1&&meta.engineVersion<=before.engineVersion&&meta.settingsVersion===1);
          releases.forEach(meta=>versionParts(meta.version));releases.sort((a,b)=>compare(b.version,a.version));
          if(!releases.length)throw Error('no compatible bot release');
          const latest=releases[0].version;
          if(before.version&&compare(latest,before.version)<=0)return {...before,updateResult:'current'};
          // Android verifies signature/hash. Resume only a confirmed install.
          await command(id,{op:'stop'});
          const installed=await command(id,{op:'install',version:latest});
          if(installed.version!==latest)throw Error('bot update not confirmed; inspect status');
          let result=installed;
          if(before.desired==='running'){await sync(id);result=await command(id,{op:'start'});}
          else if(before.desired==='paused')result=await command(id,{op:'pause'});
          return {...result,updateResult:'updated'};
        }
        if(body.op==='assign'){if(typeof body.botId!=='string'||!body.botId.match(/^[a-z][a-z0-9_-]{0,40}$/))throw Error('unknown bot');try{const manifest=JSON.parse(await readFile(path.join(root,body.botId,'manifest.json'),'utf8'));if(manifest.id!==body.botId)throw Error();}catch{throw Error('unknown bot');}const result=await command(id,body);profiles[id]={...(profiles[id]||{}),botId:body.botId,settings:profiles[id]?.botId===body.botId?profiles[id].settings:defaults(),revision:profiles[id]?.revision||0};await save();return result;}
        if(body.op==='editor'){
          if(!['point','capture'].includes(body.kind)||typeof body.mapId!=='string')throw Error('invalid editor operation');
          const index=JSON.parse(await readFile(path.join(root,'lordnine/maps/index.json'),'utf8'));
          if(!index.maps.some(m=>m.id===body.mapId))throw Error('unknown editor map');
          const state=await command(id,{op:'status'});const manifest=JSON.parse(await readFile(path.join(root,'lordnine/manifest.json'),'utf8'));if(state.version!==manifest.version)throw Error('update bot module to '+manifest.version);
          await command(id,{op:'pause'});
          const p=profiles[id];if(!p?.settings)throw Error('settings required');
          const original=structuredClone(p.settings);
          try{
            p.editorBackup=original;p.settings={...original,autostart_enabled:false,editor_request:{kind:body.kind,map_id:body.mapId}};p.revision++;p.pending=true;await save();await sync(id);await command(id,{op:'start'});
            const end=Date.now()+150000;
            while(Date.now()<end){await new Promise(r=>setTimeout(r,1000));const result=await command(id,{op:'status'});
              if(result.desired==='paused'&&result.error)throw Error(result.error);
              if(result.desired!=='running'&&result.appliedRevision!==p.revision)throw Error('editor_cancelled');
              if(result.appliedRevision!==p.revision)continue;
              const point=/^editor_point_(\d+\.\d+)_(\d+\.\d+)$/.exec(result.reason||'');
              if(point)return {point:[Number(point[1]),Number(point[2])],mapId:body.mapId};
              if(result.reason==='editor_capture_ready')return {ready:true,mapId:body.mapId};
              if(result.desired!=='running')throw Error('editor_cancelled');
            }throw Error('editor recognition timeout');
          }finally{try{await command(id,{op:'pause'});}finally{p.settings=original;delete p.editorBackup;p.revision++;p.pending=true;await save();await sync(id);}}
        }
        if(['start','resume'].includes(body.op))await sync(id);
        if(!['status','install','rollback','start','pause','resume','stop'].includes(body.op))throw Error('invalid action');return command(id,body);
      });throw Object.assign(Error('not found'),{status:404});
    },close(){closed=true;clearInterval(timer);}
  };
}
