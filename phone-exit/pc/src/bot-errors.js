import {mkdir,readFile,writeFile,readdir,stat,rm,rename} from 'node:fs/promises';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

export const ERROR_TTL=12*60*60*1000,ERROR_CLEANUP=3*60*60*1000;
export function createBotErrors(profilePath){
  const directory=profilePath&&path.join(profilePath,'bot-errors');let nextCleanup=0;
  async function prune(force=false,now=Date.now()){
    if(!directory||!force&&now<nextCleanup)return;nextCleanup=now+ERROR_CLEANUP;
    await mkdir(directory,{recursive:true});const records=[];
    for(const entry of await readdir(directory,{withFileTypes:true})){
      if(!entry.isDirectory()||!/^\d{13}-[a-f0-9]{16}(?:\.tmp)?$/.test(entry.name))continue;
      const folder=path.join(directory,entry.name),at=Number(entry.name.slice(0,13));
      if(entry.name.endsWith('.tmp')){if(now-at>300000)await rm(folder,{recursive:true,force:true});continue;}
      if(now-at>ERROR_TTL){await rm(folder,{recursive:true,force:true});continue;}
      let size=0;for(const item of await readdir(folder))if(['report.json','screen.jpg'].includes(item))size+=(await stat(path.join(folder,item))).size;
      records.push({folder,at,size});
    }
    records.sort((a,b)=>b.at-a.at);let bytes=0;
    for(let i=0;i<records.length;i++){bytes+=records[i].size;if(i>=100||bytes>64*1024*1024)await rm(records[i].folder,{recursive:true,force:true});}
  }
  async function save(phone,report,image=null,source='phone_error_frame'){
    if(!directory)return;
    const safe={savedAt:Date.now(),source,phone:phone.name,country:phone.country,character:phone.profile?.identity?.characterName||null};
    for(const key of ['botId','version','step','error','reason','activePoint','appliedRevision','updatedAt','capturedAt','frameCapturedAt','screenshotUnavailable','phoneRecordId','errorKey'])if(report[key]!==undefined)safe[key]=report[key];
    const bytes=image?Buffer.from(image,'base64'):null;
    if(bytes&&(bytes.length>1048576||bytes[0]!==255||bytes[1]!==216))throw Error('invalid diagnostic image');
    await mkdir(directory,{recursive:true});const name=String(Date.now())+'-'+randomBytes(8).toString('hex'),temp=path.join(directory,name+'.tmp');await mkdir(temp);
    try{if(bytes)await writeFile(path.join(temp,'screen.jpg'),bytes);await writeFile(path.join(temp,'report.json'),JSON.stringify(safe,null,2));await rename(temp,path.join(directory,name));}finally{await rm(temp,{recursive:true,force:true});}
    await prune(true);return name;
  }
  async function list(){await prune();if(!directory)return {directory:null,records:[]};const records=[];for(const name of await readdir(directory)){if(!/^\d{13}-[a-f0-9]{16}$/.test(name))continue;try{records.push({id:name,...JSON.parse(await readFile(path.join(directory,name,'report.json'),'utf8'))});}catch{}}
    return {directory,retentionHours:12,cleanupHours:3,records:records.sort((a,b)=>b.savedAt-a.savedAt)};
  }
  return {directory,save,prune,list};
}
