import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createBotApi,validateBotSettings} from '../src/bot-api.js';
const id='1'.repeat(32),id2='2'.repeat(32);
const settings=()=>({settingsVersion:1,farm_enabled:true,recovery_enabled:true,auto_dismantle_enabled:true,autostart_enabled:false,
  farm_map_spots:[{id:'a',map_id:'map',map_points:[[.2,.3]],teleport_point:null}],active_farm_map_spot_id:'a'});

test('phone identity stays on PC and copying settings preserves recipient identity',async()=>{
  const api=createBotApi({devices:()=>[{id},{id:id2}],enqueue:()=>{throw Error('identity must not command phone');},get:()=>{}});
  try{
    await api.handle('POST',`/bot/v1/devices/${id}/identity`,{characterName:'Orfeus',provider:'UgPhone'});
    await api.handle('POST',`/bot/v1/devices/${id2}/identity`,{characterName:'Zimaraf',provider:'VMOS'});
    await api.handle('POST',`/bot/v1/devices/${id}/settings`,{settings:settings()});
    await api.handle('POST',`/bot/v1/devices/${id}/copy`,{targets:[id2]});
    const profile=await api.handle('GET',`/bot/v1/devices/${id2}/profile`);
    assert.deepEqual(profile.identity,{characterName:'Zimaraf',provider:'VMOS'});
    await assert.rejects(api.handle('POST',`/bot/v1/devices/${id}/identity`,{characterName:'bad\nname',provider:'VMOS'}));
  }finally{api.close();}
});

test('editor receives a fresh phone result, restores settings and leaves bot paused',async()=>{
  const moduleVersion=JSON.parse(await readFile(new URL('../../bots/lordnine/manifest.json',import.meta.url),'utf8')).version;
  const frames=[],done=new Map();let revision=0,desired='stopped',upload=[],value;
  const api=createBotApi({devices:()=>[{id,online:true,control:{botApi:1}}],enqueue:async(phone,command,args)=>{
    frames.push(args);const jobId=String(frames.length);
    if(args.op==='settingsBegin')upload=[];
    if(args.op==='settingsChunk')upload.push(Buffer.from(args.data,'base64'));
    if(args.op==='settingsCommit'){revision=args.revision;value=JSON.parse(Buffer.concat(upload));}
    if(args.op==='pause')desired='paused';if(args.op==='start')desired='running';
    const result={botId:'lordnine',version:moduleVersion,receivedRevision:revision,appliedRevision:revision,desired,
      reason:value?.editor_request?'editor_point_0.60000000_0.57000000':null};
    done.set(jobId,{status:'done',result:{ok:true,result}});return {id:jobId};
  },get:async(phone,job)=>done.get(job)});
  try{
    const original=settings();await api.handle('POST',`/bot/v1/devices/${id}/settings`,{settings:original});
    const job=await api.handle('POST',`/bot/v1/devices/${id}/action`,{op:'editor',kind:'point',mapId:'tab1_row1_dien_port'});
    for(let i=0;i<200&&job.status==='running';i++)await new Promise(r=>setTimeout(r,10));
    assert.equal(job.status,'done');assert.deepEqual(job.result.point,[.6,.57]);
    assert.deepEqual((await api.handle('GET',`/bot/v1/devices/${id}/profile`)).settings,original);
    assert.equal(desired,'paused');assert.equal(frames.filter(x=>x.op==='start').length,1);
  }finally{api.close();}
});
test('bot settings validate coordinates, revisions and switches',()=>{
  assert.equal(validateBotSettings(settings()).settingsVersion,1);
  assert.equal(validateBotSettings({...settings(),confirm_rare_dismantle_enabled:true}).confirm_rare_dismantle_enabled,true);
  assert.throws(()=>validateBotSettings({...settings(),confirm_rare_dismantle_enabled:'true'}));
  assert.throws(()=>validateBotSettings({...settings(),active_farm_map_spot_id:'missing'}));
  assert.throws(()=>validateBotSettings({...settings(),farm_map_spots:[{id:'a',map_id:'map',map_points:[[NaN,.2]]}]}));
  assert.throws(()=>validateBotSettings({...settings(),current_location_templates:{'../outside':'abc'}}));
  assert.throws(()=>validateBotSettings({...settings(),current_location_templates:{map:'not-a-png'}}));
});
test('travel plans reject unknown routes and out-of-range floors before sending',()=>{
  const value=settings(),spot=value.farm_map_spots[0];
  spot.travel_plan={enabled:true,type:'tyriosa_floor_chain',target_floor:'3F'};
  assert.equal(validateBotSettings(value),value);
  spot.travel_plan.target_floor='4F';assert.throws(()=>validateBotSettings(value));
  spot.travel_plan={enabled:true,type:'deadmans_district_chain',target_district:'2'};assert.equal(validateBotSettings(value),value);
  spot.travel_plan.target_district='4';assert.throws(()=>validateBotSettings(value));
  spot.travel_plan={enabled:false};assert.equal(validateBotSettings(value),value);
  spot.travel_plan=null;assert.equal(validateBotSettings(value),value);
  spot.enabled='true';assert.throws(()=>validateBotSettings(value));
});
test('settings persist while phone offline, copy independently and restore after gateway restart',async()=>{
  const profilePath=await mkdtemp(path.join(os.tmpdir(),'phone-exit-bot-'));
  const devices=()=>[{id,online:false},{id:id2,online:false}];let api=createBotApi({profilePath,devices,enqueue:()=>{throw Error('offline');},get:()=>{}});
  try{await api.handle('POST',`/bot/v1/devices/${id}/settings`,{settings:settings()});await api.handle('POST',`/bot/v1/devices/${id}/copy`,{targets:[id2]});api.close();api=createBotApi({profilePath,devices});
    const p=await api.handle('GET',`/bot/v1/devices/${id2}/profile`);assert.equal(p.pending,true);assert.equal(p.settings.active_farm_map_spot_id,'a');assert.equal(p.revision,1);
    const changed=settings();changed.farm_enabled=false;await api.handle('POST',`/bot/v1/devices/${id}/settings`,{settings:changed});assert.equal((await api.handle('GET',`/bot/v1/devices/${id2}/profile`)).settings.farm_enabled,true);
    assert.ok((await readFile(path.join(profilePath,'bot-profiles.json'),'utf8')).includes('farm_map_spots'));
  }finally{api.close();await rm(profilePath,{recursive:true,force:true});}
});

test('gateway restart restores interrupted editor profile and requires pause before sync',async()=>{
  const profilePath=await mkdtemp(path.join(os.tmpdir(),'phone-exit-editor-'));
  const original=settings();await writeFile(path.join(profilePath,'bot-profiles.json'),JSON.stringify({[id]:{botId:'lordnine',revision:4,settings:{...original,editor_request:{kind:'point',map_id:'map'}},editorBackup:original}}));
  const api=createBotApi({profilePath,devices:()=>[{id,online:false}],enqueue:()=>{throw Error('offline');}});
  try{const p=await api.handle('GET',`/bot/v1/devices/${id}/profile`);assert.deepEqual(p.settings,original);assert.equal(p.editorRecovery,true);assert.equal(p.revision,5);assert.equal(p.pending,true);assert.equal(p.editorBackup,undefined);}finally{api.close();await rm(profilePath,{recursive:true,force:true});}
});
test('start waits for chunk hash commit; failed action is never replayed',async()=>{
  const frames=[],done=new Map();let upload=[],revision=0;
  const api=createBotApi({devices:()=>[{id,online:true,control:{botApi:1}}],enqueue:async(phone,command,args)=>{
    frames.push(args);assert.equal(command,'bot');const jobId=String(frames.length);
    if(args.op==='settingsChunk')upload.push(Buffer.from(args.data,'base64'));
    if(args.op==='settingsCommit'){assert.equal(createHash('sha256').update(Buffer.concat(upload)).digest('hex'),frames.find(x=>x.op==='settingsBegin').sha256);revision=args.revision;}
    done.set(jobId,{status:'done',result:{ok:args.op!=='start',error:'game_not_foreground',result:{botId:'lordnine',receivedRevision:revision}}});return {id:jobId};
  },get:async(phone,job)=>done.get(job)});
  try{await api.handle('POST',`/bot/v1/devices/${id}/settings`,{settings:settings()});const job=await api.handle('POST',`/bot/v1/devices/${id}/action`,{op:'start'});
    for(let i=0;i<30&&job.status==='running';i++)await new Promise(r=>setTimeout(r,10));assert.equal(job.status,'failed');assert.equal(frames.filter(x=>x.op==='start').length,1);assert.ok(frames.findIndex(x=>x.op==='settingsCommit')<frames.findIndex(x=>x.op==='start'));
  }finally{api.close();}
});
