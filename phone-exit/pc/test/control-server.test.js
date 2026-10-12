import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {mkdtemp,mkdir,writeFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {sealControl} from '../src/control-api.js';
test('real PHP broker isolates accounts/devices, bounds queues and never redelivers',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'phone-exit-control-'));await mkdir(join(dir,'catalog'));await mkdir(join(dir,'control'));
  const token=randomBytes(32).toString('hex'),id=randomBytes(16).toString('hex'),other=randomBytes(16).toString('hex');
  const digest=createHash('sha256').update(token).digest('hex');
  await writeFile(join(dir,'catalog',digest+'.json'),JSON.stringify({devices:{[id]:{updated:Date.now()/1000},[other]:{updated:Date.now()/1000}}}));
  const socket=createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));const port=socket.address().port;await new Promise(r=>socket.close(r));
  const child=spawn('php',['-S','127.0.0.1:'+port,'-t',resolve('../server')],{env:{...process.env,PHONE_EXIT_CATALOG_DATA:join(dir,'catalog'),PHONE_EXIT_CONTROL_DATA:join(dir,'control')},stdio:'ignore'});
  t.after(async()=>{child.kill();if(child.exitCode===null)await new Promise(r=>child.once('exit',r));await rm(dir,{recursive:true,force:true});await new Promise(r=>setTimeout(r,200));});
  const url='http://127.0.0.1:'+port+'/control.php';let started=false;
  for(let i=0;i<40;i++){try{await fetch(url);started=true;break;}catch{await new Promise(r=>setTimeout(r,50));}}assert.ok(started);
  const api=body=>fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token,id,...body})});
  const request=randomBytes(16).toString('hex'),box=sealControl(token,{command:'status'});
  assert.equal((await api({op:'enqueue',request,box})).status,200);
  assert.equal((await (await api({op:'poll',id:other})).json()).job,null);
  assert.equal((await api({op:'poll',token:randomBytes(32).toString('hex')})).status,403);
  assert.equal((await (await api({op:'poll'})).json()).job.request,request);
  assert.equal((await (await api({op:'poll'})).json()).job,null);
  assert.equal((await api({op:'result',request,box})).status,200);
  assert.equal((await (await api({op:'get',request})).json()).status,'done');
  assert.equal((await api({op:'get',id:other,request})).status,404);
  assert.equal((await api({op:'ack',request})).status,200);
  const consumed=await (await api({op:'get',request})).json();assert.equal(consumed.consumed,true);assert.equal(consumed.box,null);
  const storage=join(dir,'control',digest+'.json'),before=await stat(storage);
  await new Promise(r=>setTimeout(r,40));assert.equal((await (await api({op:'poll'})).json()).job,null);await api({op:'get',request});
  assert.equal((await stat(storage)).mtimeMs,before.mtimeMs,'empty poll/get must not rewrite the entire account');
  const helper=join(dir,'lock.php');await writeFile(helper,'<?php $f=fopen($argv[1],"c+");flock($f,LOCK_EX);echo "locked\\n";fflush(STDOUT);fgets(STDIN);fclose($f);');
  const holder=spawn('php',[helper,storage],{stdio:['pipe','pipe','ignore']});
  try{await new Promise((r,reject)=>{holder.stdout.once('data',r);holder.once('error',reject);});const started=performance.now();assert.equal((await api({op:'get',request})).status,503);assert.ok(performance.now()-started<1000,'lock contention must not occupy a PHP worker');}
  finally{holder.stdin.end('\n');if(holder.exitCode===null)await new Promise(r=>holder.once('exit',r));}
  // Completed history must not throttle an active bot to 32 requests / 120 seconds.
  for(let i=0;i<40;i++){
    const next=randomBytes(16).toString('hex');assert.equal((await api({op:'enqueue',request:next,box})).status,200);
    assert.equal((await (await api({op:'poll'})).json()).job.request,next);
    assert.equal((await api({op:'result',request:next,box})).status,200);assert.equal((await api({op:'ack',request:next})).status,200);
  }
  for(let i=0;i<4;i++)assert.equal((await api({op:'enqueue',request:randomBytes(16).toString('hex'),box})).status,200);
  assert.equal((await api({op:'enqueue',request:randomBytes(16).toString('hex'),box})).status,429);
  assert.equal((await api({op:'enqueue',request:randomBytes(16).toString('hex'),box:{iv:'bad',data:'bad'}})).status,400);
});
