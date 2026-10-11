import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdir,rm,writeFile,utimes} from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

test('product signaling: more than 30 rooms, isolation, expiry cleanup and bounded quota',{timeout:30000},async t=>{
  const base=path.resolve('../.test-data'),folder=path.join(base,'signals-'+randomBytes(8).toString('hex'));
  assert.ok(folder.startsWith(base+path.sep));await mkdir(folder,{recursive:true});
  const socket=net.createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));const port=socket.address().port;await new Promise(r=>socket.close(r));
  const php=spawn(process.env.PHONE_EXIT_PHP||'php',['-S','127.0.0.1:'+port,'-t',path.resolve('../server')],{windowsHide:true,stdio:'ignore',env:{...process.env,PHONE_EXIT_SIGNAL_DATA:folder}});
  t.after(async()=>{php.kill();if(php.exitCode===null)await new Promise(r=>php.once('exit',r));assert.ok(folder.startsWith(base+path.sep));await rm(folder,{recursive:true,force:true});});
  const url='http://127.0.0.1:'+port+'/signal.php';
  for(let i=0;i<50;i++){try{await fetch(url);break;}catch{await new Promise(r=>setTimeout(r,50));}}
  const tokens=Array.from({length:40},()=>randomBytes(32).toString('hex'));
  const api=async(token,role='pc',op='poll',message=null,after=0)=>fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,role,op,message,after})});
  for(const token of tokens)assert.equal((await api(token)).status,200);
  assert.equal((await api(tokens[0],'pc','send',{type:'offer',value:'test SDP'})).status,200);
  const answer=await (await api(tokens[0],'phone')).json();assert.equal(answer.messages[0].message.value,'test SDP');
  assert.deepEqual((await (await api(tokens[1],'phone')).json()).messages,[]);
  assert.deepEqual((await (await api(tokens[0],'phone','poll',null,answer.messages[0].id)).json()).messages,[]);
  assert.equal((await api(tokens[0],'phone','send',{type:'offer'})).status,400);
  const old=[];
  for(let i=40;i<512;i++){const token=randomBytes(32).toString('hex'),file=path.join(folder,createHash('sha256').update(token).digest('hex')+'.json');await writeFile(file,JSON.stringify({created:Math.floor(Date.now()/1000),messages:[],seq:0}));old.push(file);}
  assert.equal((await api(randomBytes(32).toString('hex'))).status,429);
  const stale=new Date(Date.now()-901000);for(const file of old)await utimes(file,stale,stale);
  assert.equal((await api(randomBytes(32).toString('hex'))).status,200,'quota must be recomputed after removing stale rooms');
});
