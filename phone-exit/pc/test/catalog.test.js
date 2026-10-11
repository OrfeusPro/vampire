import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import {mkdir,readFile,readdir,rm} from 'node:fs/promises';
import {generateKeyPairSync,createPublicKey,diffieHellman,createHash,createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {createAccount} from '../src/account.js';
import {Directory,PRODUCT_SIGNAL} from '../src/directory.js';
import {CATALOG,catalogKey} from '../src/catalog.js';

function seal(account,value){
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const remote=createPublicKey({key:Buffer.from(account.publicKey,'base64'),format:'der',type:'spki'});
  const key=createHash('sha256').update(diffieHellman({privateKey:pair.privateKey,publicKey:remote})).digest();
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from('phone-exit-registration-v1'));
  const data=Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final(),cipher.getAuthTag()]);
  return {ephemeral:pair.publicKey.export({type:'spki',format:'der'}).toString('base64'),iv:iv.toString('base64'),data:data.toString('base64')};
}
function open(token,box){
  const label=Buffer.from('phone-exit-connect-v1'),key=createHash('sha256').update(label).update(Buffer.from(token,'hex')).digest();
  const data=Buffer.from(box.data,'base64'),cipher=createDecipheriv('aes-256-gcm',key,Buffer.from(box.iv,'base64'));
  cipher.setAAD(label);cipher.setAuthTag(data.subarray(-16));return JSON.parse(Buffer.concat([cipher.update(data.subarray(0,-16)),cipher.final()]).toString());
}
test('real PHP catalog: 40 automatic phones, bounded latest state, encrypted connect, isolation, stale and blocked devices',{timeout:30000},async t=>{
  const base=path.resolve('../.test-data'),folder=path.resolve(base,'catalog-'+randomBytes(8).toString('hex'));
  assert.ok(folder.startsWith(base+path.sep));await mkdir(folder,{recursive:true});
  const socket=net.createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));const port=socket.address().port;await new Promise(r=>socket.close(r));
  const php=spawn(process.env.PHONE_EXIT_PHP||'php',['-S','127.0.0.1:'+port,'-t',path.resolve('../server')],{windowsHide:true,stdio:'ignore',env:{...process.env,PHONE_EXIT_CATALOG_DATA:folder}});
  t.after(async()=>{php.kill();if(php.exitCode===null)await new Promise(r=>php.once('exit',r));assert.ok(folder.startsWith(base+path.sep));await rm(folder,{recursive:true,force:true});});
  let started=false;for(let i=0;i<50;i++){try{await fetch('http://127.0.0.1:'+port+'/directory.php');started=true;break;}catch{await new Promise(r=>setTimeout(r,50));}}assert.ok(started);
  const url='http://127.0.0.1:'+port+'/directory.php';
  const account=createAccount(),token=catalogKey(account.feedToken),now=Date.now();
  const api=async(op,extra={},key=token)=>{const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token:key,op,...extra})});assert.equal(response.status,200);return response.json();};
  const phones=Array.from({length:40},(_,i)=>({id:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),name:'Test device '+i,at:now,country:i%2?'UA':'PL',busy:false,signal:PRODUCT_SIGNAL}));
  const boxes=phones.map(phone=>seal(account,phone));
  for(let i=0;i<phones.length;i++)await api('pulse',{id:phones[i].id,box:boxes[i]});
  for(let i=0;i<110;i++)await api('pulse',{id:phones[0].id,box:boxes[0]});
  assert.equal((await api('list')).devices.length,40);
  assert.equal((await api('list',{},catalogKey(createAccount().feedToken))).devices.length,0);
  let clock=now;const events=[];
  const request=async(url,options)=>url===CATALOG?fetch('http://127.0.0.1:'+port+'/directory.php',options):{ok:true,text:async()=>'{"messages":[]}'};
  const directory=new Directory(event=>events.push(structuredClone(event)),request,()=>clock);
  directory.setAccount(account);directory.setPhones([]);await directory.poll();assert.equal(directory.phones.length,40);assert.ok(events.at(-1).phones.every(p=>p.online));
  assert.ok(events.at(-1).phones.every(p=>p.signal===PRODUCT_SIGNAL));
  const pairing={version:1,signal:PRODUCT_SIGNAL,token:randomBytes(32).toString('hex')};
  await directory.connect(phones[0].id,pairing);
  const reply=await api('pulse',{id:phones[0].id,box:boxes[0]});assert.deepEqual(open(phones[0].token,reply.request).pairing,pairing);assert.throws(()=>open(phones[1].token,reply.request));
  directory.remove(phones[0].id);await directory.poll();assert.equal(directory.phones.length,39);
  clock+=46000;await directory.poll();assert.ok(events.at(-1).phones.every(p=>!p.online));
  const stored=(await Promise.all((await readdir(folder)).map(file=>readFile(path.join(folder,file),'utf8')))).join('');
  assert.ok(!stored.includes(phones[0].token)&&!stored.includes(pairing.token)&&!stored.includes('Test device'));
  const invalid=await fetch(url,{method:'POST',body:JSON.stringify({version:1,token:'weak',op:'list'})});assert.equal(invalid.status,403);
});
