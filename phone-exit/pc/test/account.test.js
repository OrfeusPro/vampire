import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync,createPublicKey,diffieHellman,createHash,createCipheriv,randomBytes } from 'node:crypto';
import { createAccount,openRegistration,feedKey } from '../src/account.js';
import { Directory,BUCKET_MS } from '../src/directory.js';

function seal(account,data) {
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const publicKey=createPublicKey({key:Buffer.from(account.publicKey,'base64'),format:'der',type:'spki'});
  const key=createHash('sha256').update(diffieHellman({privateKey:pair.privateKey,publicKey})).digest();
  const iv=randomBytes(12), cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from('phone-exit-registration-v1'));
  const encrypted=Buffer.concat([cipher.update(JSON.stringify(data)),cipher.final(),cipher.getAuthTag()]);
  return {ephemeral:pair.publicKey.export({type:'spki',format:'der'}).toString('base64'),iv:iv.toString('base64'),data:encrypted.toString('base64')};
}
test('personal discovery enrolls phones without preknown keys; wrong account, tamper, replay and blocked device are rejected',async()=>{
  const account=createAccount(), wrong=createAccount(), now=Date.now(), emitted=[];
  const phone={id:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),name:'Новый телефон',at:now,country:'UA',busy:false};
  const second={...phone,id:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),name:'Второй',country:'PL'};
  const box=seal(account,phone); assert.deepEqual(openRegistration(account,box),phone);
  assert.throws(()=>openRegistration(wrong,box));
  const tampered=Buffer.from(box.data,'base64'); tampered[5]^=1;
  assert.throws(()=>openRegistration(account,{...box,data:tampered.toString('base64')}));
  let registrations=[box,seal(account,second),seal(wrong,{...phone,id:'a'.repeat(32)}),seal(account,{...phone,id:'b'.repeat(32),at:now-46000})];
  const request=async(url,options)=>{
    const body=JSON.parse(options.body);
    const feed=body.token===feedKey(account.feedToken,Math.floor(now/BUCKET_MS));
    return {ok:true,text:async()=>JSON.stringify({messages:feed?registrations.map((box,i)=>({id:i+1,message:{type:'candidate',value:{directory:2,type:'register',box}}})):[]})};
  };
  const directory=new Directory(event=>emitted.push(structuredClone(event)),request,()=>now);
  directory.setPhones([]); directory.setAccount(account); await directory.poll();
  assert.equal(directory.phones.length,2);
  assert.deepEqual(emitted.at(-1).phones.map(p=>[p.country,p.online]),[['UA',true],['PL',true]]);
  assert.ok(emitted.some(e=>e.event==='save')); assert.equal(JSON.stringify(emitted.at(-1)).includes(phone.token),false);
  directory.remove(phone.id); await directory.poll(); assert.equal(directory.phones.length,1);
  assert.ok(emitted.some(e=>e.event==='saveAccount'&&e.account.blocked.includes(phone.id)));
  registrations=[seal(account,{...second,token:'f'.repeat(64),at:now+1})];
  await directory.poll(); assert.equal(directory.phones[0].token,second.token);
});
