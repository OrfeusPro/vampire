// Independent disposable account; never touches the user's personal profile.
import {generateKeyPairSync,createPublicKey,diffieHellman,createHash,createCipheriv,randomBytes,createDecipheriv} from 'node:crypto';
import assert from 'node:assert/strict';
import {createAccount} from './src/account.js';
import {CATALOG,catalogKey,sealRequest} from './src/catalog.js';
import {Directory} from './src/directory.js';
const account=createAccount(),token=catalogKey(account.feedToken);
function seal(phone){const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),remote=createPublicKey({key:Buffer.from(account.publicKey,'base64'),format:'der',type:'spki'});
  const key=createHash('sha256').update(diffieHellman({privateKey:pair.privateKey,publicKey:remote})).digest(),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from('phone-exit-registration-v1'));return {ephemeral:pair.publicKey.export({type:'spki',format:'der'}).toString('base64'),iv:iv.toString('base64'),data:Buffer.concat([cipher.update(JSON.stringify(phone)),cipher.final(),cipher.getAuthTag()]).toString('base64')};}
async function api(op,extra={}){const response=await fetch(CATALOG,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token,op,...extra}),signal:AbortSignal.timeout(15000)});assert.equal(response.status,200,'Catalog HTTP '+response.status);return response.json();}
const phones=Array.from({length:40},(_,i)=>({id:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),name:'Synthetic probe '+i,at:Date.now(),country:i%2?'UA':'PL',busy:false}));
for(const phone of phones)await api('pulse',{id:phone.id,box:seal(phone)});
const response=await api('list');assert.equal(response.devices.length,40);
const directory=new Directory(()=>{},(url,options)=>url===CATALOG?fetch(url,options):Promise.resolve({ok:true,text:async()=>'{"messages":[]}'}));directory.setAccount(account);directory.setPhones([]);await directory.poll();
assert.equal(directory.phones.length,40);assert.equal([...directory.states.values()].filter(p=>Date.now()-p.received<45000).length,40);
const pairing={version:1,signal:'https://demochko.com/hosting-webrtc-probe/signal.php',token:randomBytes(32).toString('hex')};await directory.connect(phones[0].id,pairing);
const pulse=await api('pulse',{id:phones[0].id,box:seal({...phones[0],at:Date.now()})});assert.ok(pulse.request);
const label=Buffer.from('phone-exit-connect-v1'),key=createHash('sha256').update(label).update(Buffer.from(phones[0].token,'hex')).digest(),data=Buffer.from(pulse.request.data,'base64');
const cipher=createDecipheriv('aes-256-gcm',key,Buffer.from(pulse.request.iv,'base64'));cipher.setAAD(label);cipher.setAuthTag(data.subarray(-16));
assert.deepEqual(JSON.parse(Buffer.concat([cipher.update(data.subarray(0,-16)),cipher.final()]).toString()).pairing,pairing);
console.log('PASS: deployed HTTPS catalog, 40 encrypted synthetic devices auto-discovered, encrypted connect delivered; personal profile untouched');
