import { randomBytes, scryptSync, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const LIMIT = 524288, AAD = Buffer.from('phone-exit-account-transfer-v1');
function checkPassword(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw Error('password');
}
export function validateProfile(profile) {
  const a = profile?.account;
  if (profile?.version !== 1 || a?.version !== 1 || !/^[a-f0-9]{64}$/.test(a.feedToken) ||
      typeof a.privateKey !== 'string' || a.privateKey.length > 1024 || typeof a.publicKey !== 'string' || a.publicKey.length > 1024) throw Error('profile');
  const key = createPrivateKey({key:Buffer.from(a.privateKey,'base64'),format:'der',type:'pkcs8'});
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails.namedCurve !== 'prime256v1' ||
      createPublicKey(key).export({format:'der',type:'spki'}).toString('base64') !== a.publicKey) throw Error('profile');
  if (!Array.isArray(a.blocked) || a.blocked.length > 1024 || a.blocked.some(id=>typeof id!=='string'||!/^[a-f0-9]{32}$/.test(id))) throw Error('profile');
  if (!Array.isArray(profile.phones) || profile.phones.length > 256) throw Error('profile');
  const ids = new Set();
  const phones = profile.phones.map(p=>{
    if (typeof p.id!=='string'||!/^[a-f0-9]{32}$/.test(p.id)||typeof p.token!=='string'||!/^[a-f0-9]{64}$/.test(p.token)||
        typeof p.name!=='string'||p.name.length<1||p.name.length>40||ids.has(p.id)) throw Error('profile');
    ids.add(p.id);return {id:p.id,token:p.token,name:p.name};
  });
  return {version:1,account:{version:1,feedToken:a.feedToken,publicKey:a.publicKey,privateKey:a.privateKey,blocked:[...a.blocked]},phones};
}
function derive(password,salt) {return scryptSync(password,salt,32,{N:32768,r:8,p:1,maxmem:67108864});}
export function sealProfile(profile,password) {
  checkPassword(password);const raw=Buffer.from(JSON.stringify(validateProfile(profile)));
  const salt=randomBytes(16),iv=randomBytes(12),key=derive(password,salt);
  try {
    const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(AAD);
    const data=Buffer.concat([cipher.update(raw),cipher.final()]);
    return JSON.stringify({format:'phone-exit-account',version:1,kdf:'scrypt-32768-8-1',salt:salt.toString('base64'),iv:iv.toString('base64'),data:data.toString('base64'),tag:cipher.getAuthTag().toString('base64')});
  } finally {key.fill(0);raw.fill(0);}
}
export function openProfile(archive,password) {
  checkPassword(password);if(typeof archive!=='string'||Buffer.byteLength(archive)>LIMIT) throw Error('archive');
  const box=JSON.parse(archive);
  if(box.format!=='phone-exit-account'||box.version!==1||box.kdf!=='scrypt-32768-8-1') throw Error('archive');
  for(const field of ['salt','iv','data','tag']) if(typeof box[field]!=='string'||! /^[A-Za-z0-9+/]*={0,2}$/.test(box[field])) throw Error('archive');
  const salt=Buffer.from(box.salt,'base64'),iv=Buffer.from(box.iv,'base64'),tag=Buffer.from(box.tag,'base64');
  if(salt.length!==16||iv.length!==12||tag.length!==16) throw Error('archive');
  const key=derive(password,salt);let raw;
  try {const cipher=createDecipheriv('aes-256-gcm',key,iv);cipher.setAAD(AAD);cipher.setAuthTag(tag);
    raw=Buffer.concat([cipher.update(Buffer.from(box.data,'base64')),cipher.final()]);return validateProfile(JSON.parse(raw.toString('utf8')));
  } finally {key.fill(0);raw?.fill(0);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  let input='',size=0;
  process.stdin.setEncoding('utf8');
  process.stdin.on('data',chunk=>{size+=Buffer.byteLength(chunk);if(size>LIMIT*2){process.exitCode=1;process.stdin.destroy();return;}input+=chunk;});
  process.stdin.on('end',()=>{try {const req=JSON.parse(input.replace(/^\uFEFF/,''));
    const result=req.op==='export'?{archive:sealProfile(req.profile,req.password)}:req.op==='import'?{profile:openProfile(req.archive,req.password)}:null;
    if(!result) throw Error('operation');process.stdout.write(JSON.stringify(result));
  } catch {process.stdout.write(JSON.stringify({error:'invalid-transfer'}));process.exitCode=1;}});
}
