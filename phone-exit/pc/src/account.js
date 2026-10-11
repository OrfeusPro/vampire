import { generateKeyPairSync, randomBytes, createHmac, createPrivateKey, createPublicKey,
  diffieHellman, createHash, createDecipheriv } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export function createAccount() {
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  return {version:1,feedToken:randomBytes(32).toString('hex'),
    publicKey:pair.publicKey.export({type:'spki',format:'der'}).toString('base64'),
    privateKey:pair.privateKey.export({type:'pkcs8',format:'der'}).toString('base64'),blocked:[]};
}
export function feedKey(token,bucket) {
  return createHmac('sha256',Buffer.from(token,'hex')).update(`phone-exit-registration-v1:${bucket}`).digest('hex');
}
export function openRegistration(account,box) {
  if(!box||typeof box.ephemeral!=='string'||box.ephemeral.length>256||typeof box.iv!=='string'||box.iv.length>32||typeof box.data!=='string'||box.data.length>4096) throw Error('invalid registration');
  const publicKey=createPublicKey({key:Buffer.from(box.ephemeral,'base64'),format:'der',type:'spki'});
  if(publicKey.asymmetricKeyType!=='ec'||publicKey.asymmetricKeyDetails.namedCurve!=='prime256v1') throw Error('invalid curve');
  const privateKey=createPrivateKey({key:Buffer.from(account.privateKey,'base64'),format:'der',type:'pkcs8'});
  const key=createHash('sha256').update(diffieHellman({privateKey,publicKey})).digest();
  const iv=Buffer.from(box.iv,'base64'), data=Buffer.from(box.data,'base64');
  if(iv.length!==12||data.length<16) throw Error('invalid ciphertext');
  const cipher=createDecipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from('phone-exit-registration-v1')); cipher.setAuthTag(data.subarray(-16));
  return JSON.parse(Buffer.concat([cipher.update(data.subarray(0,-16)),cipher.final()]).toString('utf8'));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) process.stdout.write(JSON.stringify(createAccount()));
