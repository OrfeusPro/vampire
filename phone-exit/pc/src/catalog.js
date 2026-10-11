import {createHmac,createHash,createCipheriv,randomBytes} from 'node:crypto';
export const CATALOG='https://demochko.com/phone-exit/directory.php';
export const MAX_PHONES=256;
export function catalogKey(feedToken){return createHmac('sha256',Buffer.from(feedToken,'hex')).update('phone-exit-catalog-v1').digest('hex');}
export function sealRequest(token,body){
  const label=Buffer.from('phone-exit-connect-v1');
  const key=createHash('sha256').update(label).update(Buffer.from(token,'hex')).digest();
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(label);
  const data=Buffer.concat([cipher.update(JSON.stringify(body)),cipher.final(),cipher.getAuthTag()]);
  return {iv:iv.toString('base64'),data:data.toString('base64')};
}
