import {randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {createServer} from 'node:http';
import {fileURLToPath} from 'node:url';
import {runBrowserProbe} from '../src/browser-probe.js';
import {signal} from '../../diagnostics/browser/shared.js';

const directory=resolve(process.argv.slice(2).find(v=>!v.startsWith('--'))??fileURLToPath(new URL('../../.tools/browser-direct-session/',import.meta.url)));mkdirSync(directory,{recursive:true});
const token=randomBytes(32).toString('hex');
const page='https://demochko.com/hosting-webrtc-probe/phone-exit-browser-test/';
const url=page+'#'+token;
writeFileSync(join(directory,'link.txt'),url+'\n');
writeFileSync(join(directory,'session.json'),JSON.stringify({pid:process.pid,createdAt:Date.now(),expiresAt:Date.now()+600000}));
console.log('Private pairing link saved locally; waiting up to 10 minutes. No account keys used.');
// Optional local UI test: keep the secret out of browser automation arguments/logs.
let redirect;
if(process.argv.includes('--qa-redirect')){
  redirect=createServer((req,res)=>{
    if(req.method!=='GET'||req.url!=='/'){res.writeHead(404).end();return;}
    res.writeHead(302,{'Location':url,'Cache-Control':'no-store','Referrer-Policy':'no-referrer'}).end();redirect.close();
  });
  await new Promise(r=>redirect.listen(0,'127.0.0.1',r));console.log('Local QA redirect: http://127.0.0.1:'+redirect.address().port+'/');
}
const result=await runBrowserProbe({api:(body,abort)=>signal(new URL('../signal.php',page).href,token,'pc',body,abort),onPhase:phase=>console.log(phase)});
redirect?.close();
writeFileSync(join(directory,'result.json'),JSON.stringify({at:new Date().toISOString(),...result},null,2));console.log(JSON.stringify(result));
setTimeout(()=>process.exit(result.result==='connected'?0:1),1000);
