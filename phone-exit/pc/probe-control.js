import {createInterface} from 'node:readline';
import {Directory} from './src/directory.js';
import {CONTROL,sealControl,openControl} from './src/control-api.js';
import {catalogKey} from './src/catalog.js';
import {randomBytes} from 'node:crypto';
import {mkdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
let raw='';for await(const line of lines)raw+=line;
const account=JSON.parse(raw.replace(/^\uFEFF/,''));const directory=new Directory(()=>{});directory.setAccount(account);directory.setPhones([]);
const delay=ms=>new Promise(r=>setTimeout(r,ms));let phone;
for(let i=0;i<20;i++){await directory.discoverCatalog();phone=directory.phones.find(p=>p.name.includes(process.argv[2]||'V2061')&&directory.states.get(p.id)?.control?.api>=1);if(phone)break;await delay(2000);}
if(!phone)throw Error('Updated phone not available');
const api=async body=>{const response=await fetch(CONTROL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token:catalogKey(account.feedToken),id:phone.id,...body}),signal:AbortSignal.timeout(10000)});if(!response.ok)throw Error('HTTP '+response.status);return response.json();};
const command=async(cmd,args={})=>{
  const request=randomBytes(16).toString('hex');await api({op:'enqueue',request,box:sealControl(phone.token,{id:phone.id,request,at:Date.now(),command:cmd,args})});
  for(let i=0;i<55;i++){const value=await api({op:'get',request});if(value.status==='done'){const result=openControl(phone.token,value.box);if(result.id!==phone.id||result.request!==request)throw Error('Wrong result');return result;}if(value.status==='expired')throw Error('Command expired');await delay(2000);}throw Error('Command timeout');
};
const status=await command('status');if(!status.ok)throw Error('Status command failed');
console.log('PASS: real phone HTTP status, APK '+directory.states.get(phone.id).versionName+', SDK '+status.result.androidSdk+', processRoot='+status.result.processRoot+', suPresent='+status.result.suPresent);
if(process.argv.includes('--network')){
  const info=await command('deviceInfo');if(!info.ok)throw Error('Device info: '+info.error);
  console.log('NETWORK interface names/counts only: '+JSON.stringify(info.result.networkDiagnostics??{available:false}));
}
if(process.argv.includes('--reconnect')){
  const {DirectControl}=await import('./src/control-direct.js');
  const native=(await import('node-datachannel')).default;
  try{
    for(let i=0;i<10;i++){
      const direct=new DirectControl({id:phone.id,bootstrap:async sdp=>{
        console.log('PC reconnect offer structure: '+JSON.stringify({
          attempt:i+1,candidates:(sdp.match(/^a=candidate:/gm)||[]).length,
          rejectedSections:(sdp.match(/^m=\S+ 0 /gm)||[]).length,
          mediaSections:(sdp.match(/^m=/gm)||[]).length,
          iceCredentials:(sdp.match(/^a=ice-ufrag:/gm)||[]).length,
          fingerprints:(sdp.match(/^a=fingerprint:/gm)||[]).length
        }));
        const answer=await command('connectControl',{sdp});
        if(!answer.ok){console.log('Android bootstrap diagnostics: '+JSON.stringify(answer.diagnostics??{available:false}));throw Error('Remote reconnect bootstrap: '+answer.error);}
        return answer.result;
      }});
      try{
        await direct.connect();
        const job=direct.send('deviceInfo',{}),deadline=Date.now()+10000;
        let result;
        while(Date.now()<deadline){
          const value=direct.get(job.id);
          if(value.status==='done'){result=value.result;break;}
          if(value.status==='expired')throw Error('Remote reconnect command expired');
          await delay(20);
        }
        if(!result?.ok)throw Error('Remote reconnect deviceInfo: '+(result?.error||'timeout'));
        if(i===0&&result.result.controlDiagnostics)console.log('Android connected lifecycle diagnostics: '+JSON.stringify(result.result.controlDiagnostics));
        console.log('PASS remote native reconnect '+(i+1)+', APK '+result.result.versionName);
      }catch(error){console.log('Reconnect failure phase/state: '+JSON.stringify({attempt:i+1,phase:direct.phase,state:direct.peer?.connectionState,candidates:direct.candidates}));throw error;}
      finally{direct.close();}
      await delay(500);
    }
  }finally{native.cleanup();}
}
if(process.argv.includes('--ice')){
  const {RTCPeerConnection}=await import('./src/native-peer.js');
  const native=(await import('node-datachannel')).default;
  const peer=new RTCPeerConnection({iceServers:[{urls:['stun:stun.l.google.com:19302','stun:stun.cloudflare.com:3478']}]});
  try{
    peer.createDataChannel('phone-exit-automation-v1');
    await peer.setLocalDescription(await peer.createOffer());
    const answer=await command('connectControl',{sdp:peer.localDescription.sdp});
    if(!answer.ok)throw Error('Remote ICE answer: '+answer.error);
    const sdp=answer.result.sdp;
    console.log('ICE answer structure only: '+JSON.stringify({
      candidates:(sdp.match(/^a=candidate:/gm)||[]).length,
      media:(sdp.match(/^m=.*$/gm)||[]).map(line=>{const parts=line.trim().split(/\s+/);return {kind:parts[0].slice(2),rejected:parts[1]==='0',protocol:parts[2]};}),
      iceCredentials:(sdp.match(/^a=ice-ufrag:/gm)||[]).length,
      fingerprints:(sdp.match(/^a=fingerprint:/gm)||[]).length,
      endOfCandidates:(sdp.match(/^a=end-of-candidates/gm)||[]).length
    }));
    await peer.setRemoteDescription(answer.result);
    for(let i=0;i<50&&!['connected','failed','closed'].includes(peer.connectionState);i++)await delay(200);
    console.log('ICE diagnostic state: '+peer.connectionState);
  }finally{await peer.close();native.cleanup();}
}
const screen=await command('screenshot');if(status.result.enabled===false&&screen.error!=='control_disabled')throw Error('Consent gate failed');
if(status.result.enabled&&screen.ok){
  const folder=new URL('../.test-data/',import.meta.url);await mkdir(folder,{recursive:true});
  const path=new URL('control-preview.jpg',folder);await writeFile(path,Buffer.from(screen.result.image,'base64'));
  console.log('PASS: real HTTPS screenshot '+screen.result.width+'x'+screen.result.height+', '+fileURLToPath(path));
}else console.log(status.result.enabled?'Screenshot result: '+screen.error:'PASS: screen command rejected while control disabled');
const actionArg=process.argv.find(a=>a.startsWith('--command='));
if(actionArg){const cmd=actionArg.slice('--command='.length),argsArg=process.argv.find(a=>a.startsWith('--args='));const result=await command(cmd,argsArg?JSON.parse(argsArg.slice('--args='.length)):{});if(!result.ok)throw Error('Input command failed: '+result.error);console.log('PASS: real HTTPS command '+cmd);}
if(process.argv.includes('--update')){
  const update=await command('installUpdate');if(!update.ok)throw Error('Remote update command failed');
  console.log('Remote update result: '+update.result.status+', available '+update.result.availableVersion+', silentInstall='+update.result.silentInstall);
  if(update.result.status!=='ready_for_confirmation')throw Error('Update was not prepared');
}
(await import('node-datachannel')).default.cleanup();
