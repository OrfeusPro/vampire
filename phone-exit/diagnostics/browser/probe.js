import {LABEL,ipv4Candidate,description,candidate,statsSummary,safeReport,signal} from './shared.js';
const $=id=>document.getElementById(id),input=$('link');
let initial=location.hash.slice(1);history.replaceState(null,'',location.pathname);if(/^[a-f0-9]{64}$/.test(initial))input.placeholder='Ссылка принята · нажми «Начать проверку»';else initial='';
let running=false,abort,pc,dc,timer,queue=Promise.resolve(),latest={},pings=0,started=0,finished=false;
const show=text=>$('status').textContent=text;
async function finish(result){
  if(finished)return;finished=true;clearTimeout(timer);
  const report=safeReport({result,pings,elapsedMs:Date.now()-started,checks:latest});$('report').textContent=JSON.stringify(report,null,2);
  show({connected:'Канал открыт: все 5 проверок прошли',failed:'Прямой канал не установился',timeout:'Время ожидания истекло',stopped:'Проверка остановлена',https_failed:'Служебный HTTPS-запрос не прошёл',room_expired:'Ссылка истекла · нужна новая ссылка с ПК',unsupported:'В браузере недоступен WebRTC'}[result]);
  try{await Promise.race([send({type:'candidate',value:null,probeReport:report}),new Promise(r=>setTimeout(r,3000))]);}catch{}
  await new Promise(r=>setTimeout(r,300));abort.abort();dc?.close();pc?.close();running=false;$('start').disabled=true;$('stop').disabled=true;
}
let send;
$('start').onclick=async()=>{
  if(running)return;let token=input.value.trim()||initial;try{if(token.includes('#'))token=new URL(token).hash.slice(1);}catch{}
  if(!/^[a-f0-9]{64}$/.test(token)){show('Вставь полную ссылку проверки из файла на ПК.');return;}
  initial='';input.value='';running=true;finished=false;pings=0;latest={};queue=Promise.resolve();started=Date.now();abort=new AbortController();
  $('start').disabled=true;$('stop').disabled=false;$('report').textContent='';show('Проверяю служебный HTTPS и жду предложение ПК…');
  const endpoint=new URL('../signal.php',location.href).href;
  const api=body=>signal(endpoint,token,'phone',body,abort.signal);
  send=message=>{const task=queue.then(()=>api({op:'send',message}));queue=task.catch(()=>{});return task;};
  if(!globalThis.RTCPeerConnection){await finish('unsupported');return;}
  timer=setTimeout(()=>finish('timeout'),90000);
  try{
    pc=new RTCPeerConnection({iceServers:[{urls:['stun:stun.l.google.com:19302','stun:stun.cloudflare.com:3478']}]});
    let sent=0;pc.onicecandidate=e=>{if(e.candidate&&ipv4Candidate(e.candidate)&&sent++<32)send({type:'candidate',value:e.candidate.toJSON()}).catch(()=>finish('https_failed'));};
    pc.onconnectionstatechange=()=>{if(!finished){show('WebRTC: '+pc.connectionState);if(pc.connectionState==='failed')finish('failed');}};
    pc.ondatachannel=e=>{
      if(dc||e.channel.label!==LABEL){e.channel.close();return;}dc=e.channel;
      dc.onmessage=e=>{
        if(typeof e.data!=='string'||e.data.length>256||dc.bufferedAmount>4096){finish('failed');return;}
        try{const v=JSON.parse(e.data);if(v.type==='ping'&&v.seq===pings+1&&pings<5){pings++;dc.send(JSON.stringify({type:'pong',seq:v.seq}));show('Канал открыт · проверка '+pings+' / 5');}
        else if(v.type==='done'&&pings===5){dc.send('{"type":"doneAck"}');finish('connected');}else finish('failed');}catch{finish('failed');}
      };
    };
    let after=0,offered=false,received=0;const pending=[];
    while(!finished){
      const r=await api({op:'poll',after});
      for(const item of r.messages??[]){after=Math.max(after,item.id);const m=item.message;
        if(m?.type==='offer'&&!offered){offered=true;await pc.setRemoteDescription(description(m.value,'offer'));for(const c of pending)await pc.addIceCandidate(c);pending.length=0;
          await pc.setLocalDescription(await pc.createAnswer());await send({type:'answer',value:description(pc.localDescription,'answer')});show('Ответ отправлен · устанавливаю прямой канал…');}
        else if(m?.type==='candidate'&&m.value&&received++<32){const c=candidate(m.value);if(pc.remoteDescription)await pc.addIceCandidate(c);else pending.push(c);}
      }
      if(pc.remoteDescription)try{latest=statsSummary(await pc.getStats());}catch{}
      await new Promise(r=>setTimeout(r,700));
    }
  }catch(error){if(!finished)await finish(['https_failed','room_expired'].includes(error.message)?error.message:'failed');}
};
$('stop').onclick=()=>finish('stopped');
addEventListener('pagehide',()=>{abort?.abort();clearTimeout(timer);dc?.close();pc?.close();});
