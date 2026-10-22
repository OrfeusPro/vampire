export const LABEL='phone-exit-browser-probe-v1';
export function ipv4Candidate(candidate){
  if(!candidate)return true;
  const p=candidate.candidate?.trim().split(/\s+/);
  return !!p&&p.length>=8&&p[1]==='1'&&p[2].toLowerCase()==='udp'&&!p[4].includes(':')&&candidate.candidate.length<=2048;
}
export function ipv4Sdp(sdp){return sdp.split(/\r?\n/).filter(line=>!line.startsWith('a=candidate:')||ipv4Candidate({candidate:line.slice(2)})).join('\r\n');}
export function description(value,type){
  if(value?.type!==type||typeof value.sdp!=='string'||value.sdp.length>11000||!value.sdp.includes('m=application '))throw Error('invalid_description');
  return {type,sdp:ipv4Sdp(value.sdp)};
}
export function candidate(value){
  if(value===null)return null;
  if(!ipv4Candidate(value)||typeof value.sdpMid!=='string'||value.sdpMid.length>32||!Number.isInteger(value.sdpMLineIndex)||value.sdpMLineIndex<0||value.sdpMLineIndex>8)throw Error('invalid_candidate');
  return {candidate:value.candidate,sdpMid:value.sdpMid,sdpMLineIndex:value.sdpMLineIndex};
}
export function statsSummary(report){
  const pairs=[];let pairCount=0;
  for(const s of report.values())if(s.type==='candidate-pair'){
    pairCount++;if(pairs.length>=32)continue;const p={};
    if(['frozen','waiting','in-progress','failed','succeeded'].includes(s.state))p.state=s.state;
    if(typeof s.nominated==='boolean')p.nominated=s.nominated;
    for(const k of ['requestsSent','requestsReceived','responsesSent','responsesReceived','bytesSent','bytesReceived'])if(Number.isFinite(s[k])&&s[k]>=0)p[k]=s[k];
    pairs.push(p);
  }return {pairCount,pairs};
}
export function safeReport(value){
  const result={};
  if(['connected','failed','timeout','stopped','https_failed','room_expired','unsupported'].includes(value?.result))result.result=value.result;else throw Error('invalid_report');
  for(const k of ['pings','pongs','elapsedMs'])if(Number.isSafeInteger(value[k])&&value[k]>=0&&value[k]<=600000)result[k]=value[k];
  if(value.checks)result.checks=statsSummary((value.checks.pairs??[]).slice(0,32).map(s=>({...s,type:'candidate-pair'})));
  return result;
}
export async function signal(endpoint,token,role,body,signal){
  const r=await fetch(endpoint,{method:'POST',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,role,...body}),signal:AbortSignal.any([signal,AbortSignal.timeout(8000)])});
  if(!r.ok)throw Error(r.status===410?'room_expired':'https_failed');const text=await r.text();if(text.length>262144)throw Error('signal_limit');return JSON.parse(text);
}
