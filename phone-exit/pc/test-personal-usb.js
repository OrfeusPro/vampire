import { spawn,execFileSync,execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import assert from 'node:assert/strict';
import { Directory } from './src/directory.js';

const execute=promisify(execFile), serial=process.argv[2];
if(!/^[a-zA-Z0-9_-]+$/.test(serial||'')) throw Error('USB serial required');
let raw=''; for await(const chunk of process.stdin) { raw+=chunk; if(raw.length>65536) throw Error('large config'); }
const account=JSON.parse(raw.replace(/^\uFEFF/,''));
const adb=(...args)=>execFileSync('adb.exe',['-s',serial,...args],{encoding:'utf8',timeout:20000,windowsHide:true});
const directory=new Directory(()=>{}); directory.setAccount(account); directory.setPhones([]);
const clients=new Set(); let wifiDisabled=false, held;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function bounded(promise,ms,label) {
  let timer; try { return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(label)),ms);})]); }
  finally { clearTimeout(timer); }
}
async function waitPhone(predicate,timeout=75000) {
  const deadline=Date.now()+timeout;
  while(Date.now()<deadline) {
    await directory.poll();
    const phone=directory.phones.find(p=>p.name.includes('V2061')) || directory.phones[0];
    if(phone&&predicate(directory.states.get(phone.id),phone)) return phone;
    await delay(2000);
  }
  throw Error('Phone did not reach required directory state');
}
async function connect(phone) {
  let resolvePair,resolveReady;
  const pair=new Promise(resolve=>resolvePair=resolve), ready=new Promise(resolve=>resolveReady=resolve);
  const child=spawn(process.execPath,[fileURLToPath(new URL('src/main.js',import.meta.url))],{stdio:['pipe','pipe','pipe'],env:{...process.env,PHONE_EXIT_DESKTOP:'1'},windowsHide:true});
  clients.add(child);
  const exited=new Promise(resolve=>child.once('exit',code=>{clients.delete(child);resolve(code);}));
  const lines=createInterface({input:child.stdout});
  lines.on('line',line=>{ if(line.startsWith('{')) { try { resolvePair(JSON.parse(line)); } catch {} }
    if(line.startsWith('Готово: SOCKS5')) resolveReady(); });
  child.stderr.on('data',()=>{});
  child.once('exit',()=>lines.close());
  await directory.connect(phone.id,await bounded(pair,10000,'No session created'));
  await bounded(Promise.race([ready,exited.then(()=>{throw Error('PC session exited before ready');})]),45000,'Direct connection timed out');
  return {child,exited};
}
async function https(count=1) {
  const results=await Promise.all(Array.from({length:count},()=>execute('curl.exe',['--max-time','20','--silent','--fail','--socks5-hostname','127.0.0.1:1080','https://api.ipify.org'],{windowsHide:true})));
  const ips=results.map(r=>r.stdout.trim()); assert.ok(ips.every(ip=>/^(\d{1,3}\.){3}\d{1,3}$/.test(ip))); assert.equal(new Set(ips).size,1);
}
async function hold() {
  const socket=net.connect({host:'127.0.0.1',port:1080}); let buffer=Buffer.alloc(0);
  const read=n=>bounded(new Promise((resolve,reject)=>{
    const check=()=>{ if(buffer.length>=n) { const result=buffer.subarray(0,n);buffer=buffer.subarray(n);cleanup();resolve(result); } };
    const fail=()=>{cleanup();reject(Error('SOCKS closed'));};
    const cleanup=()=>{socket.off('data',check);socket.off('error',fail);socket.off('close',fail);};
    socket.on('data',check);socket.once('error',fail);socket.once('close',fail);check();
  }),10000,'SOCKS timeout');
  socket.on('data',data=>{buffer=Buffer.concat([buffer,data]);});
  await bounded(new Promise(resolve=>socket.once('connect',resolve)),5000,'SOCKS connect');
  socket.write(Buffer.from([5,1,0])); assert.deepEqual(await read(2),Buffer.from([5,0]));
  const host=Buffer.from('example.com'); socket.write(Buffer.concat([Buffer.from([5,1,0,3,host.length]),host,Buffer.from([1,187])]));
  assert.equal((await read(10))[1],0); return socket;
}
async function stop(session) {
  if(session.child.exitCode===null) session.child.stdin.end('stop\n');
  await bounded(session.exited,7000,'PC did not stop');
}
try {
  const started=Date.now();
  adb('shell','am','force-stop','net.phoneexit');
  adb('shell','am','start','-n','net.phoneexit/.MainActivity');
  const phone=await waitPhone(state=>state?.at>=started&&!state.busy);
  console.log('PASS: phone enrolled through personal APK with no pairing code; country '+(directory.states.get(phone.id).country||'unknown'));
  const first=await connect(phone); await https(3);
  console.log('PASS: three HTTPS requests over automatically discovered phone (IP not logged)');
  held=await hold(); let streamClosed=false; held.once('close',()=>streamClosed=true);
  wifiDisabled=true; adb('shell','svc','wifi','disable');
  await bounded(first.exited,15000,'PC stayed connected without Wi-Fi');
  assert.ok(streamClosed||held.destroyed);
  console.log('PASS: Wi-Fi loss closes active TCP and PC proxy');
  await waitPhone(state=>state&&Date.now()-state.received>=45000,65000);
  assert.ok(adb('shell','dumpsys','activity','services','net.phoneexit').includes('ServiceRecord'));
  console.log('PASS: phone becomes offline in directory; Android service waits for Wi-Fi');
  const restored=Date.now(); adb('shell','svc','wifi','enable'); wifiDisabled=false;
  const returned=await waitPhone(state=>state?.at>=restored&&!state.busy);
  const second=await connect(returned); await https(); await stop(second);
  console.log('PASS: Wi-Fi recovery re-registers phone and restores HTTPS without reopening app or entering code');
} finally {
  if(wifiDisabled) adb('shell','svc','wifi','enable');
  held?.destroy();
  for(const child of clients) { try { child.stdin.end('stop\n'); } catch {} }
  await delay(3500);
  for(const child of clients) child.kill();
}
