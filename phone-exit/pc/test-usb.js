// Explicit USB integration run; not part of the offline npm test suite.
import { spawn, execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import net from 'node:net';
const serial = process.argv[2];
const check = process.argv[3] || 'stop';
if(!['stop','wifi-loss'].includes(check)) throw Error('Expected stop or wifi-loss');
const run = promisify(execFile);
async function heldConnection() {
  const socket=net.connect({host:'127.0.0.1',port:1080});
  let pending=Buffer.alloc(0),notify,problem;
  socket.on('data',chunk=>{pending=Buffer.concat([pending,chunk]);notify?.();});
  socket.on('error',error=>{problem=error;notify?.();});
  socket.on('close',()=>{problem||=Error('Held socket closed');notify?.();});
  const read=async n=>{while(pending.length<n){if(problem)throw problem;await new Promise(r=>notify=r);}const out=pending.subarray(0,n);pending=pending.subarray(n);return out;};
  await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
  socket.write(Buffer.from([5,1,0])); if(!(await read(2)).equals(Buffer.from([5,0]))) throw Error('SOCKS authentication');
  const host=Buffer.from('api.ipify.org'); const request=Buffer.concat([Buffer.from([5,1,0,3,host.length]),host,Buffer.from([1,187])]);
  socket.write(request); const reply=await read(10); if(reply[1]!==0) throw Error('Held CONNECT rejected');
  let ended=false; const closed=new Promise(resolve=>socket.once('close',()=>{ended=true;resolve();}));
  return {socket,closed,isClosed:()=>ended};
}
if (!serial || !/^[a-zA-Z0-9._:-]+$/.test(serial)) throw Error('Usage: node test-usb.js SERIAL');
const adb = (...args) => execFileSync('adb',['-s',serial,...args],{encoding:'utf8',timeout:20000});
const child = spawn(process.execPath,['src/main.js'],{stdio:['ignore','pipe','pipe']});
let paired = false, ready = false;
let wifiDisabled = false;
let held;
const rl = createInterface({input:child.stdout});
const stop = () => {
  held?.socket.destroy();
  if(wifiDisabled) { try { adb('shell','svc','wifi','enable'); } catch {} wifiDisabled=false; }
  try { adb('shell','am','force-stop','net.phoneexit'); } catch {}
  child.kill(); rl.close();
};
const deadline = setTimeout(() => { console.error('FAIL: USB pairing timed out'); stop(); process.exitCode=1; },90000);
child.stderr.on('data',d => process.stderr.write(d));
child.on('exit',code => { if(!ready) {clearTimeout(deadline); console.error('Client stopped before connection:',code);process.exitCode=1;} });
rl.on('line',async line => {
  if(line.startsWith('{')&&!paired) {
    paired=true;
    const pairing=JSON.parse(line);
    if(pairing.version!==1 || !/^[0-9a-f]{64}$/.test(pairing.token)) throw Error('Invalid pairing');
    const encoded=Buffer.from(line).toString('base64');
    // Do not log the capability or save it to disk.
    console.log('Launching debug application on USB device');
    const launch=adb('shell','am','start','-S','-n','net.phoneexit/.UsbTestActivity','--es','testPairingBase64',encoded);
    console.log(launch.replaceAll(encoded,'[pairing omitted]').trim());
  } else if(line.startsWith('Готово:')&&!ready) {
    ready=true;clearTimeout(deadline);
    console.log('WebRTC connected; checking HTTPS through phone SOCKS');
    try {
      const responses=await Promise.all([0,1,2].map(() => run('curl.exe',['--fail','--silent','--show-error','--max-time','25','--socks5-hostname','127.0.0.1:1080','https://api.ipify.org'],{encoding:'utf8',timeout:30000})));
      const addresses=responses.map(r => r.stdout.trim());
      if(addresses.some(r=>!net.isIP(r)) || new Set(addresses).size!==1) throw Error('Invalid or inconsistent exit IP');
      console.log('PASS: three parallel HTTPS requests through Android Wi-Fi; same public IP (not logged)');
      writeFileSync(new URL('../android-connected.png',import.meta.url),execFileSync('adb',['-s',serial,'exec-out','screencap','-p'],{timeout:15000}));
      held=await heldConnection();
      if(held.isClosed()) throw Error('Held TCP stream closed before interruption');
      const exited=new Promise(resolve => child.once('exit',resolve));
      if(check==='wifi-loss') {
        wifiDisabled=true; adb('shell','svc','wifi','disable');
      } else {
        // Click the real app control, rather than relying on OEM Intent delivery.
        const dumpPath='/data/local/tmp/phone-exit-test-ui.xml';
        adb('shell','uiautomator','dump',dumpPath);
        const ui=adb('shell','cat',dumpPath);
        const nodes=ui.match(/<node\b[^>]*>/g)||[];
        const button=nodes.find(n => n.includes('package="net.phoneexit"') && /text="Остановить"/i.test(n));
        const bounds=button?.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
        adb('shell','rm',dumpPath);
        if(!bounds) throw Error('Phone Exit stop button is not visible');
        adb('shell','input','tap',String(Math.floor((Number(bounds[1])+Number(bounds[3]))/2)),String(Math.floor((Number(bounds[2])+Number(bounds[4]))/2)));
      }
      const timeout=new Promise((_,reject) => { const timer=setTimeout(()=>reject(Error('Client did not stop after phone disconnected')),15000); timer.unref(); });
      await Promise.race([exited,timeout]);
      await Promise.race([held.closed,timeout]);
      console.log('PASS: active TCP stream closed');
      console.log(`PASS: ${check} closes PC client; no fallback to mobile internet`);
    } catch(error) { console.error('FAIL:',error.message);process.exitCode=1; }
    finally { stop(); }
  } else if(!line.includes('token')) console.log(line);
});
process.on('SIGINT',() => {clearTimeout(deadline);stop();});
