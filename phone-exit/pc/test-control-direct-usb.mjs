import {DirectControl} from './src/control-direct.js';
import {execFileSync,spawn} from 'node:child_process';
import {writeFileSync,mkdirSync,unlinkSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
import native from 'node-datachannel';
const root=fileURLToPath(new URL('../',import.meta.url)),adb=root+'.tools/android-sdk/platform-tools/adb.exe';
const call=(...args)=>execFileSync(adb,['-s','81865352',...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
const pause=ms=>new Promise(r=>setTimeout(r,ms));
let instrument,direct;let instrumentationOutput="";
const offerFile=root+'.test-data/control-test-offer.json';mkdirSync(root+'.test-data',{recursive:true});
async function result(command,args={}){
  const accepted=direct.send(command,args),end=Date.now()+10000;
  while(Date.now()<end){const v=direct.get(accepted.id);if(v.status==='done'){assert.equal(v.result.ok,true,v.result.error);return v.result.result;}assert.notEqual(v.status,'expired');await pause(5);}
  throw Error('Result timeout; no replay');
}
try{
  // Instrumentation kills this app anyway. Clear stale Android binding records
  // left by repeated APK installs, preserving only permissions already granted.
  const existingServices=call('shell','settings','get','secure','enabled_accessibility_services');
  assert.ok(existingServices.split(':').includes('net.phoneexit/net.phoneexit.ControlAccessibility'),'previously granted accessibility permission');
  call('shell','am','force-stop','net.phoneexit');
  call('shell','am','start','-n','net.phoneexit/.MainActivity');
  call('shell','settings','put','secure','enabled_accessibility_services',existingServices);
  await pause(1000);
  call('shell','run-as','net.phoneexit','mkdir','-p','files');
  call('shell','run-as','net.phoneexit','rm','-f','files/control-test-stop','files/control-test-answer.json');
  direct=new DirectControl({id:'0'.repeat(32),bootstrap:async sdp=>{
    writeFileSync(offerFile,JSON.stringify({sdp}));call('push',offerFile,'/data/local/tmp/control-test-offer.json');
    call('shell','run-as','net.phoneexit','cp','/data/local/tmp/control-test-offer.json','files/control-test-offer.json');
    instrument=spawn(adb,['-s','81865352','shell','am','instrument','-w','net.phoneexit.test/net.phoneexit.ControlDirectInstrumentation'],{stdio:['ignore','pipe','pipe']});
    let output='';instrument.stdout.on('data',b=>{output+=b;instrumentationOutput+=b;});instrument.stderr.on('data',b=>{output+=b;instrumentationOutput+=b;});
    // Instrumentation kills the target process, so Android marks its already enabled
    // accessibility service as crashed. Rebind only this existing permission.
    const enabled=call('shell','settings','get','secure','enabled_accessibility_services');
    const own='net.phoneexit/net.phoneexit.ControlAccessibility';assert.ok(enabled.split(':').includes(own));
    await pause(800);
    try{call('shell','settings','put','secure','enabled_accessibility_services',enabled.split(':').filter(v=>v!==own).join(':')||'null');await pause(300);}
    finally{call('shell','settings','put','secure','enabled_accessibility_services',enabled);}

    for(let i=0;i<70;i++){
      try{const answer=JSON.parse(call('exec-out','run-as','net.phoneexit','cat','files/control-test-answer.json'));direct.id=answer.id;return {type:'answer',sdp:answer.sdp};}catch{}
      if(instrument.exitCode!==null)throw Error('Instrumentation failed: '+output);await pause(500);
    }
    throw Error('Android answer timeout');
  }});
  const start=performance.now();await direct.connect();console.log('PASS native Android connection, setup '+Math.round(performance.now()-start)+' ms');
  const info=await result('deviceInfo');assert.equal(info.versionName,'0.7.7');assert.equal(info.capabilities.api,3);assert.equal(info.screenLocked,false);
  call('shell','am','force-stop','net.phoneexit.fixture');
  await result('launch',{package:'net.phoneexit.fixture'});await pause(400);
  call('shell','uiautomator','dump','/sdcard/phone-exit-fixture.xml');const xml=call('exec-out','cat','/sdcard/phone-exit-fixture.xml');
  assert.ok(xml.includes('package="net.phoneexit.fixture"'),'fixture is the active window');
  assert.equal((await result('foreground')).package,'net.phoneexit.fixture','fixture accessibility window');
  const node=xml.match(/<node[^>]*class="android.widget.Button"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);assert.ok(node,'fixture button visible');
  const x=Math.round((Number(node[1])+Number(node[3]))/2*info.frameWidth/info.width),y=Math.round((Number(node[2])+Number(node[4]))/2*info.frameHeight/info.height);
  const cycles=[],captures=[],actions=[],captureStarts=[];
  const cycleCount=process.argv.includes('--reconnect-only')?0:60;
  for(let i=0;i<cycleCount;i++){
    const cycle=performance.now(),image=await result('screenshot',{format:'jpg',width:720,height:1280,quality:65});assert.equal(Buffer.from(image.image,'base64').readUInt16BE(0),0xffd8);captures.push(Math.round(performance.now()-cycle));captureStarts.push(image.captureStartedElapsedMs);if(i>0)assert.ok(captureStarts[i]-captureStarts[i-1]>=1000,'Android frame spacing');
    const action=performance.now();await result('tap',{x,y,width:info.frameWidth,height:info.frameHeight});actions.push(Math.round(performance.now()-action));cycles.push(Math.round(performance.now()-cycle));
    // Android screenshots have a minimum interval; drive the requested 1 cycle/s.
    await pause(Math.max(0,1000-(performance.now()-cycle)));
  }
  if(cycleCount){
  const metrics=JSON.parse(call('exec-out','run-as','net.phoneexit.fixture','cat','files/metrics.json'));assert.equal(metrics.taps,60);
  // Dispatch is paced on Android; UI click delivery occurs after the gesture and
  // has scheduler jitter. Verify the full minute and reject bursts, allowing 50ms.
  const tapIntervals=metrics.tapTimes.slice(1).map((time,i)=>time-metrics.tapTimes[i]);
  assert.ok(tapIntervals.every(time=>time>=950),'Android click delivery has no bursts');
  assert.ok(metrics.tapTimes.at(-1)-metrics.tapTimes[0]>=59000,'Android action rate <=1/s');
  const report={scope:'USB vivo over real Wi-Fi WebRTC, not remote WAN',version:info.versionName,cycles,captures,actions,captureStarts,tapIntervals,rateTarget:1,taps:metrics.taps};
  writeFileSync(root+'.test-data/control-direct-usb-speed.json',JSON.stringify(report,null,2));console.log('PASS 60 frames + 60 taps, frame starts >=1000ms, action rate <=1/s; capture latency '+Math.min(...captures)+'..'+Math.max(...captures)+'ms; action latency '+Math.min(...actions)+'..'+Math.max(...actions)+'ms');
  }
  const phoneId=direct.id;
  const reconnectCount=Number(process.argv.find(a=>a.startsWith('--reconnect-count='))?.split('=')[1]??10);
  assert.ok(Number.isInteger(reconnectCount)&&reconnectCount>=10&&reconnectCount<=20);
  for(let i=0;i<reconnectCount;i++){
    direct.close();
    direct=new DirectControl({id:phoneId,bootstrap:async sdp=>{
      call('shell','run-as','net.phoneexit','rm','-f','files/control-test-answer.json');
      writeFileSync(offerFile,JSON.stringify({sdp}));call('push',offerFile,'/data/local/tmp/control-test-offer.json');
      call('shell','run-as','net.phoneexit','cp','/data/local/tmp/control-test-offer.json','files/control-test-reoffer.json');
      for(let attempt=0;attempt<70;attempt++){
        try{return JSON.parse(call('exec-out','run-as','net.phoneexit','cat','files/control-test-answer.json'));}catch{}
        if(instrument.exitCode!==null)throw Error('Reconnect instrumentation failed: '+instrumentationOutput);await pause(250);
      }throw Error('Reconnect answer timeout');
    }});
    await direct.connect();assert.equal((await result('deviceInfo')).versionName,'0.7.7');
    console.log('PASS native reconnect '+(i+1));
  }
  console.log('PASS '+reconnectCount+' sequential native reconnects in the same Android process');
  try{
    // A disconnected phone cannot send a close frame. PC heartbeat allows 10s.
    call('shell','svc','wifi','disable');const lostDeadline=Date.now()+12000;
    while(!direct.closed&&Date.now()<lostDeadline)await pause(100);
    assert.equal(direct.closed,true,'Wi-Fi loss closes direct control');
    assert.throws(()=>direct.send('deviceInfo',{}));
  }finally{call('shell','svc','wifi','enable');}
  console.log('PASS Wi-Fi loss closes control; Wi-Fi restored');
  writeFileSync(root+'.test-data/control-direct-usb-reconnect.json',JSON.stringify({version:'0.7.7',reconnects:reconnectCount,wifiLoss:true,scope:'USB SDP only; real native Wi-Fi WebRTC'},null,2));
}finally{
  try{call('shell','run-as','net.phoneexit','touch','files/control-test-stop');}catch{}
  direct?.close();
  if(instrument){await Promise.race([new Promise(r=>instrument.once('exit',r)),pause(12000)]);if(instrument.exitCode===null)instrument.kill();}
  for(const path of ['/data/local/tmp/control-test-offer.json','/sdcard/phone-exit-fixture.xml'])try{call('shell','rm','-f',path);}catch{}
  try{unlinkSync(offerFile);}catch{}
  try{
    call('shell','am','start','-n','net.phoneexit/.MainActivity');
    const enabled=call('shell','settings','get','secure','enabled_accessibility_services'),own='net.phoneexit/net.phoneexit.ControlAccessibility';
    if(enabled.split(':').includes(own)){
      try{call('shell','settings','put','secure','enabled_accessibility_services',enabled.split(':').filter(v=>v!==own).join(':')||'null');await pause(300);}
      finally{call('shell','settings','put','secure','enabled_accessibility_services',enabled);}
    }
  }catch{}
  native.cleanup();
}

assert.match(instrumentationOutput,/PASS native Android control test/);console.log("PASS Android live-control/catalog-outage status verified");
