import { createHmac, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { feedKey,openRegistration } from './account.js';
import {CATALOG,MAX_PHONES,catalogKey,sealRequest} from './catalog.js';

export const SIGNAL = 'https://demochko.com/hosting-webrtc-probe/signal.php';
export const PRODUCT_SIGNAL = 'https://demochko.com/phone-exit/signal.php';
export const BUCKET_MS = 300000;
export function roomKey(key, bucket) {
  return createHmac('sha256', Buffer.from(key, 'hex')).update(`phone-exit-directory-v1:${bucket}`).digest('hex');
}
export function validPhone(phone) {
  return phone && /^[a-f0-9]{32}$/.test(phone.id) && /^[a-f0-9]{64}$/.test(phone.token)
    && typeof phone.name === 'string' && phone.name.length >= 1 && phone.name.length <= 40;
}
export class Directory {
  constructor(emit, request = fetch, now = Date.now) {
    this.emit = emit; this.request = request; this.now = now;
    this.phones = []; this.states = new Map(); this.cursors = new Map(); this.running = false; this.catalogDevices=new Set();
  }
  async api(token, op, message) {
    const response = await this.request(SIGNAL, {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token, role:'pc', op, message, after:this.cursors.get(token) || 0}), signal:AbortSignal.timeout(8000)});
    if (!response.ok) throw Error('directory unavailable');
    const raw = await response.text();
    if (raw.length > 262144) throw Error('directory response too large');
    return JSON.parse(raw);
  }
  setPhones(phones) {
    if (!Array.isArray(phones) || phones.length > MAX_PHONES || !phones.every(validPhone) || new Set(phones.map(p=>p.id)).size !== phones.length) throw Error('invalid phones');
    this.phones = phones.map(p=>({...p}));
    this.publish();
  }
  setAccount(account) {
    if(account==null) { this.account=null; return; }
    if(account.version!==1||!/^[a-f0-9]{64}$/.test(account.feedToken)||typeof account.privateKey!=='string'||account.privateKey.length>1024||!Array.isArray(account.blocked)||account.blocked.length>1024) throw Error('invalid account');
    this.account=account;
  }
  async discover(bucket) {
    if(!this.account) return;
    for(const b of [bucket-1,bucket]) {
      const key=feedKey(this.account.feedToken,b);
      try {
        const result=await this.api(key,'poll');
        for(const item of result.messages||[]) {
          this.cursors.set(key,Math.max(this.cursors.get(key)||0,item.id));
          const value=item.message?.value;
          if(item.message?.type!=='candidate'||value?.directory!==2||value.type!=='register') continue;
          try {
            const registration=openRegistration(this.account,value.box);
            if(!validPhone(registration)||!Number.isSafeInteger(registration.at)||Math.abs(registration.at-this.now())>45000||this.account.blocked.includes(registration.id)) continue;
            let phone=this.phones.find(p=>p.id===registration.id);
            if(phone&&phone.token!==registration.token) continue;
            if(!phone) {
              if(this.phones.length>=MAX_PHONES) continue;
              phone={id:registration.id,name:registration.name,token:registration.token}; this.phones.push(phone);
              this.emit({event:'save',phones:this.phones});
            }
            const country=/^[A-Z]{2}$/.test(registration.country)?registration.country:'';
            const prev=this.states.get(phone.id);
            if(!prev||registration.at>prev.at) this.states.set(phone.id,{country,busy:registration.busy===true,at:registration.at,received:Math.min(this.now(),registration.at)});
          } catch { /* Malformed, wrong account or tampered announcements cannot enroll. */ }
        }
      } catch { /* Keep cached devices, expire their availability normally. */ }
    }
  }
  async catalog(op,extra={}) {
    const response=await this.request(CATALOG,{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({version:1,token:catalogKey(this.account.feedToken),op,...extra}),signal:AbortSignal.timeout(8000)});
    if(!response.ok)throw Error('catalog unavailable');
    const raw=await response.text();if(raw.length>2097152)throw Error('catalog response too large');
    return JSON.parse(raw);
  }
  async discoverCatalog(){
    if(!this.account)return;
    try{
      const result=await this.catalog('list');
      if(!Array.isArray(result.devices)||result.devices.length>MAX_PHONES)return;
      for(const entry of result.devices){
        try{
          const value=openRegistration(this.account,entry.box);
          if(!validPhone(value)||entry.id!==value.id||!Number.isSafeInteger(value.at)||Math.abs(value.at-this.now())>45000||this.account.blocked.includes(value.id))continue;
          let phone=this.phones.find(p=>p.id===value.id);
          if(phone&&phone.token!==value.token)continue;
          if(!phone){if(this.phones.length>=MAX_PHONES)continue;phone={id:value.id,name:value.name,token:value.token};this.phones.push(phone);this.emit({event:'save',phones:this.phones});}
          phone.signal=value.signal===PRODUCT_SIGNAL?PRODUCT_SIGNAL:SIGNAL;
          this.catalogDevices.add(phone.id);
          const prev=this.states.get(phone.id);
          if(!prev||value.at>=prev.at)this.states.set(phone.id,{country:/^[A-Z]{2}$/.test(value.country)?value.country:'',busy:value.busy===true,at:value.at,received:Math.min(this.now(),value.at),versionName:typeof value.versionName==='string'?value.versionName.slice(0,32):null,versionCode:Number.isSafeInteger(value.versionCode)?value.versionCode:null,control:value.control||null,update:value.update||null});
        }catch{}
      }
    }catch{}
  }
  publish() {
    this.emit({event:'phones', phones:this.phones.map(p => {
      const state = this.states.get(p.id);
      return {id:p.id,name:p.name,country:state?.country || '', online:!!state && this.now()-state.received < 45000,
        busy:!!state?.busy,signal:p.signal===PRODUCT_SIGNAL?PRODUCT_SIGNAL:SIGNAL,versionName:state?.versionName??null,versionCode:state?.versionCode??null,control:state?.control??null,update:state?.update??null};
    })});
  }
  async poll() {
    if (this.running) return; this.running = true;
    const bucket = Math.floor(this.now()/BUCKET_MS);
    try {
      await this.discoverCatalog();
      await this.discover(bucket);
      await Promise.all((this.account?[]:this.phones).map(async phone => {
        for (const b of [bucket-1,bucket]) {
          const key = roomKey(phone.token,b);
          try {
            const result = await this.api(key,'poll');
            for (const item of result.messages || []) {
              this.cursors.set(key,Math.max(this.cursors.get(key)||0,item.id));
              const value = item.message?.value;
              if (item.message?.type !== 'candidate' || value?.directory !== 1 || value.type !== 'presence'
                  || !Number.isSafeInteger(value.at) || Math.abs(value.at-this.now())>45000) continue;
              const country = /^[A-Z]{2}$/.test(value.country) ? value.country : '';
              const prev = this.states.get(phone.id);
              if (!prev || value.at > prev.at) this.states.set(phone.id,{country,busy:value.busy===true,at:value.at,received:Math.min(this.now(),value.at)});
            }
          } catch { /* A failed directory poll expires availability; no secrets in errors. */ }
        }
      }));
      const allowed = new Set(this.phones.flatMap(p=>[roomKey(p.token,bucket-1),roomKey(p.token,bucket)]));
      if(this.account) { allowed.add(feedKey(this.account.feedToken,bucket)); allowed.add(feedKey(this.account.feedToken,bucket-1)); }
      for (const key of this.cursors.keys()) if (!allowed.has(key)) this.cursors.delete(key);
      this.publish();
    } finally { this.running = false; }
  }
  add(name) {
    if (this.phones.length >= MAX_PHONES) throw Error('phone limit');
    if (typeof name !== 'string' || !name.trim() || name.trim().length>40) throw Error('invalid name');
    const phone = {id:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),name:name.trim()};
    this.phones.push(phone);
    this.emit({event:'save',phones:this.phones});
    this.emit({event:'enroll',code:JSON.stringify({version:2,mode:'directory',signal:SIGNAL,...phone})});
    this.publish();
  }
  remove(id) {
    if(this.account&&!this.account.blocked.includes(id)) {
      if(this.account.blocked.length>=1024) throw Error('block limit');
      this.account.blocked.push(id); this.emit({event:'saveAccount',account:this.account});
    }
    this.phones = this.phones.filter(p=>p.id!==id); this.states.delete(id);
    this.emit({event:'save',phones:this.phones}); this.publish();
  }
  async connect(id, code) {
    const phone = this.phones.find(p=>p.id===id), state = this.states.get(id);
    if (!phone || !state || this.now()-state.received>=45000 || state.busy) throw Error('phone unavailable');
    if (code?.version!==1 || code.signal!==(phone.signal===PRODUCT_SIGNAL?PRODUCT_SIGNAL:SIGNAL) || !/^[a-f0-9]{64}$/.test(code.token)) throw Error('invalid session');
    const value = {directory:1,type:'connect',at:this.now(),request:randomBytes(16).toString('hex'),pairing:code};
    if(this.account&&this.catalogDevices.has(phone.id))await this.catalog('connect',{id:phone.id,request:sealRequest(phone.token,{at:value.at,request:value.request,pairing:code})});
    else await this.api(roomKey(phone.token,Math.floor(this.now()/BUCKET_MS)),'send',{type:'candidate',value});
    this.emit({event:'requested',id});
  }
  async updatePhone(id){
    const phone=this.phones.find(p=>p.id===id),state=this.states.get(id);
    if(!this.account||!phone||this.account.blocked.includes(id)||!state||this.now()-state.received>=45000)throw Error('phone unavailable');
    if(!state.control?.api){this.emit({event:'update',message:'На этом телефоне старый APK: первое обновление установите вручную из папки проекта.'});return;}
    const {sealControl,CONTROL}=await import('./control-api.js');const request=randomBytes(16).toString('hex');
    const response=await this.request(CONTROL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,token:catalogKey(this.account.feedToken),op:'enqueue',id,request,box:sealControl(phone.token,{id,request,at:this.now(),command:'installUpdate',args:{}})}),signal:AbortSignal.timeout(10000)});
    if(!response.ok)throw Error('update unavailable');
    this.emit({event:'update',message:'Запрос обновления отправлен выбранному телефону. После загрузки подтвердите установку на телефоне; версия в списке обновится автоматически.'});
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const emit = value => process.stdout.write(JSON.stringify(value)+'\n');
  const directory = new Directory(emit);
  let chain = Promise.resolve();
  const timer = setInterval(()=>{directory.publish();directory.poll();},6000);
  const lines = createInterface({input:process.stdin,crlfDelay:Infinity});
  lines.on('line',line => {
    chain = chain.then(async () => {
      if (line.length>65536) throw Error('large command');
      // .NET Framework's redirected UTF-8 StreamWriter may prefix the first line with BOM.
      const command = JSON.parse(line.replace(/^\uFEFF/,''));
      if(command.op==='init') {
        directory.setAccount(command.account);
        directory.setPhones(command.phones); directory.poll();
      }
      else if(command.op==='add') directory.add(command.name);
      else if(command.op==='remove') directory.remove(command.id);
      else if(command.op==='connect') await directory.connect(command.id,command.code);
      else if(command.op==='update')await directory.updatePhone(command.id);
      else if(command.op==='stop') { clearInterval(timer); process.exit(0); }
    }).catch(error=>emit({event:'error',reason:['invalid phones','phone limit','invalid name','phone unavailable','invalid session'].includes(error.message)?error.message:'invalid command',message:'Телефон недоступен или каталог не отвечает. Проверьте Wi-Fi и включённый выход на телефоне.'}));
  });
  lines.on('close',()=>{ clearInterval(timer); process.exit(0); });
}
