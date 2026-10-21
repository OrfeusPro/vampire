// Offline tool. Default output contains counts, never hosts, tokens or bodies.
import {open,mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {CAPTURE_LIMITS} from './diagnostic-capture.js';
const MAX=CAPTURE_LIMITS['all-tcp'];

export async function readCapture(path) {
  const file=await open(path,'r');let bytes;
  try{
    if((await file.stat()).size>MAX.maxFileBytes)throw Error('Capture exceeds file limit');
    const buffer=Buffer.alloc((MAX.maxFileBytes+1));let used=0;
    while(used<buffer.length){const {bytesRead}=await file.read(buffer,used,buffer.length-used,null);if(!bytesRead)break;used+=bytesRead;}
    if(used>MAX.maxFileBytes)throw Error('Capture exceeds file limit');bytes=buffer.subarray(0,used);
  }finally{await file.close();}
  const lines=bytes.toString('utf8').split('\n');if(lines.pop()!=='')throw Error('Incomplete capture record');
  if(lines.length>(MAX.maxRecords+1))throw Error('Capture record limit');
  const flows=new Map();let start=false,end=null,total=0,mode='endpoints',limits=CAPTURE_LIMITS.endpoints;
  for(const line of lines){
    if(line.length>262144)throw Error('Capture record limit');
    let r;try{r=JSON.parse(line);}catch{throw Error('Invalid capture JSON');}
    if(!r||typeof r!=='object'||end)throw Error('Invalid capture order');
    if(r.type==='start'){
      if(start||r.version!==1)throw Error('Unsupported capture');
      mode=r.mode??'endpoints';if(!Object.hasOwn(CAPTURE_LIMITS,mode))throw Error('Unsupported capture mode');
      limits=CAPTURE_LIMITS[mode];
      if(bytes.length>limits.maxFileBytes||lines.length>limits.maxRecords+1)throw Error('Capture exceeds mode limits');
      start=true;continue;
    }
    if(!start)throw Error('Missing capture header');
    if(r.type==='end'){
      if(r.bytes!==total||r.flows!==flows.size)throw Error('Capture counters differ');end=r;continue;
    }
    if(!Number.isInteger(r.flow)||r.flow<1||r.flow>limits.maxFlows)throw Error('Invalid capture flow');
    if(r.type==='open'){
      if(flows.has(r.flow))throw Error('Duplicate capture flow');
      flows.set(r.flow,{flow:r.flow,c2s:[],s2c:[],c2sBytes:0,s2cBytes:0,closed:false});continue;
    }
    const f=flows.get(r.flow);if(!f||f.closed)throw Error('Invalid capture flow order');
    if(r.type==='close'){if(r.c2s!==f.c2sBytes||r.s2c!==f.s2cBytes)throw Error('Capture counters differ');f.closed=true;continue;}
    if(r.type!=='data'||!['c2s','s2c'].includes(r.direction)||!Number.isInteger(r.length)||r.length<0||r.length>1048576||typeof r.data!=='string')throw Error('Invalid capture data');
    const value=Buffer.from(r.data,'base64');
    if(value.toString('base64')!==r.data||value.length!==r.length||r.offset!==f[r.direction+'Bytes'])throw Error('Capture offset or length differs');
    total+=value.length;if(total>limits.maxBytes)throw Error('Capture exceeds data limit');
    f[r.direction].push(value);f[r.direction+'Bytes']+=value.length;
  }
  if(!start)throw Error('Missing capture header');
  return {flows,summary:{version:1,mode,fileSha256:createHash('sha256').update(bytes).digest('hex'),fileBytes:bytes.length,
    finalized:!!end,reason:!end?'unfinished':['manual','transport_stopped','time_limit','byte_limit','file_limit','queue_limit','flow_limit','record_limit','io_error','observer_error'].includes(end.reason)?end.reason:'unknown',
    bytes:total,flows:[...flows.values()].map(f=>({flow:f.flow,c2sBytes:f.c2sBytes,s2cBytes:f.s2cBytes,closed:f.closed}))}};
}
export async function exportCapture(path) {
  const result=await readCapture(path),folder=join(resolve(path,'..'),'streams');
  // Never overwrite an earlier export, including a partial one.
  await mkdir(folder,{mode:0o700});
  for(const f of result.flows.values())for(const direction of ['c2s','s2c'])
    await writeFile(join(folder,`flow-${String(f.flow).padStart(2,'0')}-${direction}.bin`),Buffer.concat(f[direction]),{flag:'wx',mode:0o600});
  return result.summary;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const args=process.argv.slice(2);
  try{
    if(args.length<1||args.length>2||(args[1]&&args[1]!=='--export'))throw Error('Usage: capture-inspect.js traffic.jsonl [--export]');
    const result=args[1]?await exportCapture(args[0]):(await readCapture(args[0])).summary;
    console.log(JSON.stringify(result,null,2));
  }catch{console.error('Не удалось проверить запись. Проверьте формат, лимиты и отсутствие прежнего каталога streams.');process.exitCode=1;}
}
