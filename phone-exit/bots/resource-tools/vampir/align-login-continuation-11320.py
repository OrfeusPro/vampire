"""Automatic bounded continuation transfer; changed/ambiguous anchors remain queued."""
import argparse,hashlib,importlib.util,importlib.metadata,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NEW='544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
ALIGNMENT='99974a080331ea0ab6ad3bfecf1a173a7ee65f3b308f0be1c58691f9222e4d07'
WINDOW=65536
def load(n):
 s=importlib.util.spec_from_file_location(n.replace('-','_'),HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def digest(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(root):
 root=Path(root).resolve();native=load('build-native-entry-code');binding=load('update-bindings');align=load('align-stat-batch-11318')
 path=HERE/'knowledge/native-contexts/login-continuation-11318.json';raw=path.read_bytes();old=json.loads(raw)
 if old.get('source_sha256')!=OLD or len(old.get('functions',{}))!=2 or len(old.get('anchors',[]))!=6:raise ValueError('Explicit continuation source/scope differs')
 runtime=importlib.metadata.distribution('capstone');record=runtime.read_text('RECORD')
 if native.capstone.__version__!='5.0.6' or runtime.version!='5.0.6' or not record:raise ValueError('Pinned continuation decoder required')
 runtime_sha=hashlib.sha256(record.encode()).hexdigest()
 pinned={str(path):hashlib.sha256(raw).hexdigest()}
 for n in ('align-login-continuation-11320.py','build-native-entry-code.py','extract-native-enums.py','update-bindings.py','align-stat-batch-11318.py','research-workflow.py'):pinned[str(HERE/n)]=digest(HERE/n)
 images={}
 for sha in (OLD,NEW):
  path=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe';raw=path.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Continuation source changed')
  images[sha]=native.Image(raw);pinned[str(path)]=sha
 path=root/'knowledge/login-batch-alignment-11320'/ALIGNMENT/'manifest.json';raw=path.read_bytes();report=json.loads(raw)
 if hashlib.sha256(raw).hexdigest()!=ALIGNMENT or report['source_sha256']!=NEW or report['baseline_sha256']!=OLD:raise ValueError('Continuation alignment identity changed')
 pinned[str(path)]=ALIGNMENT
 producer=HERE/'align-login-batch-11320.py'
 if digest(producer)!=report['tool_sha256']:raise ValueError('Continuation alignment producer changed')
 pinned[str(producer)]=digest(producer)
 for name,sha in report['inputs'].items():
  if digest(name)!=sha:raise ValueError('Continuation alignment input changed')
  pinned[name]=sha
 links={a:set(b) for a,b in report['links'].items()};cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
 def data(sha,at,size):
  im=images[sha];off=im.offset(at-im.pe.base);v=im.data[off:off+size]
  if len(v)!=size:raise ValueError('Continuation data bounds')
  return v
 def mapped(at):
  if len(links.get(at,set()))!=1:raise ValueError('Missing/ambiguous continuation reference '+at)
  return next(iter(links[at]))
 def rows(raw,at):
  result=[]
  for i in cs.disasm(raw,at):
   call,branch=i.group(native.capstone.CS_GRP_CALL),i.group(native.capstone.CS_GRP_JUMP)
   target=i.operands[0].imm if (call or branch) and i.operands and i.operands[0].type==native.X86_OP_IMM else None
   result.append(dict(address=i.address,bytes=i.bytes.hex(),call=call,branch=branch,direct_target=target,rip_references=[i.address+i.size+o.mem.disp for o in i.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]))
  if sum(len(bytes.fromhex(r['bytes'])) for r in result)!=len(raw):raise ValueError('Continuation anchor instruction gap')
  return result
 def link(before,after):
  if align.instruction_shape(before,cs)!=align.instruction_shape(after,cs):raise ValueError('Continuation code shape changed')
  for a,b in zip(before,after):
   links.setdefault(hex(a['address']),set()).add(hex(b['address']))
   if a['direct_target'] is not None:links.setdefault(hex(a['direct_target']),set()).add(hex(b['direct_target']))
   for x,y in zip(a['rip_references'],b['rip_references']):links.setdefault(hex(x),set()).add(hex(y))
 for at in old['functions'].values():link(binding.rows(native,images[OLD],int(at,16)),binding.rows(native,images[NEW],int(mapped(at),16)))
 for spec in old['anchors']:
  at=int(spec['address'],16);raw=bytes.fromhex(spec['bytes'])
  if len(raw)>128 or data(OLD,at,len(raw))!=raw:raise ValueError('Continuation baseline anchor changed')
  section=next(s for s in images[OLD].pe.sections if s['rva']<=at-images[OLD].pe.base<s['rva']+s['raw_size'])
  if section['name']!='.text':
   mapped(spec['address']);continue  # Current table checked below and in native replay.
  before=rows(raw,at)
  if len(links.get(spec['address'],set()))==1:
   link(before,rows(data(NEW,int(mapped(spec['address']),16),len(raw)),int(mapped(spec['address']),16)));continue
  target=next(s for s in images[NEW].pe.sections if s['name']=='.text');begin=max(target['rva'],at-images[NEW].pe.base-WINDOW);end=min(target['rva']+target['raw_size']-len(raw),at-images[NEW].pe.base+WINDOW)
  im=images[NEW];cursor=im.offset(begin);stop=im.offset(end)+len(raw);hits=[]
  expected=align.instruction_shape(before,cs)
  while cursor<stop:
   cursor=im.data.find(raw[:3],cursor,stop)
   if cursor<0:break
   current=im.pe.base+target['rva']+cursor-target['raw'];cursor+=1
   try:after=rows(data(NEW,current,len(raw)),current)
   except ValueError:continue
   if align.instruction_shape(after,cs)==expected:
    consistent=True
    for a,b in zip(before,after):
     pairs=list(zip(a['rip_references'],b['rip_references']))
     if a['direct_target'] is not None:pairs.append((a['direct_target'],b['direct_target']))
     if any(len(links.get(hex(x),set()))==1 and hex(y) not in links[hex(x)] for x,y in pairs):consistent=False;break
    if consistent:hits.append(current)
   if len(hits)>32:raise ValueError('Continuation anchor candidate budget')
  if len(hits)!=1:
   for name,sha in pinned.items():
    if digest(name)!=sha:raise ValueError('Continuation inputs changed')
   if hashlib.sha256((runtime.read_text('RECORD') or '').encode()).hexdigest()!=runtime_sha:raise ValueError('Continuation runtime changed')
   queued=dict(schema=1,state='requires_review',source_sha256=NEW,baseline_sha256=OLD,
       reason='Missing/ambiguous continuation anchor',anchor=spec['address'],candidates=[hex(x) for x in hits],
       functions={k:mapped(v) for k,v in old['functions'].items()},inputs=pinned,runtime=dict(capstone=runtime.version,record_sha256=runtime_sha),
       semantic_verification=False,network_used=False,profile_activated=False)
   return load('research-workflow').snapshot(root,'continuation-alignment-11320',queued),queued
  link(before,rows(data(NEW,hits[0],len(raw)),hits[0]))
 for at,code in old['leaves'].items():link(rows(bytes.fromhex(code),int(at,16)),rows(data(NEW,int(mapped(at),16),len(bytes.fromhex(code))),int(mapped(at),16)))
 available={};exports={}
 wanted={mapped(a) for a in old['functions'].values()}
 for run in ('run-cd7653218083','run-85faf6d508b5'):
  path=root/'ghidra/request-exports'/NEW/run/'details.json';raw=path.read_bytes();value=json.loads(raw)
  if value['new_source_sha256']!=NEW:raise ValueError('Continuation export source changed')
  found={f['address'] for f in value['functions'] if f.get('decompilation_completed')}
  if wanted&found:exports[run]=hashlib.sha256(raw).hexdigest();wanted-=found;pinned[str(path)]=exports[run]
 if wanted:raise ValueError('Continuation export missing')
 def convert(v,key=None):
  if key=='source_sha256':return NEW
  if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
  if key=='exports':return exports
  if key=='anchors':return [dict(address=mapped(s['address']),bytes=data(NEW,int(mapped(s['address']),16),len(bytes.fromhex(s['bytes']))).hex()) for s in v]
  if key=='leaves':return {mapped(a):data(NEW,int(mapped(a),16),len(bytes.fromhex(code))).hex() for a,code in v.items()}
  if isinstance(v,dict):return {(mapped(k) if k.startswith('0x') else k):convert(x,k) for k,x in v.items()}
  if isinstance(v,list):return [convert(x) for x in v]
  if isinstance(v,str) and re.fullmatch('0x[0-9a-f]+',v):return mapped(v)
  return v
 current=convert(old)
 for name,sha in pinned.items():
  if digest(name)!=sha:raise ValueError('Continuation transfer inputs changed')
 if hashlib.sha256((runtime.read_text('RECORD') or '').encode()).hexdigest()!=runtime_sha:raise ValueError('Continuation runtime changed')
 result=dict(schema=1,source_sha256=NEW,baseline_sha256=OLD,context=current,inputs=pinned,semantic_verification=False,network_used=False,profile_activated=False)
 path=load('research-workflow').snapshot(root,'continuation-alignment-11320',result)
 return path,result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'));a=p.parse_args();path,r=run(a.root);print(json.dumps(dict(report=str(path),sha256=digest(path),state=r.get('state','candidate'),functions=r.get('context',r).get('functions'),reason=r.get('reason'),anchor=r.get('anchor'))))
