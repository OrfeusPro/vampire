"""Bounded Version preparation/result candidates and explicit source contexts; no admission."""
import argparse,copy,hashlib,importlib.util,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NEW='544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
ROOT=Path('F:/PhoneExit Resources/Vampir');WINDOW=65536
PREP=('version-prepare','version-nm-device','version-cpu','version-windows','version-combiner','version-platform','version-prepare-nm','version-prepare-system','version-prepare-combiner','version-prepare-platform')
NAMES=PREP+('version-result','version-result-handler')
def load(name):
 s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def digest(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def discover(root):
 native,bindings,shape=load('build-native-entry-code'),load('update-bindings'),load('align-stat-batch-11318')
 contexts={};pinned={};images={}
 for name in NAMES:
  path=HERE/'knowledge/native-contexts'/(name+'-11318.json');raw=path.read_bytes();c=json.loads(raw)
  if c['source_sha256']!=OLD:raise ValueError('Version baseline source differs')
  contexts[name]=c;pinned[str(path)]=hashlib.sha256(raw).hexdigest()
 for sha in (OLD,NEW):
  path=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe';raw=path.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Version source changed')
  images[sha]=native.Image(raw);pinned[str(path)]=sha
 for c in contexts.values():
  for run,sha in c['exports'].items():
   path=root/'ghidra/request-exports'/OLD/run/'details.json'
   if digest(path)!=sha:raise ValueError('Version baseline export changed')
   pinned[str(path)]=sha
 wanted={int(contexts['version-prepare'][k],16) for k in ('prepare','constructor')}
 wanted.add(0x1467cc850)
 for name in ('version-cpu','version-combiner'):wanted.update(int(v,16) for v in contexts[name]['functions'].values())
 wanted.add(int(contexts['version-windows']['function'],16))
 wanted.update(int(contexts['version-nm-device'][k],16) for k in ('wrapper','getter'))
 wanted.update(int(contexts['version-platform'][k],16) for k in ('selector','store','lookup'))
 if len(wanted)!=20:raise ValueError('Version preparation root budget differs')
 prep=set(wanted);result=contexts['version-result'];handler=contexts['version-result-handler']
 wanted.update(int(v,16) for v in result['native_input']['functions'].values());wanted.add(int(result['reader'],16))
 wanted.add(int(handler['functions']['handler'],16))
 if len(wanted)>40:raise ValueError('Version total root budget exceeded')
 cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
 cache={};reports={};links={};calls={}
 def rows(sha,at):
  if (sha,at) not in cache:cache[sha,at]=bindings.rows(native,images[sha],at)
  return cache[sha,at]
 def add(a,b):links.setdefault(hex(a),set()).add(hex(b))
 for at in sorted(wanted):
  try:before=rows(OLD,at)
  except ValueError as e:reports[hex(at)]=dict(candidates=[],reason=str(e));continue
  oldroot=images[OLD].roots[images[OLD].containing(at)];size=oldroot[1]-oldroot[0];expected=shape.instruction_shape(before,cs)
  candidates={r for r in images[NEW].roots.values() if abs(images[NEW].pe.base+r[0]-at)<=WINDOW and r[1]-r[0]==size}
  if len(candidates)>4096:raise ValueError('Version search budget exceeded')
  hits=[]
  for r in sorted(candidates):
   target=images[NEW].pe.base+r[0]
   try:after=rows(NEW,target)
   except ValueError:continue
   if shape.instruction_shape(after,cs)==expected:hits.append(target)
  if len(hits)>32:raise ValueError('Version ambiguity budget exceeded')
  reports[hex(at)]=dict(candidates=[hex(x) for x in hits],instructions=len(before),reason=None if len(hits)==1 else 'Missing/ambiguous complete instruction/control shape')
  if len(hits)!=1:continue
  after=rows(NEW,hits[0])
  for a,b in zip(before,after):
   add(a['address'],b['address'])
   if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
   if len(a['rip_references'])!=len(b['rip_references']):raise ValueError('Version RIP arity differs')
   for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
   if a['call']:calls[hex(a['address'])]=(hex(b['address']),hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
 # Identical helper bodies are resolved only by exact direct-call links from
 # already unique full-function candidates, never by closest address.
 changed=True
 while changed:
  changed=False
  for text,item in reports.items():
   if len(item['candidates'])<=1:continue
   linked=links.get(text,set());hits=sorted(set(item['candidates'])&linked)
   if len(hits)!=1:continue
   item['candidates']=hits;item['reason']=None;item['constraint']='unique_source_call_reference';changed=True
   before,after=rows(OLD,int(text,16)),rows(NEW,int(hits[0],16))
   for a,b in zip(before,after):
    add(a['address'],b['address'])
    if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
    for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
    if a['call']:calls[hex(a['address'])]=(hex(b['address']),hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
 # The existing registration proof bounds this byte window, not its huge owner.
 window=handler['registration_window'];old_at=int(window['address'],16);old_raw=bytes.fromhex(window['bytes'])
 def window_rows(image,at,size):
  off=image.offset(at-image.pe.base);raw=image.data[off:off+size];out=[]
  for i in cs.disasm(raw,at):
   call,branch=i.group(native.capstone.CS_GRP_CALL),i.group(native.capstone.CS_GRP_JUMP)
   target=i.operands[0].imm if (call or branch) and i.operands and i.operands[0].type==native.X86_OP_IMM else None
   out.append(dict(address=i.address,bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str,call=call,branch=branch,direct_target=target,rip_references=[i.address+i.size+o.mem.disp for o in i.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]))
  if sum(len(bytes.fromhex(x['bytes'])) for x in out)!=size:raise ValueError('Registration window gap')
  return out
 before=window_rows(images[OLD],old_at,len(old_raw));expected=shape.instruction_shape(before,cs);window_hits=[]
 section=next(s for s in images[NEW].pe.sections if s['name']=='.text');start=max(section['rva'],old_at-images[NEW].pe.base-WINDOW);end=min(section['rva']+section['raw_size']-len(old_raw),old_at-images[NEW].pe.base+WINDOW)
 cursor=images[NEW].offset(start);stop=images[NEW].offset(end)+1
 while cursor<stop:
  cursor=images[NEW].data.find(old_raw[:3],cursor,stop)
  if cursor<0:break
  at=images[NEW].pe.base+section['rva']+cursor-section['raw'];cursor+=1
  try:after=window_rows(images[NEW],at,len(old_raw))
  except ValueError:continue
  if shape.instruction_shape(after,cs)==expected:window_hits.append(at)
 if len(window_hits)!=1:raise ValueError('Registration window missing/ambiguous')
 after=window_rows(images[NEW],window_hits[0],len(old_raw));new_owner=images[NEW].pe.base+images[NEW].roots[images[NEW].containing(window_hits[0])][0]
 add(int(window['owner'],16),new_owner)
 for a,b in zip(before,after):
  add(a['address'],b['address'])
  if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
  for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
 return native,images,contexts,pinned,reports,links,calls,prep

def run(root=ROOT,exports=()):
 root=Path(root);producer=digest(__file__);native,images,contexts,pinned,reports,links,calls,prep=discover(root)
 report=dict(schema=1,baseline_sha256=OLD,source_sha256=NEW,functions=reports,links={a:sorted(v) for a,v in links.items()},calls=calls,prep_roots=[reports[hex(a)]['candidates'] for a in sorted(prep)],inputs=pinned,tool_sha256=producer,semantic_verification=False,network_used=False,profile_activated=False)
 if exports:raise ValueError('Context generation not ready; candidates only')
 for path,sha in pinned.items():
  if digest(path)!=sha:raise ValueError('Version input changed during alignment')
 if digest(__file__)!=producer:raise ValueError('Version alignment tool changed')
 path=load('research-workflow').snapshot(root,'version20-proposal',report);return path,report
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--export',action='append',type=Path,default=[]);a=p.parse_args();path,r=run(a.root,a.export);print(json.dumps(dict(report=str(path),sha256=digest(path),roots={x:y['candidates'] for x,y in r['functions'].items()},gaps={x:y['reason'] for x,y in r['functions'].items() if y['reason']})))
