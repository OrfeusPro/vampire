"""Generate explicit preparation contexts from pinned candidate links, never admission."""
import argparse,hashlib,importlib.util,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NEW='544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
LOGIN=('login-prepare','login-prepare-sdk','login-metadata','login-prepare-metadata')
VERSION=('version-prepare','version-nm-device','version-cpu','version-windows','version-combiner','version-platform','version-prepare-nm','version-prepare-system','version-prepare-combiner','version-prepare-platform','version-result','version-result-handler')
def load(name):
 s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def digest(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def objects(v):
 if isinstance(v,dict):
  yield v
  for x in v.values():yield from objects(x)
 elif isinstance(v,list):
  for x in v:yield from objects(x)
def run(root,group,alignment,exports):
 root=Path(root).resolve();alignment=Path(alignment).resolve();raw=alignment.read_bytes();report=json.loads(raw)
 if digest(alignment)!=alignment.parent.name or report['baseline_sha256']!=OLD or report['source_sha256']!=NEW:raise ValueError('Alignment identity differs')
 if group not in ('login','version'):raise ValueError('Unknown preparation group')
 producer='align-'+('login-batch' if group=='login' else 'version-contexts')+'-11320.py'
 if report['tool_sha256']!=digest(HERE/producer):raise ValueError('Alignment producer changed')
 pinned={str(alignment):digest(alignment),str(HERE/producer):digest(HERE/producer),str(Path(__file__).resolve()):digest(__file__)}
 for name,sha in report['inputs'].items():
  if digest(name)!=sha:raise ValueError('Alignment input changed')
  pinned[name]=sha
 native,binding,shape=load('build-native-entry-code'),load('update-bindings'),load('align-stat-batch-11318')
 for name in ('build-native-entry-code.py','extract-native-enums.py','update-bindings.py','align-stat-batch-11318.py','research-workflow.py'):pinned[str(HERE/name)]=digest(HERE/name)
 images={}
 for sha in (OLD,NEW):
  path=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
  if digest(path)!=sha:raise ValueError('Entry source changed')
  images[sha]=native.Image(path.read_bytes());pinned[str(path)]=sha
 links={a:set(v) for a,v in report['links'].items()}
 def add(a,b):links.setdefault(hex(a),set()).add(hex(b))
 def address(value):
  values=links.get(value,set())
  if not values:
   if 0x28000000<=int(value,16)<0x28040000:return value  # Explicit harness scratch fixture only.
  if len(values)!=1:raise ValueError('Missing/ambiguous preparation reference '+value)
  return next(iter(values))
 def data(sha,at,size):
  im=images[sha];off=im.offset(at-im.pe.base);value=im.data[off:off+size]
  if len(value)!=size:raise ValueError('Entry data bounds differ')
  return value
 contexts={}
 for name in LOGIN if group=='login' else VERSION:
  path=HERE/'knowledge/native-contexts'/(name+'-11318.json');contexts[name]=json.loads(path.read_bytes());pinned[str(path)]=digest(path)
 if group=='version':
  oldgate,newgate=load('version-gate-switch-11318'),load('version-gate-switch-11320')
  for n in ('version-gate-switch-11318.py','version-gate-switch-11320.py'):pinned[str(HERE/n)]=digest(HERE/n)
  add(oldgate.ENTRY,newgate.ENTRY)
  before,after=oldgate.rows(native,images[OLD],OLD),newgate.rows(native,images[NEW],NEW)
  if len(before)!=len(after):raise ValueError('Gate instruction count changed')
  # The source-specific validator independently checks the indexed table RVAs.
  for a,b in zip(before,after):
   if a['mnemonic']!=b['mnemonic']:raise ValueError('Gate instruction topology changed')
   add(a['address'],b['address'])
   if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
   for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
 cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
 def compare(at,current,code):
  oldraw=bytes.fromhex(code);newraw=data(NEW,current,len(oldraw))
  if data(OLD,at,len(oldraw))!=oldraw:raise ValueError('Baseline leaf differs')
  def rows(raw,where):
   ins=list(cs.disasm(raw,where))
   if sum(i.size for i in ins)!=len(raw):raise ValueError('Leaf instruction gap')
   result=[]
   for i in ins:
    call,branch=i.group(native.capstone.CS_GRP_CALL),i.group(native.capstone.CS_GRP_JUMP)
    target=i.operands[0].imm if (call or branch) and i.operands and i.operands[0].type==native.X86_OP_IMM else None
    result.append(dict(address=i.address,bytes=i.bytes.hex(),call=call,branch=branch,direct_target=target,rip_references=[i.address+i.size+o.mem.disp for o in i.operands if o.type==native.X86_OP_MEM and o.mem.base==native.X86_REG_RIP]))
   return result
  before,after=rows(oldraw,at),rows(newraw,current)
  if shape.instruction_shape(before,cs)!=shape.instruction_shape(after,cs):raise ValueError('Preparation leaf shape changed')
  for a,b in zip(before,after):
   add(a['address'],b['address'])
   for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
   if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
 allitems=[item for c in contexts.values() for item in objects(c)]
 for item in allitems:
  for at,spec in item.get('leaves',{}).items():
   if len(links.get(at,set()))==1:compare(int(at,16),int(address(at),16),spec['bytes'] if isinstance(spec,dict) else spec)
 for item in allitems:
  specs=list(item.get('tables',[]))
  if 'table_bytes' in item:specs.append(dict(address=item['table'],bytes=item['table_bytes']))
  for spec in specs:
   oldtable=int(spec['address'],16)
   if len(links.get(hex(oldtable),set()))!=1:continue
   current=int(address(hex(oldtable)),16);size=len(bytes.fromhex(spec['bytes']))
   for slot in range(0,size-size%8,8):
    a,b=struct.unpack('<Q',data(OLD,oldtable+slot,8))[0],struct.unpack('<Q',data(NEW,current+slot,8))[0]
    if images[OLD].pe.base<=a<images[OLD].pe.base+0x20000000:add(a,b)
 if group=='version':
  result=contexts['version-result'];oldtable=int(result['packet_table'],16);newtable=int(address(hex(oldtable)),16)
  literal=b'PktVersionResult\0'
  if data(OLD,oldtable+0x50,len(literal))!=literal or data(NEW,newtable+0x50,len(literal))!=literal:raise ValueError('VersionResult literal link differs')
  add(oldtable+0x50,newtable+0x50)
 leaves={at:spec['bytes'] if isinstance(spec,dict) else spec for item in allitems for at,spec in item.get('leaves',{}).items()}
 remaining=dict(leaves)
 while remaining:
  ready=[at for at in remaining if len(links.get(at,set()))==1]
  if not ready:raise ValueError('Preparation leaves not linked: '+repr(list(remaining)))
  for at in ready:compare(int(at,16),int(address(at),16),remaining.pop(at))
 # Tag literal comes from the actual linked global pointer.
 prep=contexts[group+'-prepare'];oldptr=int(prep['globals']['tag_pointer'],16);newptr=int(address(hex(oldptr)),16)
 add(struct.unpack('<Q',data(OLD,oldptr,8))[0],struct.unpack('<Q',data(NEW,newptr,8))[0])
 if group=='version':
  table=int(prep['wrapper_table'],16);current=int(address(hex(table)),16)
  for slot in (0x38,0x48):add(struct.unpack('<Q',data(OLD,table+slot,8))[0],struct.unpack('<Q',data(NEW,current+slot,8))[0])
 available={};hashes={}
 for supplied in exports:
  path=Path(supplied).resolve()
  if not path.is_relative_to(root/'ghidra/request-exports'/NEW) or path.name!='details.json':raise ValueError('Export outside current library')
  raw=path.read_bytes();value=json.loads(raw)
  if value['new_source_sha256']!=NEW:raise ValueError('Export source differs')
  available[path.parent.name]={f['address'] for f in value['functions'] if f.get('decompilation_completed')}
  hashes[path.parent.name]=hashlib.sha256(raw).hexdigest();pinned[str(path)]=hashes[path.parent.name]
 def selected(c):
  roots=set()
  for item in objects(c):
   roots.update(address(a) for a in item.get('functions',{}).values())
  for k in ('prepare','function','wrapper','getter','selector','store','lookup','reader'):
   if isinstance(c.get(k),str) and re.fullmatch('0x[0-9a-f]+',c[k]):roots.add(address(c[k]))
  if 'prepare' in c:roots.add(address(c['constructor']))
  chosen={}
  while roots:
   run=max(available,key=lambda r:len(roots&available[r]))
   if not roots&available[run]:raise ValueError('Missing preparation exports '+repr(sorted(roots)))
   roots-=available[run];chosen[run]=hashes[run]
  return chosen
 def convert(v,key=None,parent=None,chosen=None):
  if key=='source_sha256':return NEW
  if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
  if key=='exports':return chosen
  if key=='leaves':
   out={}
   for at,spec in v.items():
    code=spec['bytes'] if isinstance(spec,dict) else spec;raw=data(NEW,int(address(at),16),len(bytes.fromhex(code)))
    out[address(at)]=dict(bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()) if isinstance(spec,dict) else raw.hex()
   return out
  if key=='tables':
   out=[]
   for spec in v:
    current=address(spec['address']);raw=data(NEW,int(current,16),len(bytes.fromhex(spec['bytes'])))
    out.append(dict(address=current,bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()))
   return out
  if key=='table_bytes':return data(NEW,int(address(parent['table']),16),len(bytes.fromhex(v))).hex()
  if key=='call_sites':
   if v and not next(iter(v)).startswith('0x'):return {k:convert(x,'call_sites',v,chosen) for k,x in v.items()}
   out={}
   for at,spec in v.items():
    # Find the actual current instruction for the explicit old callsite.
    where=int(address(at),16);raw=data(NEW,where,15);i=next(cs.disasm(raw,where));target=hex(i.operands[0].imm) if i.operands[0].type==native.X86_OP_IMM else i.op_str
    if not i.group(native.capstone.CS_GRP_CALL):raise ValueError('Mapped callsite is not a call')
    out[hex(where)]=dict(target=target) if isinstance(spec,dict) else target
   return out
  if key=='switch_gate':return 'version-gate-11320'
  if key=='registration_window':
   where=int(address(v['address']),16);raw=data(NEW,where,len(bytes.fromhex(v['bytes'])))
   ins=list(cs.disasm(raw,where))
   if sum(i.size for i in ins)!=len(raw):raise ValueError('Registration window gap')
   return dict(address=hex(where),owner=address(v['owner']),bytes=raw.hex(),sha256=hashlib.sha256(raw).hexdigest(),instructions=[[hex(i.address),i.mnemonic,i.op_str] for i in ins])
  if key=='wrapper_table_sha256':return hashlib.sha256(data(NEW,int(address(parent['wrapper_table']),16),0x50)).hexdigest()
  if key=='compiled_tag_source':
   at=int(address(v['literal']),16);raw=data(NEW,at,33)
   if not re.fullmatch(b'[0-9A-F]{32}\0',raw):raise ValueError('Compiled tag format differs')
   return dict(literal=hex(at),value=raw[:-1].decode())
  if isinstance(v,dict):return {k:convert(x,k,v,chosen) for k,x in v.items()}
  if isinstance(v,list):return [convert(x,chosen=chosen) for x in v]
  if isinstance(v,str) and re.fullmatch('0x[0-9a-fA-F]+',v):return address(v.lower())
  return v
 generated={}
 for name,c in contexts.items():
  generated[name]=convert(c,chosen=selected(c));generated[name]['verify_whole_exports']=True
  if name=='version-result-handler':generated[name].pop('verify_whole_exports',None)
  if group=='login' and 'tag_literal' in generated[name]:
   at=int(generated[name]['tag_literal'],16);raw=data(NEW,at,33)
   if not re.fullmatch(b'[0-9A-F]{32}\0',raw):raise ValueError('Login compiled tag format differs')
   generated[name]['compiled_tag_source']=dict(literal=hex(at),value=raw[:-1].decode())
 for path,sha in pinned.items():
  if digest(path)!=sha:raise ValueError('Entry generation input changed')
 result=dict(schema=1,source_sha256=NEW,baseline_sha256=OLD,group=group,inputs=pinned,contexts=generated,semantic_verification=False,profile_activated=False,network_used=False)
 path=load('research-workflow').snapshot(root,'entry-context-generation-11320',result)
 return path,result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'));p.add_argument('--group',choices=('login','version'),required=True);p.add_argument('--alignment',type=Path,required=True);p.add_argument('--export',type=Path,action='append',required=True);a=p.parse_args();path,r=run(a.root,a.group,a.alignment,a.export);print(json.dumps(dict(report=str(path),contexts=list(r['contexts']))))
