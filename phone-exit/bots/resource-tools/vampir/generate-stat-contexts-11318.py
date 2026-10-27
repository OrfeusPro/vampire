"""Build current stat replay contexts from exact shapes, callback tables and explicit exports."""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
def load(name):
 s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def generate(root,alignment,exports):
 root=Path(root);path=Path(alignment);a=json.loads(path.read_text('utf-8'))
 if digest(path)!=path.parent.name or a['source_sha256']!=NEW or a['baseline_sha256']!=OLD or a['unknown']:raise ValueError('Unresolved stat alignment')
 if a['tool_sha256']!=digest(HERE/'align-stat-batch-11318.py'):raise ValueError('Stat alignment producer changed')
 native=load('build-native-entry-code');images={}
 for sha in (OLD,NEW):
  raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
  if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Stat source changed')
  images[sha]=native.Image(raw)
 links={int(k,16):{int(v,16) for v in values} for k,values in a['links'].items()}
 def add(old,new):
  links.setdefault(old,set()).add(new)
  if len(links[old])!=1:raise ValueError('Conflicting stat binding '+hex(old))
 def mapped(old):
  values=links.get(old,set())
  if len(values)!=1:raise ValueError('Missing stat binding '+hex(old))
  return next(iter(values))
 shared=json.loads((HERE/'knowledge/native-contexts/character-list-records-11318.json').read_text('utf-8'))
 historical=json.loads((HERE/'knowledge/native-contexts/stat-notify-11316.json').read_text('utf-8'))
 for key in ('vector','input_constructor','input_buffer_constructor','input_u16','input_u32','input_u64','input_bool','input_raw'):
  add(int(historical['functions'][key],16),int(shared['functions'][key],16))
 for old,new in ((0x144aace10,0x144aad110),(0x144aad190,0x144aad490),(0x144aad1a0,0x144aad4a0)) :add(old,new)
 def data(sha,at,size):
  im=images[sha];off=im.offset(at-im.pe.base);return im.data[off:off+size]
 def word(sha,at):return struct.unpack('<Q',data(sha,at,8))[0]
 # Exact resize callback slot is verified against each historical fixture boundary.
 for table,resize in ((0x149924c48,0x1456ba3e0),(0x14993f988,0x1456ba3a0)):
  if word(OLD,table+8)!=resize:raise ValueError('Historical stat resize table changed')
  add(resize,word(NEW,mapped(table)+8))
 declared=dict(shared['exports']);covered={}
 for item in exports:
  p=Path(item);payload=p.read_bytes();report=json.loads(payload)
  if report.get('new_source_sha256')!=NEW:raise ValueError('Stat export source differs')
  declared[p.parent.name]=hashlib.sha256(payload).hexdigest()
  for f in report['functions']:covered[int(f['address'],16)]=f
 for run,sha in shared['exports'].items():
  p=root/'ghidra/request-exports'/NEW/run/'details.json'
  if digest(p)!=sha:raise ValueError('Shared stat input export changed')
  for f in json.loads(p.read_text('utf-8'))['functions']:covered[int(f['address'],16)]=f
 decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
 align=load('align-stat-batch-11318')
 def leaf_rows(raw,at):
  rows=[]
  for ins in decoder.disasm(raw,at):
   branch=ins.group(native.capstone.CS_GRP_JUMP);call=ins.group(native.capstone.CS_GRP_CALL)
   target=ins.operands[0].imm if (branch or call) and ins.operands[0].type==native.capstone.x86.X86_OP_IMM else None
   refs=[ins.address+ins.size+op.mem.disp for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
   rows.append(dict(address=ins.address,bytes=ins.bytes.hex(),call=call,branch=branch,direct_target=target,rip_references=refs))
  if sum(len(bytes.fromhex(r['bytes'])) for r in rows)!=len(raw):raise ValueError('Stat leaf gap')
  return rows
 result={}
 for kind in ('notify','initial'):
  old=json.loads((HERE/'knowledge/native-contexts'/('stat-'+kind+'-11316.json')).read_text('utf-8'))
  functions={k:hex(mapped(int(v,16))) for k,v in old['functions'].items()}
  for at in functions.values():
   if int(at,16) not in covered:raise ValueError('Stat root needs explicit export '+at)
  leaves={}
  for at,raw in old['leaves'].items():
   before=bytes.fromhex(raw);new=mapped(int(at,16));after=data(NEW,new,len(before))
   if data(OLD,int(at,16),len(before))!=before or align.instruction_shape(leaf_rows(before,int(at,16)),decoder)!=align.instruction_shape(leaf_rows(after,new),decoder):raise ValueError('Stat leaf shape differs')
   leaves[hex(new)]=after.hex()
  c=dict(schema=1,source_sha256=NEW,source=str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe'),functions=functions,exports=declared,leaves=leaves,helpers={'memcpy':shared['helpers']['memcpy']},alignment=dict(path=str(path),sha256=digest(path)),fixtures={hex(at):hex(mapped(at)) for at in (0x1456ba3e0,0x1456b59f0,0x1456b66c0,0x1456ba3a0,0x1456b5990,0x145594e00,0x1455f10f0)},bindings={hex(at):hex(mapped(at)) for at in (0x14991f558,0x149921c20)})
  if kind=='initial':
   current=mapped(0x145787640)
   if current not in covered:raise ValueError('PktCharacter callsite needs explicit export '+hex(current))
   main=covered[current];rows=main['instructions'];matches=[]
   for i,row in enumerate(rows):
    if row.get('text','').startswith('CALL ') and row.get('references')==[functions['reader']]:matches.append(rows[max(0,i-3):i+1])
   if len(matches)!=1 or not any('1c8' in str(row).lower() for row in matches[0]):raise ValueError('Current PktCharacter +1c8 binding differs')
   for row in matches[0]:
    raw=bytes.fromhex(row['bytes'])
    if data(NEW,int(row['address'],16),len(raw))!=raw:raise ValueError('Current stat callsite bytes differ')
   c['character_stat_link']=matches[0]
  result[kind]=c
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'));p.add_argument('--alignment',required=True,type=Path);p.add_argument('--export',action='append',required=True,type=Path);a=p.parse_args()
 for kind,value in generate(a.root,a.alignment,a.export).items():(HERE/'knowledge/native-contexts'/('stat-'+kind+'-11318.json')).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'contexts':['stat-notify-11318','stat-initial-11318'],'network_used':False}))
