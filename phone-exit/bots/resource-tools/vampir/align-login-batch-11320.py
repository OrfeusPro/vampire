"""Bounded explicit Login candidates for 1.13.20; semantic replay is separate."""
import argparse,hashlib,importlib.util,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD="d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c"
NEW="544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c"
NAMES=("login-prepare","login-prepare-sdk","login-prepare-metadata","login-metadata","login-result","login-result-input","login-result-string","login-result-buffer","login-result-body-handler","login-result-handler","login-post-state","login-continuation","login-result-registration")
GATE=0x1467cdc80
WINDOW=65536

def load(name):
 s=importlib.util.spec_from_file_location(name.replace("-","_"),HERE/(name+".py"));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def digest(path):
 with Path(path).open("rb") as stream:return hashlib.file_digest(stream,"sha256").hexdigest()

def visit(value):
 if isinstance(value,dict):
  yield value
  for v in value.values():yield from visit(v)
 elif isinstance(value,list):
  for v in value:yield from visit(v)

def discover(root):
 native,bindings,align=load("build-native-entry-code"),load("update-bindings"),load("align-stat-batch-11318")
 images={};pinned={}
 for sha in (OLD,NEW):
  path=root/"client-code-snapshots"/sha/"ProjectRED-Win64-Shipping.exe";raw=path.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("Login source changed")
  images[sha]=native.Image(raw);pinned[str(path)]=sha
 contexts={}
 for name in NAMES:
  path=HERE/"knowledge/native-contexts"/(name+"-11318.json");raw=path.read_bytes();context=json.loads(raw)
  if context["source_sha256"]!=OLD:raise ValueError("Login baseline context differs")
  contexts[name]=context;pinned[str(path)]=hashlib.sha256(raw).hexdigest()
  for item in visit(context):
   for run,sha in item.get("exports",{}).items():
    path=root/"ghidra/request-exports"/OLD/run/"details.json"
    if Path(run).name!=run or not run.startswith("run-") or digest(path)!=sha:raise ValueError("Login baseline export changed")
    pinned[str(path)]=sha
 roots=set()
 for context in contexts.values():
  for item in visit(context):
   roots.update(int(at,16) for at in item.get("functions",{}).values())
   roots.update(int(item[k],16) for k in ("prepare","constructor") if isinstance(item.get(k),str))
 if len(roots)!=38:raise ValueError("Explicit Login scope changed")
 roots.add(int(contexts["login-result-registration"]["bindings"]["register"],16))
 cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
 cached={}
 def rows(sha,at):
  if (sha,at) not in cached:
   try:cached[sha,at]=bindings.rows(native,images[sha],at)
   except ValueError:cached[sha,at]=None
  return cached[sha,at]
 def shape(items):return None if items is None else align.instruction_shape(items,cs)
 candidates={};mapped={};unknown={};links={};calls={}
 def add(a,b):links.setdefault(a,set()).add(b)
 def bind(old,new):
  before,after=rows(OLD,old),rows(NEW,new)
  if shape(before)!=shape(after):raise ValueError("Login candidate body changed")
  mapped[old]=new;add(old,new)
  for a,b in zip(before,after):
   add(a["address"],b["address"])
   for x,y in zip(a["rip_references"],b["rip_references"]):add(x,y)
   if a["direct_target"] is not None:add(a["direct_target"],b["direct_target"])
   if a["call"]:calls[a["address"]]=(b["address"],hex(b["direct_target"]) if b["direct_target"] is not None else b["operands"])
 for old in sorted(roots-{GATE}):
  before=rows(OLD,old);expected=shape(before);hits=[]
  if expected is None:unknown[hex(old)]="Baseline root not linearly decoded";continue
  old_root=images[OLD].roots[images[OLD].containing(old)];size=old_root[1]-old_root[0]
  possible={r for r in images[NEW].roots.values() if abs(images[NEW].pe.base+r[0]-old)<=WINDOW and r[1]-r[0]==size}
  if len(possible)>4096:raise ValueError("Login candidate root budget exceeded")
  prefix=bytes.fromhex(before[0]["bytes"])
  for r in sorted(possible):
   at=images[NEW].pe.base+r[0];offset=images[NEW].offset(r[0])
   if images[NEW].data[offset:offset+len(prefix)]!=prefix:continue
   if shape(rows(NEW,at))==expected:hits.append(at)
  candidates[hex(old)]=[hex(v) for v in hits]
  if len(hits)>32:raise ValueError("Login candidate count exceeded")
  if len(hits)==1:bind(old,hits[0])
  else:unknown[hex(old)]="Missing/ambiguous complete instruction/control shape"
 changed=True
 while changed:
  changed=False
  for text in list(unknown):
   old=int(text,16);linked=links.get(old,set())
   if len(linked)==1 and hex(next(iter(linked))) in candidates.get(text,[]):
    bind(old,next(iter(linked)));del unknown[text];changed=True
 gate_candidates=sorted(links.get(GATE,set()))
 if len(gate_candidates)==1:add(GATE,gate_candidates[0]);mapped[GATE]=gate_candidates[0]
 else:unknown[hex(GATE)]="Gate requires explicit source-specific switch validation"
 report=dict(schema=1,baseline_sha256=OLD,source_sha256=NEW,roots={hex(a):hex(b) for a,b in mapped.items()},
  candidates=candidates,unknown=unknown,gate_candidates=[hex(v) for v in gate_candidates],
  links={hex(a):[hex(b) for b in sorted(values)] for a,values in sorted(links.items())},
  required_export_roots=sorted(hex(v) for a,v in mapped.items()),inputs=pinned,
  semantic_verification=False,network_used=False,profile_activated=False,
  limits=["Explicit 39 roots only, bounded search; callers constrain ambiguity.","Gate only caller-linked candidate; requires separate instruction/data boundary proof."])
 for p,sha in pinned.items():
  if digest(p)!=sha:raise ValueError("Login alignment input changed")
 return native,images,contexts,mapped,links,calls,report

def run(root):
 _,_,_,_,_,_,report=discover(Path(root));report["tool_sha256"]=digest(__file__)
 path=load("research-workflow").snapshot(Path(root),"login-batch-alignment-11320",report)
 return path,report

if __name__=="__main__":
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,default=Path("F:/PhoneExit Resources/Vampir"));a=p.parse_args()
 path,r=run(a.root);print(json.dumps(dict(report=str(path),sha256=digest(path),roots=r["roots"],unknown=r["unknown"],required_export_roots=r["required_export_roots"])))
