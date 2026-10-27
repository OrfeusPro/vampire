"""Run registered current tag/writer contracts using existing immutable exports."""
import argparse,hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE='544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
ROOT=Path('F:/PhoneExit Resources/Vampir')
BASELINE='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
def load(name):
 s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def digest(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def context(name,root=ROOT):
 if name not in ('game-version','game-login'):raise ValueError('Explicit entry contract required')
 model=load('update-contracts').load(load('knowledge-index').api(),HERE/'knowledge')
 contract=next(c for c in model['contracts'] if c['id']==name)
 prep=json.loads((HERE/'knowledge/native-contexts'/ (('version-prepare' if name=='game-version' else 'login-prepare')+'-11320.json')).read_bytes())
 wire=json.loads((HERE/'knowledge/native-contexts/archive-wire-11320.json').read_bytes())
 exports=[]
 for key in ('constructor','prepare','writer'):
  at=contract['bindings'][SOURCE][key]
  artifacts=[]
  for run,expected in (wire if key=='writer' else prep)['exports'].items():
   path=root/'ghidra/request-exports'/SOURCE/run/'details.json'
   if digest(path)!=expected:raise ValueError('Reviewed entry export changed')
   artifacts.append(dict(path=str(path),sha256=expected))
  exports.append(dict(address=at,state='ready',artifacts=artifacts))
 return dict(schema=1,source_sha256=SOURCE,source=str(root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'),contract=contract,bindings=dict(bindings=contract['bindings'][SOURCE]),exports=exports,dependencies={})
def run(kind,root=ROOT):
 if kind not in ('tags','writers'):raise ValueError('Explicit verification kind required')
 module=load('verify-version-login-context' if kind=='tags' else 'verify-packet-writer-context')
 reports={name:module.verify(context(name,root),root) for name in ('game-version','game-login')}
 expected={'tags':{'game-version':4,'game-login':4},'writers':{'game-version':56,'game-login':104}}[kind]
 for name,r in reports.items():
  if r['source_sha256']!=SOURCE or len(r['cases'])!=expected[name] or r.get('network_used') is not False or r.get('profile_activated') is not False:raise ValueError('Entry contract source/coverage differs')
 result=dict(schema=1,source_sha256=SOURCE,kind=kind,reports=reports,network_used=False,profile_activated=False,runtime_activated=False)
 return load('research-workflow').snapshot(root,'entry-contract-checks-11320',result),result
def binding_proposals(root=ROOT):
 """Bounded preparation bindings only, never whole-contract/runtime admission."""
 proof_path,proof,_=load('run-entry-batch-11320').run(root)
 if proof['source_sha256']!=SOURCE or proof.get('runtime_activated') is not False:raise ValueError('Preparation proof scope differs')
 path=root/'knowledge/version20-proposal/d0a0ad89cb37b0149e21fe6628b516459ecce7b32caa1e395a86a4fdb2288d60/manifest.json'
 r=json.loads(path.read_bytes())
 if digest(path)!=path.parent.name or r['baseline_sha256']!=BASELINE or r['source_sha256']!=SOURCE or r['tool_sha256']!=digest(HERE/'align-version-contexts-11320.py'):raise ValueError('Preparation candidate provenance changed')
 model=load('update-contracts').load(load('knowledge-index').api(),HERE/'knowledge')
 contract=next(c for c in model['contracts'] if c['id']=='game-version')
 # Restrict to the explicit preparation set; result/input roles are excluded.
 selected={row[0] for row in r['prep_roots'] if len(row)==1}
 proposals={}
 for key,before in contract['bindings'][BASELINE].items():
  candidates=r['functions'].get(before,{}).get('candidates',[])
  if len(candidates)!=1 or candidates[0] not in selected:continue
  current=contract['bindings'].get(SOURCE,{}).get(key)
  if current is not None and current!=candidates[0]:raise ValueError('Preparation binding conflict')
  if current is None:proposals[key]=candidates[0]
 return dict(source_sha256=SOURCE,baseline_sha256=BASELINE,contract='game-version',bindings=proposals,
     proof=str(proof_path),proof_sha256=digest(proof_path),scope='bounded_preparation_with_declared_fixtures',runtime_activated=False)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kind',choices=('tags','writers'),required=True);a=p.parse_args();path,r=run(a.kind);print(json.dumps(dict(report=str(path),sha256=digest(path),cases=sum(len(x['cases']) for x in r['reports'].values()))))
