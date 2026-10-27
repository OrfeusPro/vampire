"""Cached function-only equivalence through the regular update binding resolver."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def digest(path):
 with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def verify(root,knowledge,source_sha,contract_id,keys):
 root,knowledge=Path(root),Path(knowledge)
 index,bindings,workflow=load('knowledge-index'),load('update-bindings'),load('research-workflow')
 model=load('update-contracts').load(index.api(),knowledge)
 contract=next((c for c in model['contracts'] if c['id']==contract_id),None)
 if contract is None or not keys or len(keys)>128:raise ValueError('Explicit bounded contract keys required')
 recipes={r['key']:r for r in contract['recipes']};selected=set(keys);pending=list(keys)
 while pending:
  key=pending.pop()
  if key not in recipes or recipes[key]['method']!='closed_shape':raise ValueError('Reviewed closed_shape recipe required')
  for callee in recipes[key].get('calls',{}).values():
   if callee not in selected:selected.add(callee);pending.append(callee)
  if len(selected)>128:raise ValueError('Function dependency budget exceeded')
 subset=dict(contract,recipes=[r for r in contract['recipes'] if r['key'] in selected],
  bindings={sha:{k:v for k,v in values.items() if k in selected} for sha,values in contract['bindings'].items()})
 sources={source_sha}|{r['baseline_sha256'] for r in subset['recipes']}
 for sha in sources:bindings.source(index.api(),root,sha)
 tools={name:digest(HERE/name) for name in ('verify-function-reuse.py','update-bindings.py','update-contracts.py','build-native-entry-code.py','extract-native-enums.py','research-workflow.py')}
 import platform,sys,importlib.metadata
 native=load('build-native-entry-code')
 runtime=importlib.metadata.distribution('capstone')
 record=runtime.read_text('RECORD')
 if native.capstone.__version__!='5.0.6' or runtime.version!='5.0.6' or not record:raise ValueError('Pinned Capstone runtime required')
 runtime_record=hashlib.sha256(record.encode()).hexdigest()
 def runtime_unchanged():
  if hashlib.sha256((runtime.read_text('RECORD') or '').encode()).hexdigest()!=runtime_record:raise ValueError('Capstone runtime changed during verification')
 identity=dict(schema=1,source_sha256=source_sha,sources=sorted(sources),contract=subset,
  tools=tools,python=platform.python_version(),executable=sys.executable,capstone=native.capstone.__version__,capstone_record_sha256=runtime_record)
 key=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
 cache=root/'knowledge/function-reuse-cache'/(key+'.json')
 if cache.is_file():
  pointer=json.loads(cache.read_text('utf-8'));path=Path(pointer['report']).resolve()
  if not path.is_relative_to((root/'knowledge/function-reuse-results').resolve()) or path.name!='manifest.json' or digest(path)!=path.parent.name:raise ValueError('Function reuse cache artifact changed')
  report=json.loads(path.read_text('utf-8'))
  if report['identity']!=identity:raise ValueError('Function reuse cache identity changed')
  for sha in sources:bindings.source(index.api(),root,sha)
  runtime_unchanged()
  if any(digest(HERE/name)!=value for name,value in tools.items()):raise ValueError('Function reuse tools changed during cache verification')
  return dict(report=str(path),sha256=digest(path),reused=True,**report['summary'])
 result=bindings.resolve(index.api(),SimpleNamespace(root=root),dict(contracts=[subset]),source_sha,[])
 proof=result['contracts'][contract_id]
 for sha in sources:bindings.source(index.api(),root,sha)
 runtime_unchanged()
 if any(digest(HERE/name)!=value for name,value in tools.items()):raise ValueError('Function reuse tools changed during verification')
 verified=[k for k,v in proof['verification'].items() if v['state'] in ('unchanged','moved_verified')]
 summary=dict(verified=len(verified),requires_review=len(selected)-len(verified),runtime_activated=False,profile_activated=False)
 report=dict(identity=identity,scope='function_only',verification=proof,summary=summary,
  limits=['Instruction equivalence within explicit callee/data closure only; semantic suites and whole contracts remain separate.',
          'No network, Ghidra, runtime activation or source-specific test bypass.'])
 path=workflow.snapshot(root,'function-reuse-results',report)
 cache.parent.mkdir(parents=True,exist_ok=True)
 workflow.atomic(cache,workflow.canonical(dict(report=str(path))))
 return dict(report=str(path),sha256=digest(path),reused=False,**summary)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
 parser.add_argument('--knowledge',type=Path,default=HERE/'knowledge')
 parser.add_argument('--source-sha256',required=True)
 parser.add_argument('--contract',required=True)
 parser.add_argument('--key',required=True,action='append')
 args=parser.parse_args()
 print(json.dumps(verify(args.root,args.knowledge,args.source_sha256,args.contract,args.key),ensure_ascii=False))
