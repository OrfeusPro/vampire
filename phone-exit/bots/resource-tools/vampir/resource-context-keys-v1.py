"""Content keys for declared resources of partial, non-publishing contexts."""
import copy
import fnmatch
import hashlib
import json
from pathlib import Path
import platform
import re
import sys

HERE=Path(__file__).resolve().parent
RECIPE='partial-resource-context-keys-v1'
LIMIT=32*1024*1024
SHA=re.compile('[0-9a-f]{64}')


def contract_key(workflow,contract):
    return hashlib.sha256(workflow.canonical({k:v for k,v in contract.items()
        if k not in ('purpose','limits','next_check')})).hexdigest()


def configuration(index,args):
    path=Path(args.knowledge)/'resource-context-keys.json'
    if not path.is_file():return None
    with path.open('rb') as stream:raw=stream.read(16385)
    value=json.loads(raw)
    if (len(raw)>16384 or not isinstance(value,dict) or set(value)!={'schema','recipe','contracts'}
            or type(value['schema']) is not int or value['schema']!=1 or value['recipe']!=RECIPE
            or not isinstance(value['contracts'],dict) or len(value['contracts'])>64
            or any(not isinstance(k,str) or not isinstance(v,str) or not SHA.fullmatch(v)
                for k,v in value['contracts'].items())):
        raise ValueError('Unknown partial resource key rule')
    return value


class Scope:
    def __init__(self,index,args):
        self.index,self.args=index,args
        self.owner=getattr(args,'resource_owner',None)
        if self.owner is None:raise ValueError('Resource context keys need the shared SHA owner')
        self.owner.check(index,args)
        self.root=Path(args.root).resolve();self.workflow=index.extension('research-workflow')
        self.rule=configuration(index,args)
        if self.rule is None:raise ValueError('Resource context key rule is missing')
        selector=Path(args.knowledge)/'resource-context-keys.json'
        self.rules={str(p.resolve()):self.owner.digest(p) for p in (HERE/'resource-context-keys-v1.py',selector)}
        with selector.open('rb') as stream:raw=stream.read(16385)
        if len(raw)>16384 or json.loads(raw)!=self.rule:raise ValueError('Resource context rule changed')
        self.owner.remember(selector,raw)
        self.runtime=dict(python=platform.python_version(),executable_sha256=self.owner.digest(sys.executable),
            fnmatch_sha256=self.owner.digest(fnmatch.__file__))
        self.hashes=None
        if (Path(args.knowledge)/'resource-selected-hashes.json').is_file():
            self.hashes=index.extension('resource-selected-hashes-v1').scope(index,args)
            self.rules.update(self.hashes.rules)
            self.runtime['selected_hashes']=self.hashes.runtime
        self.key=hashlib.sha256(self.workflow.canonical(dict(rules=self.rules,runtime=self.runtime))).hexdigest()
        self.observed,self.documents,self.contexts={},{},{}
        self.prepared=None;self.published=False
        self.metrics=dict(selected_inputs=0,fallback_inputs=0,contexts=0)

    def read(self,pointer):
        if (not isinstance(pointer,dict) or set(pointer)!={'path','sha256'}
                or not isinstance(pointer['path'],str) or not Path(pointer['path']).is_absolute()
                or not isinstance(pointer['sha256'],str) or not SHA.fullmatch(pointer['sha256'])):
            raise ValueError('Resource context keys need an exact pointer')
        path=Path(pointer['path']).resolve()
        if not path.is_relative_to(self.root) or path.name!='manifest.json' or path.parent.name!=pointer['sha256']:
            raise ValueError('Resource context proof outside immutable library')
        with path.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or self.owner.remember(pointer['path'],raw)!=pointer['sha256']:
            raise ValueError('Resource context proof changed')
        return json.loads(raw)

    def observe(self,row,outcome):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Resource context keys already prepared')
        slot=str(Path(row['path']).resolve());directory=outcome.get('directory') or {}
        value=dict(source=(row.get('current') or {}).get('sha256'),directory=directory.get('report'))
        if slot in self.observed and self.observed[slot]!=value:
            raise ValueError('Resource context observation changed')
        self.observed[slot]=value

    def directory(self,row):
        slot=str(Path(row['path']).resolve());observed=self.observed.get(slot)
        source=(row.get('current') or {}).get('sha256')
        if not observed or not observed['directory']:return None,'directory_not_observed'
        if observed['source']!=source:raise ValueError('Resource context archive identity changed')
        if slot in self.documents:return self.documents[slot]
        scope=getattr(self.args,'resource_directory_v1_scope',None)
        if scope is None or scope.owner is not self.owner:
            raise ValueError('Resource context keys need the verified directory owner')
        document=self.read(observed['directory']);inputs=document.get('inputs',{})
        if (document.get('recipe')!='resource-directory-v1' or inputs.get('rules')!=scope.rules
                or inputs.get('runtime')!=scope.runtime or inputs.get('source',{}).get('path')!=slot
                or inputs['source'].get('sha256')!=source
                or document.get('authoritative_directory_for_archive') is not True):
            raise ValueError('Resource context directory provenance differs')
        self.owner.expect(row['path'],source)
        if document.get('path_gaps')!=[] or document.get('unmatched_csv')!=[]:
            result=(None,'directory_inventory_incomplete')
        else:
            entries=document.get('directory_entries')
            if not isinstance(entries,list) or len(entries)>100000:
                raise ValueError('Resource context directory exceeds budget')
            paths=[e.get('canonical_path') for e in entries]
            if any(not isinstance(p,str) or not p for p in paths) or len(paths)!=len(set(paths)):
                raise ValueError('Resource context directory names differ')
            result=(entries,None)
            self.documents[slot+'-proof']=document
        self.documents[slot]=result
        return result

    def inputs(self,contract,rows):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Resource context keys already prepared')
        eligible=(contract.get('coverage')=='partial' and contract.get('builder') is None
            and not contract.get('context_checks') and bool(contract.get('checks'))
            and self.rule['contracts'].get(contract['id'])==contract_key(self.workflow,contract))
        selected=[];proof=[]
        for dep in contract.get('resources',[]):
            for row in rows:
                if not fnmatch.fnmatchcase(row['path'].replace('\\','/'),dep['archive']):continue
                legacy=dict(archive=row['path'],sha256=(row.get('current') or {}).get('sha256'),
                    logical_path_pattern=dep['path'],logical_paths_verified=False)
                reason='partial_contract_rule_not_applicable';entries=None
                if eligible:entries,reason=self.directory(row)
                matching=([e for e in entries if fnmatch.fnmatchcase(e['canonical_path'],dep['path'])]
                    if entries is not None else None)
                supplementary=[]
                if matching is not None and self.hashes is not None:
                    enriched=[];document=self.documents[str(Path(row['path']).resolve())+'-proof']
                    for e in matching:
                        value=e
                        if e.get('decoded_sha256') is None:
                            extra=self.hashes.resolve(row,document,e)
                            supplementary.append(dict(path=e['canonical_path'],**extra))
                            if extra['state']=='hashed':value=dict(e,decoded_sha256=extra['sha256'])
                        enriched.append(value)
                    matching=enriched
                if matching is not None and any(not isinstance(e.get('decoded_sha256'),str)
                        or not SHA.fullmatch(e['decoded_sha256']) or type(e.get('uncompressed')) is not int
                        or e['uncompressed']<0 for e in matching):
                    reason='matching_payload_hash_unknown';matching=None
                if matching is None:
                    value=legacy;self.metrics['fallback_inputs']+=1
                else:
                    value=dict(archive=row['path'],logical_path_pattern=dep['path'],logical_paths_verified=True,
                        recipe=RECIPE,rule_sha256=self.key,entries=sorted([dict(path=e['canonical_path'],
                            sha256=e['decoded_sha256'],bytes=e['uncompressed']) for e in matching],key=lambda e:e['path']))
                    self.metrics['selected_inputs']+=1
                selected.append(value)
                proof.append(dict(archive=row['path'],source_sha256=(row.get('current') or {}).get('sha256'),
                    pattern=dep['path'],directory=(self.observed.get(str(Path(row['path']).resolve())) or {}).get('directory'),
                    mode='selected_content' if matching is not None else 'full_archive',reason=reason))
                if supplementary:proof[-1]['selected_record_hashes']=supplementary
        entry=dict(contract_key=contract_key(self.workflow,contract),resource_inputs_sha256=hashlib.sha256(
            self.workflow.canonical(selected)).hexdigest(),eligible=eligible,proof=proof)
        if contract['id'] in self.contexts and self.contexts[contract['id']]!=entry:
            raise ValueError('Resource context request changed during update')
        self.contexts[contract['id']]=entry;self.metrics['contexts']=len(self.contexts)
        return selected

    def prepare(self):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Resource context keys already prepared')
        body=dict(schema=1,recipe=RECIPE,rules=self.rules,runtime=self.runtime,contexts=self.contexts,
            metrics=self.metrics,scope='declared_resources_of_guarded_partial_contexts',
            semantic_checks_unchanged=True,runtime_dependency_completeness_verified=False,profile_activated=False)
        if self.hashes is not None:body['selected_hash_metrics']=copy.deepcopy(self.hashes.metrics)
        raw=self.workflow.canonical(body)
        if len(raw)>LIMIT:raise ValueError('Resource context proof exceeds budget')
        path=self.workflow.snapshot(self.root,'resource-context-key-proofs-v1',body)
        self.prepared=dict(path=str(path),sha256=self.owner.remember(path,raw))
        return copy.deepcopy(self.prepared)

    def publish(self,barrier):
        if self.prepared is None or self.published or self.owner.state!='completed':
            raise ValueError('Resource context publication needs its completed owner')
        target=Path(barrier['report']).resolve();sha=barrier['sha256']
        if (not isinstance(sha,str) or not SHA.fullmatch(sha) or target.name!='manifest.json'
                or target.parent.name!=sha or not target.is_relative_to(self.root/'knowledge/resource-owner-barriers-v4')):
            raise ValueError('Resource context barrier outside immutable library')
        with target.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError('Resource context barrier changed')
        proof=json.loads(raw)
        if (barrier.get('barrier_completed') is not True or proof.get('barrier_completed') is not True
                or proof.get('epoch')!=self.owner.epoch or proof.get('recipe')!='resource-owner-sha-v4'
                or any(proof['inputs'].get(str(p))!=s for p,s in self.owner.files.items())
                or self.index.digest(self.prepared['path'])!=self.prepared['sha256']):
            raise ValueError('Resource context publication proof differs')
        body=dict(schema=1,recipe=RECIPE,proof=self.prepared,owner_barrier=dict(path=str(target),sha256=sha),
            semantic_checks_unchanged=True,runtime_dependency_completeness_verified=False,profile_activated=False)
        path=self.workflow.snapshot(self.root,'resource-context-key-receipts-v1',body);self.published=True
        result=dict(report=str(path),sha256=self.index.digest(path),proof=copy.deepcopy(self.prepared),
            metrics=copy.deepcopy(self.metrics),semantic_checks_unchanged=True)
        if self.hashes is not None:result['selected_hashes']=copy.deepcopy(self.hashes.metrics)
        return result
