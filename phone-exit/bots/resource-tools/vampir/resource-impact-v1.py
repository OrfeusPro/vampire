"""Source-bound resource diagnostics published after the shared SHA barrier."""
import copy
import fnmatch
import hashlib
import json
from pathlib import Path
import platform
import re
import sys

HERE = Path(__file__).resolve().parent
RECIPE = 'resource-impact-post-barrier-v1'
RULE = dict(schema=1,recipe=RECIPE,scope='named-tables',execution_reuse=False)
STATES = ('unchanged','changed','added','removed','unknown')
SHA = re.compile('[0-9a-f]{64}')
LIMIT = 32*1024*1024


def enabled(index,args):
    path=Path(args.knowledge)/'resource-impact-engine.json'
    if not path.is_file():return False
    with path.open('rb') as stream:raw=stream.read(4097)
    value=json.loads(raw)
    if (len(raw)>4096 or value!=RULE or type(value.get('schema')) is not int
            or type(value.get('execution_reuse')) is not bool):
        raise ValueError('Unknown resource impact selector')
    return True


class Scope:
    def __init__(self,index,args,manifest,report):
        self.index,self.args=index,args
        self.owner=getattr(args,'resource_owner',None)
        if self.owner is None:raise ValueError('Resource impact needs the shared SHA owner')
        self.owner.check(index,args)
        self.root=Path(args.root).resolve()
        self.workflow=index.extension('research-workflow')
        self.report=copy.deepcopy(report)
        manifest=Path(manifest).resolve()
        if not manifest.is_relative_to(self.root):raise ValueError('Resource impact audit outside library')
        with manifest.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or json.loads(raw)!=report:raise ValueError('Resource impact audit differs')
        self.audit=dict(path=str(manifest),sha256=self.owner.remember(manifest,raw))
        self.rules={}
        for p in (HERE/'resource-impact-v1.py',HERE/'resource-pipeline-v3.py',
                Path(args.knowledge)/'resource-impact-engine.json',Path(args.knowledge)/'update-contracts.json'):
            self.rules[str(p.resolve())]=self.owner.digest(p)
        if not enabled(index,args):raise ValueError('Resource impact selector is missing')
        registry_path=Path(args.knowledge)/'update-contracts.json'
        with registry_path.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT:raise ValueError('Resource impact registry exceeds budget')
        self.owner.remember(registry_path,raw)
        registry=json.loads(raw)
        if (not isinstance(registry,dict) or type(registry.get('schema')) is not int
                or registry['schema']!=1 or not isinstance(registry.get('contracts'),list)):
            raise ValueError('Resource impact contract registry differs')
        self.contracts=[];ids=set()
        for c in registry['contracts']:
            if (not isinstance(c,dict) or not isinstance(c.get('id'),str) or c['id'] in ids
                    or not isinstance(c.get('depends_on'),list)
                    or any(not isinstance(d,str) for d in c['depends_on'])):
                raise ValueError('Resource impact consumer identities differ')
            ids.add(c['id'])
            deps=c.get('resources',[])
            if not isinstance(deps,list) or any(not isinstance(d,dict) or set(d)!={'archive','path'}
                    or any(not isinstance(d[k],str) or not d[k] for k in d) for d in deps):
                raise ValueError('Resource impact needs declared archive/path patterns')
            self.contracts.append(dict(id=c['id'],depends_on=c['depends_on'],resources=deps))
        if any(d not in ids for c in self.contracts for d in c['depends_on']):
            raise ValueError('Resource impact has an unknown consumer dependency')
        self.files={}
        for row in report['files']:
            slot=str(Path(row['path']).resolve())
            if slot in self.files:raise ValueError('Resource impact archive slots are ambiguous')
            self.files[slot]=copy.deepcopy(row)
        self.runtime=dict(python=platform.python_version(),executable=str(Path(sys.executable).resolve()),
            executable_sha256=self.owner.digest(sys.executable),fnmatch_sha256=self.owner.digest(fnmatch.__file__))
        self.observed={};self.prepared=None;self.published=False
        self.metrics=dict(analyses=0,cache_hits=0)

    def read(self,pointer):
        if (not isinstance(pointer,dict) or set(pointer)!={'path','sha256'}
                or not isinstance(pointer['path'],str) or not Path(pointer['path']).is_absolute()
                or not isinstance(pointer['sha256'],str) or not SHA.fullmatch(pointer['sha256'])):
            raise ValueError('Resource impact needs an exact pointer')
        path=Path(pointer['path']).resolve()
        if not path.is_relative_to(self.root) or path.name!='manifest.json' or path.parent.name!=pointer['sha256']:
            raise ValueError('Resource impact proof outside immutable library')
        with path.open('rb') as stream:raw=stream.read(LIMIT+1)
        if len(raw)>LIMIT or self.owner.remember(pointer['path'],raw)!=pointer['sha256']:
            raise ValueError('Resource impact proof changed')
        return json.loads(raw)

    def observe(self,row,outcome):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Resource impact already prepared')
        slot=str(Path(row['path']).resolve())
        if row!=self.files.get(slot):raise ValueError('Resource impact source differs from audit')
        value=copy.deepcopy(outcome.get('named_tables'))
        if slot in self.observed and self.observed[slot]!=value:
            raise ValueError('Resource impact observation changed')
        self.observed[slot]=value

    def material(self,slot,named):
        if not named or named.get('state') not in ('compared','baseline_missing'):
            return None
        scope=getattr(self.args,'resource_named_tables_v1_scope',None)
        if scope is None or scope.owner is not self.owner:
            raise ValueError('Resource impact needs the same verified named scope')
        delta=self.read(named['report']);inputs=delta.get('inputs',{})
        if (delta.get('recipe')!='named-table-baselines-v1' or inputs.get('rules')!=scope.rules
                or inputs.get('runtime')!=scope.runtime or inputs.get('baseline')!=named.get('baseline')):
            raise ValueError('Resource impact named inputs differ')
        current=self.read(inputs['current_named']);source=current['inputs']['source']
        if (source['path']!=slot or source['sha256']!=(self.files[slot].get('current') or {}).get('sha256')
                or current.get('authoritative_directory_for_archive') is not True):
            raise ValueError('Resource impact current identity differs')
        self.owner.expect(slot,source['sha256'])
        before=scope.reference_body(inputs['baseline']) if inputs['baseline'] else None
        if before and str(Path(before['source']['archive_key']).resolve())!=slot:
            raise ValueError('Resource impact baseline slot differs')
        rows=delta.get('rows');counts=delta.get('counts')
        if (not isinstance(rows,list) or len(rows)>100000 or any(not isinstance(r,dict)
                or not isinstance(r.get('canonical_path'),str) or r.get('state') not in STATES for r in rows)
                or len({r['canonical_path'] for r in rows})!=len(rows)
                or counts!={state:sum(r['state']==state for r in rows) for state in STATES}
                or counts!=named.get('counts')):
            raise ValueError('Resource impact delta inventory differs')
        return dict(comparison=named['report'],current_named=inputs['current_named'],baseline=inputs['baseline'],
            before_sha256=before['source']['sha256'] if before else None,
            complete_names=bool(before and before.get('complete_names') is True
                and not current['unmatched_csv'] and not current['path_gaps']),rows=rows)

    def dependency(self,slot,dep,material):
        row=self.files[slot];before=(row.get('baseline') or {}).get('sha256')
        current=(row.get('current') or {}).get('sha256');reasons=[]
        selected=[]
        if not current:
            state='requires_review';reasons.append('current_archive_missing')
        elif before==current:
            state='archive_unchanged'
        elif material is None:
            state='requires_review';reasons.append('named_comparison_missing')
        else:
            selected=[dict(path=r['canonical_path'],state=r['state']) for r in material['rows']
                if fnmatch.fnmatchcase(r['canonical_path'],dep['path'])]
            if material['before_sha256']!=before:reasons.append('named_baseline_differs_from_audit')
            if not dep['path'].lower().endswith('.csv'):reasons.append('named_tables_do_not_cover_resource_pattern')
            if not material['complete_names']:reasons.append('named_inventory_incomplete')
            if any(r['state']=='unknown' for r in selected):reasons.append('matching_payload_hash_unknown')
            state=('observed_changes' if any(r['state'] in ('changed','added','removed') for r in selected)
                else 'requires_review' if reasons else 'named_paths_unchanged')
        return dict(archive=slot,path_pattern=dep['path'],audit_before_sha256=before,current_sha256=current,
            comparison_before_sha256=material['before_sha256'] if material else None,state=state,
            matched_counts={s:sum(r['state']==s for r in selected) for s in STATES},paths=selected,
            review_reasons=reasons,consumer_reference_verified=False,execution_reuse_allowed=False)

    def prepare(self):
        self.owner.check(self.index,self.args)
        if self.prepared is not None:raise ValueError('Resource impact already prepared')
        for slot,row in self.files.items():
            if ((row.get('current') or {}).get('sha256') and any(fnmatch.fnmatchcase(slot.replace('\\','/'),d['archive'])
                    for c in self.contracts for d in c['resources'])):
                self.owner.expect(slot,row['current']['sha256'])
        materials={slot:self.material(slot,named) for slot,named in self.observed.items()}
        inputs=dict(recipe=RECIPE,audit=self.audit,consumers=self.contracts,rules=self.rules,runtime=self.runtime,
            observed={slot:{k:v for k,v in value.items() if k!='rows'} if value else None
                for slot,value in sorted(materials.items())})
        cache=self.root/'knowledge/resource-comparison-cache-v3'/('impact-'+hashlib.sha256(self.workflow.canonical(inputs)).hexdigest()+'.json')
        pointer=self.owner.cached(cache)
        if pointer is not None:
            body=self.read(pointer)
            if body.get('inputs')!=inputs:raise ValueError('Resource impact cache inputs differ')
            self.metrics['cache_hits']+=1
        else:
            consumers=[]
            for c in self.contracts:
                deps=[self.dependency(slot,dep,materials.get(slot)) for dep in c['resources']
                    for slot in sorted(self.files) if fnmatch.fnmatchcase(slot.replace('\\','/'),dep['archive'])]
                if not c['resources']:continue
                consumers.append(dict(id=c['id'],depends_on=c['depends_on'],resources=deps,
                    unmatched_patterns=[d for d in c['resources'] if not any(fnmatch.fnmatchcase(
                        slot.replace('\\','/'),d['archive']) for slot in self.files)],
                    review_reasons=['saved_consumer_resource_inputs_not_verified'],execution_reuse_allowed=False))
            body=dict(schema=1,recipe=RECIPE,inputs=inputs,consumers=consumers,
                summary=dict(consumers=len(consumers),archive_dependencies=sum(len(c['resources']) for c in consumers),
                    observed_changes=sum(d['state']=='observed_changes' for c in consumers for d in c['resources'])),
                validation_scope='declared_resource_diagnostics',execution_reuse_allowed=False,
                affected_plan_changed=False,profile_activated=False,live_verified=False)
            if len(self.workflow.canonical(body))>LIMIT:raise ValueError('Resource impact analysis exceeds budget')
            path=self.workflow.snapshot(self.root,'resource-impact-analyses-v1',body)
            pointer=dict(path=str(path),sha256=self.owner.digest(path));self.owner.defer(cache,pointer)
            self.metrics['analyses']+=1
        self.prepared=pointer
        return copy.deepcopy(pointer)

    def publish(self,barrier):
        if self.prepared is None or self.published or self.owner.state!='completed':
            raise ValueError('Resource impact publication needs its completed owner')
        pointer=dict(path=barrier['report'],sha256=barrier['sha256']);target=Path(pointer['path']).resolve()
        if (not isinstance(pointer['sha256'],str) or not SHA.fullmatch(pointer['sha256'])
                or target.name!='manifest.json' or target.parent.name!=pointer['sha256']
                or not target.is_relative_to(self.root/'knowledge/resource-owner-barriers-v4')):
            raise ValueError('Resource impact publication needs an immutable owner receipt')
        with target.open('rb') as stream:raw=stream.read(LIMIT+1)
        if (len(raw)>LIMIT or barrier.get('barrier_completed') is not True
                or hashlib.sha256(raw).hexdigest()!=pointer['sha256']
                or self.index.digest(self.prepared['path'])!=self.prepared['sha256']):
            raise ValueError('Resource impact publication proof changed')
        proof=json.loads(raw)
        if (proof.get('recipe')!='resource-owner-sha-v4' or proof.get('epoch')!=self.owner.epoch
                or proof.get('barrier_completed') is not True
                or any(proof['inputs'].get(str(p))!=sha for p,sha in self.owner.files.items())):
            raise ValueError('Resource impact publication barrier differs')
        body=dict(schema=1,recipe=RECIPE,analysis=self.prepared,owner_barrier=pointer,
            barrier_completed=True,execution_reuse_allowed=False,affected_plan_changed=False,
            profile_activated=False,live_verified=False)
        path=self.workflow.snapshot(self.root,'resource-impact-receipts-v1',body)
        self.published=True
        return dict(report=str(path),sha256=self.index.digest(path),analysis=copy.deepcopy(self.prepared),
            metrics=copy.deepcopy(self.metrics),execution_reuse_allowed=False,affected_plan_changed=False)
