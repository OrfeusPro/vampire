"""Shared immutable lifecycle for explicitly reviewed portable native families.

Subclasses define exact roots, transfer rules, dependencies and report coverage.
This module never discovers an arbitrary family or grants runtime admission.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=module_from_spec(spec);spec.loader.exec_module(value);return value


def digest(path):return load('update-native-contexts').digest(path)
def checked(root,pointer,category):return load('update-native-contexts').checked(root,pointer,category)
def pointer(path):return dict(path=str(path),sha256=digest(path))
def plain(context):return {k:copy.deepcopy(v) for k,v in context.items() if k not in ('exports','transfer_proof','release_id')}


def historical(knowledge,family,registry):
    api=load('native-release-registry');ranks={r['id']:r['order'] for r in registry['releases']};result=[]
    for path in (Path(knowledge)/'native-contexts').glob(family+'-*.json'):
        c=json.loads(path.read_text('utf-8'));identity=api.context_identity(path,c,registry)
        if identity and identity[1]==family:result.append((path,c,ranks[identity[0]]))
    return result


def lineage_inputs(args,path):
    """Actual context/proof/export files only, never the whole generated index."""
    exports_folder=(args.root/'ghidra/request-exports').resolve()
    folders=((HERE/'knowledge/native-contexts').resolve(),(args.root/'knowledge').resolve(),exports_folder);seen={}
    def visit(path,expected=None):
        p=Path(path).resolve()
        if not any(p.is_relative_to(folder) for folder in folders):raise ValueError('Portable lineage outside reviewed knowledge')
        actual=digest(p)
        if expected is not None and actual!=expected:raise ValueError('Portable lineage digest differs')
        if str(p) in seen:return
        if len(seen)>=512:raise ValueError('Portable lineage budget exceeded')
        seen[str(p)]=actual
        if p.is_relative_to(exports_folder):return
        def walk(item,inherited_sha=None):
            if isinstance(item,dict):
                sha=item.get('source_sha256',inherited_sha)
                if isinstance(item.get('path'),str) and isinstance(item.get('sha256'),str):visit(item['path'],item['sha256'])
                if isinstance(item.get('exports'),dict):
                    if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError('Portable export lineage has no source')
                    for run,expected in item['exports'].items():
                        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid portable export name')
                        report=args.root/'ghidra/request-exports'/sha/run/'details.json'
                        if digest(report)!=expected:raise ValueError('Portable lineage export changed')
                        seen[str(report)]=expected
                for key,child in item.items():
                    if key!='exports':walk(child,sha)
            elif isinstance(item,list):
                for child in item:walk(child,inherited_sha)
        walk(json.loads(p.read_text('utf-8')))
    visit(path);return seen


class Family:
    def contexts(self,args):
        registry=load('native-release-registry').read(args.knowledge)
        return historical(args.knowledge,self.family,registry)+self.published_contexts(args.root,registry)

    def baseline_context(self,args):
        found=self.contexts(args)
        if not found:raise ValueError('No reviewed portable baseline: '+self.family)
        return max(found,key=lambda row:(row[2],str(row[0])))[:2]

    def at(self,args,sha):
        found=[(p,c) for p,c,_ in self.contexts(args) if c['source_sha256']==sha]
        if len(found)!=1:raise ValueError('Missing or ambiguous portable dependency: '+self.family)
        return found[0]

    def published_contexts(self,root,registry,*,value=None):
        p=Path(root)/'knowledge'/self.index/'index.json'
        if value is None:
            if not p.is_file():return []
            value=json.loads(p.read_text('utf-8'))
        if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
            raise ValueError('Invalid portable publication index')
        ranks={r['source_sha256']:r['order'] for r in registry['releases']};seen=set();result=[]
        for row in value['contexts']:
            if set(row)!={'context','check','order'} or type(row['order']) is not int or row['order']<0:raise ValueError('Invalid portable publication declaration')
            c=checked(root,row['context'],'generated-native-contexts');sha=c.get('source_sha256')
            if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or c.get('family')!=self.family or c.get('layout')!=self.layout:
                raise ValueError('Portable publication source/family/layout differs')
            self.roots(c);self.report_valid(checked(root,row['check'],'native-adapter-checks'),c,row['context']['sha256']);seen.add(sha)
            result.append((Path(row['context']['path']),c,ranks.get(sha,row['order'])))
        return result

    def report_valid(self,r,c,sha):
        if (r.get('source_sha256')!=c['source_sha256'] or r.get('scope')!=self.scope or r.get('method')!='bounded_native'
                or any(r.get(k) is not False for k in ('network_used','profile_activated','runtime_activated'))
                or r.get('proof')!=c.get('transfer_proof') or r.get('context_sha256')!=sha):
            raise ValueError('Portable report provenance or scope differs')
        self.validate_report(r,c)

    def export_coverage(self,root,c,native,bindings,image):
        needed=self.roots(c);available=set();exports={}
        for part in self.export_parts(c):
            if part.get('source_sha256')!=c['source_sha256'] or Path(part['source']).resolve()!=Path(c['source']).resolve():
                raise ValueError('Portable nested export source differs')
            for run,sha in part.get('exports',{}).items():
                if run in exports and exports[run]!=sha:raise ValueError('Conflicting portable export hashes')
                exports[run]=sha
        for run,sha in exports.items():
            if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid portable export name')
            p=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json'
            if digest(p)!=sha:raise ValueError('Portable export changed')
            report=json.loads(p.read_text('utf-8'))
            if report.get('new_source_sha256',report.get('source_sha256'))!=c['source_sha256']:raise ValueError('Portable export source differs')
            for fn in report['functions']:
                at=int(fn['address'],16)
                if at not in needed or fn.get('decompilation_completed') is not True:continue
                wanted={(r['address'],r['bytes']) for r in bindings.rows(native,image,at)}
                actual={(int(r['address'],16),r['bytes'].lower()) for r in fn['instructions']}
                if wanted<=actual:available.add(at)
        if available!=needed:raise ValueError('Portable exports lack complete root coverage')

    def input_materials(self,args,path,baseline,sha):return lineage_inputs(args,path)

    def plan_inputs(self,index,args,sha):
        p,c=self.baseline_context(args)
        dependencies=self.dependencies(index,args,sha);materials=self.input_materials(args,p,c,sha)
        for item in dependencies.values():materials.update(lineage_inputs(args,item['path']))
        return dict(source=sha,family=self.family,tools=self.tools(),baseline=pointer(p),
            dependencies=dependencies,baseline_materials=materials,
            registry=digest(Path(args.knowledge)/'native-release-registry.json'))

    def planned(self,c,proof):
        artifacts={proof['baseline']['path']:proof['baseline']['sha256'],c['transfer_proof']['path']:c['transfer_proof']['sha256']}
        for item in proof['dependencies'].values():artifacts[item['path']]=item['sha256']
        return dict(state='planned',source_sha256=c['source_sha256'],context={k:v for k,v in c.items() if k!='exports'},
            exports=sorted(hex(at) for at in self.roots(c)),dependencies=self.tools(),artifacts=artifacts)

    def discover(self,index,args,sha):
        registry=load('native-release-registry').read(args.knowledge)
        existing=[c for _,c,_ in self.published_contexts(args.root,registry) if c['source_sha256']==sha]
        if existing:
            c=existing[0];self.validate(index,args,c);return self.planned(c,checked(args.root,c['transfer_proof'],self.proofs))
        p,baseline=self.baseline_context(args)
        if baseline.get('transfer_proof'):self.validate(index,args,baseline)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        self.export_coverage(args.root,baseline,native,bindings,args.source_store.image(native,baseline['source_sha256']))
        c,relocation=self.transfer(index,args,baseline,sha);self.roots(c)
        proof=load('update-native-contexts').receipt(args.root,self.proofs,dict(schema=1,adapter=self.adapter,family=self.family,scope=self.scope,
            baseline=pointer(p),dependencies=self.dependencies(index,args,sha),target=c,relocation=relocation,tools=self.tools(),runtime_activated=False))
        c=dict(c,transfer_proof=proof);return self.planned(c,checked(args.root,proof,self.proofs))

    def validate(self,index,args,c,seen=None):
        p=c['transfer_proof'];proof=checked(args.root,p,self.proofs);seen=set(seen or ())
        if p['sha256'] in seen or len(seen)>=32:raise ValueError('Portable proof cycle/depth exceeded')
        seen.add(p['sha256'])
        if (proof.get('schema')!=1 or proof.get('adapter')!=self.adapter or proof.get('family')!=self.family or proof.get('scope')!=self.scope
                or proof.get('tools')!=self.tools() or proof.get('runtime_activated') is not False or c.get('layout')!=self.layout
                or proof.get('target')!=plain(c)):
            raise ValueError('Portable proof tools/fields/layout differ')
        self.roots(c);path=Path(proof['baseline']['path']).resolve()
        if not (path.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or path.is_relative_to((args.root/'knowledge/generated-native-contexts').resolve())):
            raise ValueError('Portable baseline outside reviewed contexts')
        if digest(path)!=proof['baseline']['sha256']:raise ValueError('Portable baseline changed')
        baseline=json.loads(path.read_text('utf-8'))
        if baseline.get('transfer_proof'):self.validate(index,args,baseline,seen)
        if self.dependencies(index,args,c['source_sha256'])!=proof['dependencies']:raise ValueError('Portable dependency proof or report changed')
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        self.export_coverage(args.root,baseline,native,bindings,args.source_store.image(native,baseline['source_sha256']))
        target,relocation=self.transfer(index,args,baseline,c['source_sha256'])
        if target!=proof['target'] or relocation!=proof['relocation']:raise ValueError('Portable relocated data/calls differ')
        if c.get('exports'):self.export_coverage(args.root,c,native,bindings,args.source_store.image(native,c['source_sha256']))
        return c

    def materialize(self,index,args,sha,plan,database):
        c=copy.deepcopy(plan['context']);db=index.open_index(database);exports={};workflow=load('research-workflow')
        try:
            for at in plan['exports']:
                state=workflow.function_state(index,db,sha,at)
                if state['state']!='ready':raise ValueError('Portable target export missing: '+at)
                for row in state['variants']:
                    p=Path(row['artifact']).resolve()
                    if row['completed'] and p.is_relative_to((args.root/'ghidra/request-exports'/sha).resolve()) and p.name=='details.json':exports[p.parent.name]=digest(p)
        finally:db.close()
        c['exports']=exports;self.validate(index,args,c)
        target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',c)
        artifacts={**plan['artifacts'],target['path']:target['sha256']}
        artifacts.update({str(args.root/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
        return dict(checks=[dict(id='native-auto-'+self.family,adapter=self.adapter,family=self.family,scope=self.scope,contracts=[],
            context=target,proof=c['transfer_proof'],dependencies=self.tools(),artifacts=artifacts)],queue=[])

    def execute(self,index,args,sha,declaration):
        c=checked(args.root,declaration['context'],'generated-native-contexts')
        if (declaration.get('adapter')!=self.adapter or declaration.get('family')!=self.family or declaration.get('scope')!=self.scope
                or c['source_sha256']!=sha or declaration['dependencies']!=self.tools()):raise ValueError('Portable check declaration differs')
        def unchanged():
            if any(digest(p)!=expected for p,expected in declaration['artifacts'].items()) or self.tools()!=declaration['dependencies']:
                raise ValueError('Portable check inputs changed')
        unchanged();self.validate(index,args,c);r=load(self.verifier).verify(c,args.root)
        r.update(scope=self.scope,proof=c['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False)
        self.report_valid(r,c,declaration['context']['sha256']);unchanged()
        report=load('update-native-contexts').receipt(args.root,'native-adapter-checks',r)
        return dict(id=declaration['id'],state='passed',report=report['path'],sha256=report['sha256'],scope=self.scope,runtime_activated=False,profile_activated=False)

    def publish(self,index,args,sha,declaration,outcome):
        if outcome.get('state')!='passed':raise ValueError('Only a passed portable context can publish')
        c=checked(args.root,declaration['context'],'generated-native-contexts');self.validate(index,args,c)
        if c['source_sha256']!=sha:raise ValueError('Portable publication source differs')
        check=dict(path=outcome['report'],sha256=outcome['sha256']);self.report_valid(checked(args.root,check,'native-adapter-checks'),c,declaration['context']['sha256'])
        registry=load('native-release-registry').read(args.knowledge);self.published_contexts(args.root,registry)
        p=args.root/'knowledge'/self.index/'index.json';old=json.loads(p.read_text('utf-8')) if p.is_file() else dict(schema=1,contexts=[])
        entries=[row for row in old['contexts'] if checked(args.root,row['context'],'generated-native-contexts')['source_sha256']!=sha]
        ranks={r['source_sha256']:r['order'] for r in registry['releases']};rank=ranks.get(sha,max([r['order'] for r in registry['releases']]+[r['order'] for r in entries])+1)
        entries.append(dict(context=declaration['context'],check=check,order=rank));value=dict(schema=1,contexts=sorted(entries,key=lambda row:(row['order'],row['context']['path'])))
        self.published_contexts(args.root,registry,value=value);workflow=load('research-workflow');workflow.atomic(p,workflow.canonical(value))
        return pointer(p)
