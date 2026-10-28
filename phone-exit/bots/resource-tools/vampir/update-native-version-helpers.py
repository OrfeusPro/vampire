"""Per-role portable Version helper checks with shared transfer and dependency work."""
import copy
import hashlib
import json
from pathlib import Path
import re
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent
ADAPTER='version-helper-v1'
PROOFS='native-version-helper-proofs'
STANDALONE=('version-nm-device','version-cpu','version-windows','version-combiner','version-platform')
REQUIRES={
    'version-prepare-nm':STANDALONE[:1],
    'version-prepare-system':STANDALONE[:3],
    'version-prepare-combiner':STANDALONE[:4],
    'version-prepare-platform':STANDALONE,
}
FAMILIES=STANDALONE+tuple(REQUIRES)
ROOT_COUNTS=dict(zip(FAMILIES,(2,6,1,5,3,4,11,16,19)))
META={'schema','source_sha256','source','family','layout','exports','release_id','transfer_proof',
      'verify_whole_exports','function_budget'}
NATIVE_KEYS=('native_nm','native_system','native_combiners','native_platform')


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    m=module_from_spec(spec);spec.loader.exec_module(m);return m


def digest(path):return load('update-native-contexts').digest(path)
def checked(root,pointer,category):return load('update-native-contexts').checked(root,pointer,category)
def functional(c):return {k:copy.deepcopy(v) for k,v in c.items() if k not in META}
def base_view(c):return {
    k:copy.deepcopy(v) for k,v in c.items() if k not in META and k not in NATIVE_KEYS}
def scope(family):return 'bounded_native_'+family.replace('-','_')
def layout(family):return dict(abi='win64',family=family,executed_roots=ROOT_COUNTS[family],real_identity=False,network=False)
def rule(family):return load('version-system-transfer-rules' if family in STANDALONE[:3] else 'version-string-transfer-rules')
def clean_embed(c):return {k:copy.deepcopy(v) for k,v in c.items() if k not in ('family','layout','transfer_proof','release_id')}


def roots(family,c):
    if family in STANDALONE:
        if any(key in c for key in (*NATIVE_KEYS,'function_budget')):
            raise ValueError('Standalone Version helper cannot admit optional native scope')
        if family in STANDALONE[3:]:
            expected=({'helpers','functions','fixtures','call_sites'} if family=='version-combiner' else
                {'helpers','selector','store','lookup','cache','factory','descriptor','fixtures','call_sites'})
            if set(functional(c))!=expected or c.get('verify_whole_exports') is not True:
                raise ValueError('Standalone Version string helper fields/export scope differ')
        return rule(family).roots(family,c)
    expected=REQUIRES[family];allowed={'native_nm'}
    if len(expected)>=3:allowed.add('native_system')
    if len(expected)>=4:allowed.add('native_combiners')
    if len(expected)>=5:allowed.add('native_platform')
    if {key for key in NATIVE_KEYS if key in c}!=allowed:raise ValueError('Version integration helper scope differs')
    result={int(c[k],16) for k in ('prepare','constructor')}
    nm=c['native_nm'];result.update(int(nm[k],16) for k in ('wrapper','getter'))
    if 'native_system' in c:
        # Legacy embedded descriptors rely on the outer complete export guard.
        result.update(rule('version-cpu').roots('version-cpu',dict(c['native_system']['cpu'],verify_whole_exports=True)))
        result.update(rule('version-windows').roots('version-windows',dict(c['native_system']['windows'],verify_whole_exports=True)))
    if 'native_combiners' in c:result.update(rule('version-combiner').roots('version-combiner',c['native_combiners']))
    if 'native_platform' in c:result.update(rule('version-platform').roots('version-platform',c['native_platform']))
    budget=c.get('function_budget',16)
    if type(budget) is not int or len(result)!=ROOT_COUNTS[family] or budget!=(19 if family==FAMILIES[-1] else 16):
        raise ValueError('Version integration root alias/budget differs')
    delegated={'provider':int(nm['wrapper'],16)}
    embedded=[]
    if 'native_system' in c:
        cpu,windows=c['native_system']['cpu'],c['native_system']['windows'];embedded.extend((cpu,windows))
        delegated.update(first_text=int(cpu['functions']['formatter'],16),suffix=int(windows['function'],16))
    if 'native_combiners' in c:
        combiners=c['native_combiners'];embedded.append(combiners)
        delegated.update(combine_first=int(combiners['functions']['first'],16),combine_second=int(combiners['functions']['second'],16))
    if 'native_platform' in c:
        platform=c['native_platform'];embedded.append(platform)
        delegated.update(selector=int(platform['selector'],16),context_store=int(platform['store'],16),context_value=int(platform['lookup'],16))
    if any(int(c['fixtures'].get(key,'0'),16)!=at for key,at in delegated.items()):
        raise ValueError('Version integration delegated caller role differs')
    active={int(at,16) for key,at in c['fixtures'].items() if key not in delegated}
    active.update((int(c['send'],16),int(c['helpers']['memcpy'],16)))
    for item in embedded:active.update(int(at,16) for at in item['fixtures'].values())
    if active&result:raise ValueError('Version integration fixture shadows an executed root')
    return result


def export_coverage(root,c,family,native,bindings,image):
    needed=roots(family,c);available=set();exports=dict(c.get('exports',{}))
    def merge(items):
        for run,expected in items.items():
            if run in exports and exports[run]!=expected:raise ValueError('Conflicting Version helper export hashes')
            exports[run]=expected
    for key in NATIVE_KEYS:
        part=c.get(key,{})
        if key=='native_system':
            for item in part.values():merge(item.get('exports',{}))
        else:merge(part.get('exports',{}))
    for run,sha in exports.items():
        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid Version helper export name')
        path=Path(root)/'ghidra/request-exports'/c['source_sha256']/run/'details.json'
        if digest(path)!=sha:raise ValueError('Version helper export changed')
        report=json.loads(path.read_text('utf-8'))
        if report.get('new_source_sha256',report.get('source_sha256'))!=c['source_sha256']:raise ValueError('Version helper export source differs')
        for fn in report['functions']:
            at=int(fn['address'],16)
            if at not in needed or fn.get('decompilation_completed') is not True:continue
            wanted={(r['address'],r['bytes']) for r in bindings.rows(native,image,at)}
            actual={(int(r['address'],16),r['bytes'].lower()) for r in fn['instructions']}
            if wanted<=actual:available.add(at)
    if available!=needed:raise ValueError('Version helper exports lack complete root coverage')


def report_valid(family,r,c,sha):
    if (r.get('source_sha256')!=c['source_sha256'] or r.get('scope')!=scope(family) or r.get('method')!='bounded_native'
            or any(r.get(k) is not False for k in ('network_used','profile_activated','runtime_activated'))
            or r.get('proof')!=c.get('transfer_proof') or r.get('context_sha256')!=sha):
        raise ValueError('Version helper report provenance/scope differs')
    load('version-helper-case-contracts').validate_report(family,r)


def historical(knowledge,family,registry):
    api=load('native-release-registry');result=[];ranks={r['id']:r['order'] for r in registry['releases']}
    for p in (Path(knowledge)/'native-contexts').glob(family+'-*.json'):
        c=json.loads(p.read_text('utf-8'));identity=api.context_identity(p,c,registry)
        if identity and identity[1]==family:result.append((p,c,ranks[identity[0]]))
    return result


def base_at(root,knowledge,sha):
    api=load('update-native-version-prepare');registry=load('native-release-registry').read(knowledge)
    found=historical(knowledge,'version-prepare',registry)+api.published_contexts(root,registry)
    found=[(p,c) for p,c,_ in found if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('Missing or ambiguous source-specific base Version preparation')
    return found[0]


def memo(args):
    old=getattr(args,'_version_helper_memo',None)
    if old is None or old['store'] is not args.source_store:
        old=dict(store=args.source_store,values={});args._version_helper_memo=old
    return old['values']


def lineage_inputs(args,context_path):
    """Pin only this role's existing proof chain, including its actual exports."""
    allowed=((HERE/'knowledge/native-contexts').resolve(),(args.root/'knowledge').resolve())
    seen={}
    def visit(path,expected=None):
        p=Path(path).resolve()
        if not any(p.is_relative_to(folder) for folder in allowed):raise ValueError('Version helper lineage outside reviewed knowledge')
        actual=digest(p)
        if expected is not None and actual!=expected:raise ValueError('Version helper lineage digest differs')
        if str(p) in seen:return
        if len(seen)>=512:raise ValueError('Version helper lineage budget exceeded')
        seen[str(p)]=actual
        value=json.loads(p.read_text('utf-8'))
        def walk(item,inherited_sha=None):
            if isinstance(item,dict):
                sha=item.get('source_sha256',inherited_sha)
                if isinstance(item.get('path'),str) and isinstance(item.get('sha256'),str):
                    visit(item['path'],item['sha256'])
                if isinstance(item.get('exports'),dict):
                    if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError('Version helper export lineage has no source')
                    for run,expected in item['exports'].items():
                        if Path(run).name!=run or not run.startswith('run-'):raise ValueError('Invalid Version helper lineage export')
                        report=args.root/'ghidra/request-exports'/sha/run/'details.json'
                        if digest(report)!=expected:raise ValueError('Version helper lineage export changed')
                        seen[str(report)]=expected
                for key,child in item.items():
                    if key!='exports':walk(child,sha)
            elif isinstance(item,list):
                for child in item:walk(child,inherited_sha)
        walk(value)
    visit(context_path)
    return seen


def seed(index,args,baseline_sha,target_sha):
    base_api=load('update-native-version-prepare')
    old_path,old=base_at(args.root,args.knowledge,baseline_sha);target_path,target=base_at(args.root,args.knowledge,target_sha)
    if 'transfer_proof' not in target:raise ValueError('Target Version preparation must have a portable proof')
    key=('seed',digest(old_path),digest(target_path),json.dumps(base_api.tools(),sort_keys=True))
    cache=memo(args)
    if key not in cache:
        if old.get('transfer_proof'):base_api.validate(index,args,old)
        base_api.validate(index,args,target)
        proof=checked(args.root,target['transfer_proof'],'native-version-prepare-proofs')
        archive=checked(args.root,proof['archive'],'generated-native-contexts')
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline_sha);after=args.source_store.image(native,target_sha)
        base_api.export_coverage(args.root,old,native,bindings,before)
        current,relocation=base_api.transfer(native,bindings,before,after,old,archive)
        if functional(current)!=functional(target):raise ValueError('Version helper base caller differs from published target')
        cache[key]=(current,{int(a,16):int(b,16) for a,b in relocation['mapping'].items()},
            dict(baseline_base=dict(path=str(old_path),sha256=digest(old_path)),target_base=dict(path=str(target_path),sha256=digest(target_path))))
    return copy.deepcopy(cache[key])


class Adapter:
    def __init__(self,family):
        if family not in FAMILIES:raise ValueError('Unreviewed Version helper family')
        self.family=family;self.index='generated-version-helpers/'+family

    def tools(self):
        groups=(self.family,) if self.family in STANDALONE else REQUIRES[self.family]
        result=load('update-native-version-prepare').tools()
        for family in groups:result.update(rule(family).tools())
        names=['update-native-version-helpers.py','version-helper-case-contracts.py',
            load('version-helper-case-contracts').verifier(self.family)+'.py']
        if self.family in REQUIRES:
            if len(groups)>=3:names.append('version-system-fixtures.py')
            if len(groups)>=4:names.append('version-combiner-fixtures.py')
            if len(groups)>=5:names.append('version-platform-fixtures.py')
        elif self.family=='version-combiner':names.append('version-combiner-fixtures.py')
        return {**result,**{str(HERE/n):digest(HERE/n) for n in names}}

    def published_contexts(self,root,registry,*,value=None):
        p=Path(root)/'knowledge'/self.index/'index.json'
        if value is None:
            if not p.is_file():return []
            value=json.loads(p.read_text('utf-8'))
        if value.get('schema')!=1 or not isinstance(value.get('contexts'),list) or len(value['contexts'])>4096:
            raise ValueError('Invalid generated Version helper index')
        ranks={r['source_sha256']:r['order'] for r in registry['releases']};seen=set();result=[]
        for row in value['contexts']:
            if set(row)!={'context','check','order'} or type(row['order']) is not int or row['order']<0:raise ValueError('Invalid Version helper declaration')
            c=checked(root,row['context'],'generated-native-contexts');sha=c.get('source_sha256')
            if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or sha in seen or c.get('family')!=self.family or c.get('layout')!=layout(self.family):
                raise ValueError('Invalid Version helper source/family/layout')
            report_valid(self.family,checked(root,row['check'],'native-adapter-checks'),c,row['context']['sha256']);seen.add(sha)
            result.append((Path(row['context']['path']),c,ranks.get(sha,row['order'])))
        return result

    def contexts(self,args):
        registry=load('native-release-registry').read(args.knowledge)
        return historical(args.knowledge,self.family,registry)+self.published_contexts(args.root,registry)

    def baseline_context(self,args):
        found=self.contexts(args)
        if not found:raise ValueError('No reviewed Version helper baseline: '+self.family)
        return max(found,key=lambda row:(row[2],str(row[0])))[:2]

    def at(self,args,sha):
        found=[(p,c) for p,c,_ in self.contexts(args) if c['source_sha256']==sha]
        if len(found)!=1:raise ValueError('Missing/ambiguous Version helper dependency '+self.family)
        return found[0]

    def dependencies(self,args,sha):
        result={'base':base_at(args.root,args.knowledge,sha)}
        if self.family in REQUIRES:
            for family in REQUIRES[self.family]:
                p,c=Adapter(family).at(args,sha)
                if not c.get('transfer_proof'):raise ValueError('Target helper requires portable proof: '+family)
                result[family]=(p,c)
        return result

    def plan_inputs(self,index,args,sha):
        p,base=self.baseline_context(args);deps=self.dependencies(args,sha)
        materials=lineage_inputs(args,p)
        base_path,_=base_at(args.root,args.knowledge,base['source_sha256']);materials.update(lineage_inputs(args,base_path))
        if self.family in REQUIRES:
            for family in REQUIRES[self.family]:
                old_path,_=Adapter(family).at(args,base['source_sha256']);materials.update(lineage_inputs(args,old_path))
        return dict(source=sha,family=self.family,tools=self.tools(),baseline=dict(path=str(p),sha256=digest(p)),
            dependencies={key:dict(path=str(p),sha256=digest(p)) for key,(p,_) in deps.items()},
            baseline_materials=materials,registry=digest(Path(args.knowledge)/'native-release-registry.json'))

    def transfer(self,index,args,baseline,sha):
        roots(self.family,baseline)
        current,mapping,base_proof=seed(index,args,baseline['source_sha256'],sha)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha)
        if self.family in STANDALONE:
            result,detail=rule(self.family).transfer(self.family,native,bindings,before,after,baseline,mapping)
        else:
            old_base_path,old_base=base_at(args.root,args.knowledge,baseline['source_sha256'])
            if base_view(baseline)!=functional(old_base):raise ValueError('Version integration baseline base fields differ')
            dependencies=self.dependencies(args,sha);parts={};detail={}
            for family in REQUIRES[self.family]:
                api=Adapter(family);p,old=api.at(args,baseline['source_sha256']);target_path,target=dependencies[family]
                api.validate(index,args,target)
                candidate,item=rule(family).transfer(family,native,bindings,before,after,old,mapping)
                if functional(candidate)!=functional(target):raise ValueError('Version integration helper differs from target proof: '+family)
                parts[family]=clean_embed(target);detail[family]=item
                detail[family]['baseline']=dict(path=str(p),sha256=digest(p))
                detail[family]['target']=dict(path=str(target_path),sha256=digest(target_path))
            nm_old=Adapter('version-nm-device').at(args,baseline['source_sha256'])[1]
            if {k:baseline['native_nm'].get(k) for k in ('wrapper','getter','cache','log_level','log_enabled')}!={k:nm_old[k] for k in ('wrapper','getter','cache','log_level','log_enabled')}:
                raise ValueError('Version integration baseline NM roles differ')
            for family in REQUIRES[self.family][1:]:
                old=Adapter(family).at(args,baseline['source_sha256'])[1]
                embedded=baseline['native_system'][family.removeprefix('version-')] if family in STANDALONE[1:3] else baseline['native_'+('combiners' if family=='version-combiner' else 'platform')]
                if functional(embedded)!=functional(old):raise ValueError('Version integration baseline helper fields differ')
            result=copy.deepcopy(current);nm=parts['version-nm-device']
            result['native_nm']={k:copy.deepcopy(nm[k]) for k in ('wrapper','getter','cache','log_level','log_enabled','exports')}
            if len(parts)>=3:result['native_system']={key:parts['version-'+key] for key in ('cpu','windows')}
            if len(parts)>=4:result['native_combiners']=parts['version-combiner']
            if len(parts)>=5:result['native_platform']=parts['version-platform'];result['function_budget']=19
        for key in META:result.pop(key,None)
        result.update(schema=1,family=self.family,source_sha256=sha,source=str(args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'),
            layout=layout(self.family),verify_whole_exports=True)
        if self.family==FAMILIES[-1]:result['function_budget']=19
        if len(roots(self.family,result))!=ROOT_COUNTS[self.family]:raise ValueError('Version helper root scope differs')
        return result,dict(base=base_proof,details=detail,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})

    def planned(self,c,proof):
        artifacts={proof['baseline']['path']:proof['baseline']['sha256'],c['transfer_proof']['path']:c['transfer_proof']['sha256']}
        for item in proof['dependencies'].values():artifacts[item['path']]=item['sha256']
        return dict(state='planned',source_sha256=c['source_sha256'],context={k:v for k,v in c.items() if k!='exports'},
            exports=sorted(hex(at) for at in roots(self.family,c)),dependencies=self.tools(),artifacts=artifacts)

    def discover(self,index,args,sha):
        registry=load('native-release-registry').read(args.knowledge)
        existing=[c for _,c,_ in self.published_contexts(args.root,registry) if c['source_sha256']==sha]
        if existing:
            c=existing[0];self.validate(index,args,c);return self.planned(c,checked(args.root,c['transfer_proof'],PROOFS))
        p,baseline=self.baseline_context(args)
        if baseline.get('transfer_proof'):self.validate(index,args,baseline)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        export_coverage(args.root,baseline,self.family,native,bindings,args.source_store.image(native,baseline['source_sha256']))
        c,relocation=self.transfer(index,args,baseline,sha)
        deps={key:dict(path=str(p),sha256=digest(p)) for key,(p,_) in self.dependencies(args,sha).items()}
        proof=load('update-native-contexts').receipt(args.root,PROOFS,dict(schema=1,adapter=ADAPTER,family=self.family,scope=scope(self.family),
            baseline=dict(path=str(p),sha256=digest(p)),dependencies=deps,target=c,relocation=relocation,tools=self.tools(),runtime_activated=False))
        c=dict(c,transfer_proof=proof);return self.planned(c,checked(args.root,proof,PROOFS))

    def validate(self,index,args,c,seen=None):
        pointer=c['transfer_proof'];proof=checked(args.root,pointer,PROOFS);seen=set(seen or ())
        if pointer['sha256'] in seen or len(seen)>=32:raise ValueError('Version helper proof cycle/depth exceeded')
        seen.add(pointer['sha256'])
        if (proof.get('schema')!=1 or proof.get('adapter')!=ADAPTER or proof.get('family')!=self.family or proof.get('scope')!=scope(self.family)
                or proof.get('tools')!=self.tools() or proof.get('runtime_activated') is not False or c.get('layout')!=layout(self.family)
                or proof.get('target')!={k:v for k,v in c.items() if k not in ('exports','transfer_proof','release_id')}):
            raise ValueError('Version helper proof tools/fields/layout differ')
        p=Path(proof['baseline']['path']).resolve()
        if not (p.is_relative_to((HERE/'knowledge/native-contexts').resolve()) or p.is_relative_to((args.root/'knowledge/generated-native-contexts').resolve())):
            raise ValueError('Version helper baseline outside reviewed contexts')
        if digest(p)!=proof['baseline']['sha256']:raise ValueError('Version helper baseline changed')
        baseline=json.loads(p.read_text('utf-8'))
        if baseline.get('transfer_proof'):self.validate(index,args,baseline,seen)
        expected={key:dict(path=str(p),sha256=digest(p)) for key,(p,_) in self.dependencies(args,c['source_sha256']).items()}
        if expected!=proof['dependencies']:raise ValueError('Version helper dependency index differs')
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        export_coverage(args.root,baseline,self.family,native,bindings,args.source_store.image(native,baseline['source_sha256']))
        target,relocation=self.transfer(index,args,baseline,c['source_sha256'])
        if target!=proof['target'] or relocation!=proof['relocation']:raise ValueError('Version helper relocated inputs/calls differ')
        if c.get('exports'):export_coverage(args.root,c,self.family,native,bindings,args.source_store.image(native,c['source_sha256']))
        return c

    def materialize(self,index,args,sha,plan,database):
        c=copy.deepcopy(plan['context']);db=index.open_index(database);exports={};workflow=load('research-workflow')
        try:
            for at in plan['exports']:
                state=workflow.function_state(index,db,sha,at)
                if state['state']!='ready':raise ValueError('Version helper target export missing: '+at)
                for row in state['variants']:
                    p=Path(row['artifact']).resolve()
                    if row['completed'] and p.is_relative_to((args.root/'ghidra/request-exports'/sha).resolve()) and p.name=='details.json':exports[p.parent.name]=digest(p)
        finally:db.close()
        c['exports']=exports;self.validate(index,args,c)
        target=load('update-native-contexts').receipt(args.root,'generated-native-contexts',c)
        artifacts={**plan['artifacts'],target['path']:target['sha256']}
        artifacts.update({str(args.root/'ghidra/request-exports'/sha/run/'details.json'):expected for run,expected in exports.items()})
        return dict(checks=[dict(id='native-auto-'+self.family,adapter=ADAPTER,family=self.family,scope=scope(self.family),contracts=[],
            context=target,proof=c['transfer_proof'],dependencies=self.tools(),artifacts=artifacts)],queue=[])

    def execute(self,index,args,sha,declaration):
        c=checked(args.root,declaration['context'],'generated-native-contexts')
        if (declaration.get('adapter')!=ADAPTER or declaration.get('family')!=self.family or declaration.get('scope')!=scope(self.family)
                or c['source_sha256']!=sha or declaration['dependencies']!=self.tools()):raise ValueError('Version helper check declaration differs')
        for p,expected in declaration['artifacts'].items():
            if digest(p)!=expected:raise ValueError('Version helper check artifact changed')
        self.validate(index,args,c)
        r=load(load('version-helper-case-contracts').verifier(self.family)).verify(c,args.root)
        r.update(scope=scope(self.family),proof=c['transfer_proof'],context_sha256=declaration['context']['sha256'],runtime_activated=False)
        report_valid(self.family,r,c,declaration['context']['sha256'])
        for p,expected in declaration['artifacts'].items():
            if digest(p)!=expected:raise ValueError('Version helper artifact changed during execution')
        if declaration['dependencies']!=self.tools():raise ValueError('Version helper tools changed during execution')
        p=load('update-native-contexts').receipt(args.root,'native-adapter-checks',r)
        return dict(id=declaration['id'],state='passed',report=p['path'],sha256=p['sha256'],scope=scope(self.family),runtime_activated=False,profile_activated=False)

    def publish(self,index,args,sha,declaration,outcome):
        if outcome.get('state')!='passed':raise ValueError('Only a passed Version helper context can publish')
        c=checked(args.root,declaration['context'],'generated-native-contexts');self.validate(index,args,c)
        if c['source_sha256']!=sha:raise ValueError('Version helper publication source differs')
        check=dict(path=outcome['report'],sha256=outcome['sha256']);report_valid(self.family,checked(args.root,check,'native-adapter-checks'),c,declaration['context']['sha256'])
        registry=load('native-release-registry').read(args.knowledge);self.published_contexts(args.root,registry)
        p=args.root/'knowledge'/self.index/'index.json';old=json.loads(p.read_text('utf-8')) if p.is_file() else dict(schema=1,contexts=[])
        entries=[row for row in old['contexts'] if checked(args.root,row['context'],'generated-native-contexts')['source_sha256']!=sha]
        ranks={r['source_sha256']:r['order'] for r in registry['releases']};rank=ranks.get(sha,max([r['order'] for r in registry['releases']]+[r['order'] for r in entries])+1)
        entries.append(dict(context=declaration['context'],check=check,order=rank));value=dict(schema=1,contexts=sorted(entries,key=lambda row:(row['order'],row['context']['path'])))
        self.published_contexts(args.root,registry,value=value);w=load('research-workflow');w.atomic(p,w.canonical(value))
        return dict(path=str(p),sha256=digest(p))


def select(family):return Adapter(family)
