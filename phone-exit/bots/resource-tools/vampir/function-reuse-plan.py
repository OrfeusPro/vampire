"""Inventory reviewed native contexts and verify bounded dependency-closed function batches.

This does not transfer semantic suites, capabilities, profiles or live readiness.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
SOURCES={'11316':'d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960',
         '11318':'d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'}
ADDRESS=re.compile(r'0x[0-9a-f]+')
SHA=re.compile(r'[0-9a-f]{64}')
WINDOW=65536
MAX_BATCH=128
MAX_CONTEXTS=512
MAX_ROLES=4096


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def declarations(context):
    result={}
    for group in ('functions','bindings'):
        values=context.get(group,{})
        if isinstance(values,list):values={str(i):v for i,v in enumerate(values)}
        if not isinstance(values,dict):continue
        for role,address in values.items():
            if isinstance(address,str) and ADDRESS.fullmatch(address):result[group+':'+str(role)]=address
    # Explicit executable fields used by the preparation contexts; arbitrary
    # top-level globals, table pointers, literals and fixture entries are excluded.
    for role in ('prepare','constructor','reader','handler','producer'):
        address=context.get(role)
        if isinstance(address,str) and ADDRESS.fullmatch(address):result[role]=address
    return result


def inventory(root,knowledge):
    root,knowledge=Path(root),Path(knowledge)
    contexts=[];exports={};sources={};queue=[]
    folder=knowledge/'native-contexts'
    paths=sorted(p for p in folder.glob('*.json') if any(p.stem.endswith('-'+v) for v in SOURCES))
    if len(paths)>MAX_CONTEXTS:raise ValueError('Function context budget exceeded')
    for path in paths:
        context_raw=path.read_bytes();context=json.loads(context_raw.decode('utf-8'));roles=declarations(context)
        if not roles:continue
        version=path.stem.rsplit('-',1)[1];expected=SOURCES[version];actual=context.get('source_sha256')
        if actual!=expected:
            queue.append(dict(context=str(path),reason='context_source_not_verified',source_sha256=actual));continue
        if expected not in sources:
            source=root/'client-code-snapshots'/expected/'ProjectRED-Win64-Shipping.exe'
            if digest(source)!=expected:raise ValueError('Context baseline source changed')
            sources[expected]=str(source)
        declared=context.get('exports')
        if not isinstance(declared,dict) or not declared:
            queue.append(dict(context=str(path),reason='context_exports_not_declared',source_sha256=expected));continue
        material=[]
        for run,sha in sorted(declared.items()):
            if not isinstance(run,str) or Path(run).name!=run or not run.startswith('run-') or not isinstance(sha,str) or not SHA.fullmatch(sha):
                raise ValueError('Invalid explicit context export')
            export=root/'ghidra/request-exports'/expected/run/'details.json'
            if str(export) not in exports:
                export_raw=export.read_bytes()
                if hashlib.sha256(export_raw).hexdigest()!=sha:raise ValueError('Context export changed: '+run)
                report=json.loads(export_raw.decode('utf-8'))
                if report.get('new_source_sha256',report.get('source_sha256'))!=expected:
                    raise ValueError('Context export source differs')
                exports[str(export)]=dict(sha256=sha,report=report,source_sha256=expected)
            elif exports[str(export)]['sha256']!=sha:raise ValueError('Conflicting context export digest')
            material.append(str(export))
        contexts.append(dict(path=str(path),sha256=hashlib.sha256(context_raw).hexdigest(),family=path.stem.rsplit('-',1)[0],
            version=version,source_sha256=expected,roles=roles,exports=material))
    if sum(len(c['roles']) for c in contexts)>MAX_ROLES:raise ValueError('Function role budget exceeded')
    return contexts,exports,sources,queue


def inputs(root,knowledge):
    contexts,exports,sources,queue=inventory(root,knowledge)
    # Include all eligible context files, even rejected declarations, so correcting
    # an unknown source/export declaration invalidates the cached stage.
    files=sorted(p for p in (Path(knowledge)/'native-contexts').glob('*.json') if any(p.stem.endswith('-'+v) for v in SOURCES))
    tools=('function-reuse-plan.py','update-bindings.py','build-native-entry-code.py','extract-native-enums.py','research-workflow.py','update-contracts.py')
    runtime=load('build-native-entry-code').capstone
    import importlib.metadata
    distribution=importlib.metadata.distribution('capstone')
    record=distribution.read_text('RECORD')
    if runtime.__version__!='5.0.6' or distribution.version!='5.0.6' or not record:raise ValueError('Pinned function catalog runtime required')
    return dict(present=bool(files),approved_data_sha256=digest(Path(knowledge)/'update-contracts.json') if (Path(knowledge)/'update-contracts.json').is_file() else None,capstone_version=runtime.__version__,capstone_record_sha256=hashlib.sha256(record.encode()).hexdigest(),contexts={str(p):digest(p) for p in files},
        exports={p:v['sha256'] for p,v in exports.items()},sources={p:digest(path) for p,path in sources.items()},
        tools={name:digest(HERE/name) for name in tools},queue=queue)


def choose(contexts):
    """Newest declaration per family/role; deduplicate the source/address work."""
    latest={};all_records={}
    for context in contexts:
        for role,address in context['roles'].items():
            item=dict(context=context['path'],context_sha256=context['sha256'],family=context['family'],role=role,
                version=context['version'],source_sha256=context['source_sha256'],address=address,exports=context['exports'])
            record=all_records.setdefault((item['source_sha256'],address),dict(source_sha256=item['source_sha256'],address=address,aliases=[],exports=set()))
            record['aliases'].append({k:item[k] for k in ('context','context_sha256','family','role','version')})
            record['exports'].update(context['exports'])
            identity=(context['family'],role)
            if identity not in latest or int(item['version'])>int(latest[identity]['version']):latest[identity]=item
    selected={(item['source_sha256'],item['address']) for item in latest.values()}
    return all_records,selected,latest


def export_covers(record,rows,exports):
    expected={(row['address'],row['bytes'].lower()) for row in rows}
    for path in sorted(record['exports']):
        report=exports[path]['report']
        found=[f for f in report.get('functions',[]) if f.get('address')==record['address']]
        for function in found:
            actual={(int(row['address'],16),row['bytes'].lower()) for row in function.get('instructions',[])}
            if expected<=actual:return path
    return None


def approved_data(knowledge):
    path=Path(knowledge)/'update-contracts.json'
    if not path.is_file():return {}
    result={}
    for contract in json.loads(path.read_text('utf-8')).get('contracts',[]):
        for recipe in contract.get('recipes',[]):
            if recipe.get('method') not in ('prefix','closed_shape') or not recipe.get('data'):continue
            sha,address=recipe.get('baseline_sha256'),recipe.get('baseline_address')
            if contract.get('bindings',{}).get(sha,{}).get(recipe.get('key'))!=address:continue
            key=(sha,address)
            data=recipe['data']
            if key in result and result[key]!=data:raise ValueError('Conflicting approved data declarations')
            result[key]=data
    return result


def build(root,knowledge,target_sha,*,execute=True):
    root,knowledge=Path(root),Path(knowledge)
    bindings,native=load('update-bindings'),load('build-native-entry-code')
    identity=inputs(root,knowledge)
    contexts,exports,sources,queue=inventory(root,knowledge)
    if (any(identity['contexts'].get(c['path'])!=c['sha256'] for c in contexts)
            or identity['exports']!={p:v['sha256'] for p,v in exports.items()}):
        raise ValueError('Function inventory changed during planning')
    target=bindings.source(None,root,target_sha)
    records,selected,latest=choose(contexts)
    identity['target_sha256']=target_sha
    identity['approved_data_sha256']=digest(knowledge/'update-contracts.json') if (knowledge/'update-contracts.json').is_file() else None
    images={};decoded={};data_specs=approved_data(knowledge)
    def image(sha):
        if sha not in images:images[sha]=native.Image(Path(sources[sha]).read_bytes())
        return images[sha]
    def inspect(key):
        if key in decoded:return decoded[key]
        record=records[key];sha,address=key;address=int(address,16);im=image(sha)
        result=dict(key='f-'+hex(address)[2:],baseline_sha256=sha,baseline_address=hex(address),
            method='closed_shape',search_window=WINDOW,calls={},data=data_specs.get(key,{}))
        reasons=[];dependencies=[]
        try:
            rows=bindings.rows(native,im,address)
            covered=export_covers(record,rows,exports)
            if not covered:reasons.append('explicit_export_does_not_cover_root')
            else:record['covering_export']=dict(path=covered,sha256=exports[covered]['sha256'])
            locations={row['address'] for row in rows}
            for row in rows:
                offset=str(row['address']-address)
                if row['call'] or row['branch']:
                    target=row['direct_target']
                    if target in locations:continue
                    if not row['call'] or target is None:
                        reasons.append('indirect_or_external_branch_at_'+hex(row['address']));continue
                    dep=(sha,hex(target))
                    if dep not in records:
                        reasons.append('undeclared_callee_'+hex(target));continue
                    result['calls'][offset]='f-'+hex(target)[2:];dependencies.append(dep)
                if row['rip_references'] and offset not in result['data']:
                    reasons.append('undeclared_data_at_'+hex(row['address']))
            # Exercise source declaration validation even before target matching.
            if not reasons:
                baseline={result['key']:result['baseline_address']}
                baseline.update({'f-'+address[2:]:address for sha2,address in records if sha2==sha})
                bindings.closed_shape(native,im,address,baseline,result)
        except (ValueError,KeyError,StopIteration) as error:reasons.append('source_boundary_rejected: '+str(error))
        decoded[key]=(result,sorted(set(dependencies)),sorted(set(reasons)))
        return decoded[key]
    pending=list(sorted(selected))
    while pending:
        key=pending.pop();recipe,deps,reasons=inspect(key)
        for dependency in deps:
            if dependency not in selected:selected.add(dependency);pending.append(dependency)
        if len(selected)>MAX_ROLES:raise ValueError('Expanded function dependency budget exceeded')
    rejected={key:list(inspect(key)[2]) for key in selected if inspect(key)[2]}
    changed=True
    while changed:
        changed=False
        for key in selected-set(rejected):
            blocked=[address for sha,address in inspect(key)[1] if (sha,address) in rejected]
            if blocked:rejected[key]=['callee_not_closed: '+', '.join(blocked)];changed=True
    eligible=selected-set(rejected)
    # Keep each undirected dependency component together; never split a closure
    # across resolver contracts or silently assume an oversized component.
    adjacency={key:set() for key in eligible}
    for key in eligible:
        for dep in inspect(key)[1]:
            adjacency[key].add(dep);adjacency[dep].add(key)
    components=[];remaining=set(eligible)
    while remaining:
        first=min(remaining);component={first};pending=[first];remaining.remove(first)
        while pending:
            key=pending.pop()
            for dep in adjacency[key]&remaining:remaining.remove(dep);component.add(dep);pending.append(dep)
        if len(component)>MAX_BATCH:
            for key in component:rejected[key]=['dependency_component_exceeds_128']
        else:components.append(sorted(component))
    batches=[]
    for sha in sorted(sources):
        current=[]
        for component in (c for c in components if c[0][0]==sha):
            if len(current)+len(component)>MAX_BATCH:batches.append(current);current=[]
            current.extend(component)
        if current:batches.append(current)
    contracts=[];verifications=[]
    index=SimpleNamespace(extension=lambda name:load(name))
    for number,batch in enumerate(batches):
        baseline=batch[0][0]
        recipes=[inspect(key)[0] for key in batch]
        contract=dict(id='function-batch-'+str(number),bindings={baseline:{r['key']:r['baseline_address'] for r in recipes}},recipes=recipes)
        contracts.append(contract)
        if execute:
            outcome=bindings.resolve(index,SimpleNamespace(root=root),dict(contracts=[contract]),target_sha,[])['contracts'][contract['id']]
            verifications.append(dict(id=contract['id'],baseline_sha256=baseline,**outcome))
    for key in sorted(rejected):
        sha,address=key;queue.append(dict(source_sha256=sha,address=address,aliases=records[key]['aliases'],reasons=rejected[key]))
    for key in sorted(selected):
        record=records[key];record['exports']=sorted(record['exports']);record['dependency_added']=not any(
            item['source_sha256']==key[0] and item['address']==key[1] for item in latest.values())
    verified=sum(len(v['closed_shapes']) for v in verifications)
    planned=sum(len(c['recipes']) for c in contracts)
    current_data=digest(knowledge/'update-contracts.json') if (knowledge/'update-contracts.json').is_file() else None
    if current_data!=identity['approved_data_sha256']:raise ValueError('Approved data recipes changed during planning')
    for name,sha in identity['tools'].items():
        if digest(HERE/name)!=sha:raise ValueError('Function planner tool changed during planning')
    import importlib.metadata
    runtime=importlib.metadata.distribution('capstone')
    if hashlib.sha256((runtime.read_text('RECORD') or '').encode()).hexdigest()!=identity['capstone_record_sha256']:
        raise ValueError('Function planner runtime changed during planning')
    for name in identity['contexts']:
        if digest(name)!=identity['contexts'][name]:raise ValueError('Function contexts changed during planning')
    current_files={str(p) for p in (knowledge/'native-contexts').glob('*.json') if any(p.stem.endswith('-'+v) for v in SOURCES)}
    if current_files!=set(identity['contexts']):raise ValueError('Function context inventory changed during planning')
    for name,sha in identity['exports'].items():
        if digest(name)!=sha:raise ValueError('Function exports changed during planning')
    for sha,path in sources.items():
        if digest(path)!=sha:raise ValueError('Function baseline changed during planning')
    if hashlib.sha256(bindings.source(None,root,target_sha)).hexdigest()!=target_sha:raise ValueError('Function target changed')
    summary=dict(contexts=len(contexts),roles=sum(len(c['roles']) for c in contexts),functions=len(selected),
        baseline_counts={sha:sum(key[0]==sha for key in selected) for sha in sorted(sources)},
        planned=planned,verified=verified,requires_review=len(selected)-verified,executed=execute)
    report=dict(schema=1,identity=identity,target_sha256=target_sha,summary=summary,
        inventory=[records[key] for key in sorted(selected)],contracts=contracts,verification=verifications,queue=queue,
        scope='function_only',runtime_activated=False,profile_activated=False,
        limits=['Newest explicit context role selected per family; baseline 1.13.16 is used directly when no 1.13.18 declaration exists.',
            'Unwind roots and explicit export instructions are verified. Undeclared data/callees, leaves and indirect/tail branches remain queued.',
            'Only bounded declared instruction/callee/data equivalence is verified; native semantic suites and runtime admission remain separate.'])
    return report


def run(index,args,sha):
    if not (Path(args.knowledge)/'native-contexts').is_dir():
        return dict(state='skipped',reason='No native context catalog',runtime_activated=False)
    report=build(args.root,args.knowledge,sha,execute=True)
    path=load('research-workflow').snapshot(Path(args.root),'function-reuse-catalog',report)
    return dict(report=str(path),sha256=digest(path),summary=report['summary'],runtime_activated=False,profile_activated=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--knowledge',type=Path,default=HERE/'knowledge')
    parser.add_argument('--source-sha256',required=True)
    parser.add_argument('--plan-only',action='store_true')
    args=parser.parse_args();value=build(args.root,args.knowledge,args.source_sha256,execute=not args.plan_only)
    path=load('research-workflow').snapshot(args.root,'function-reuse-catalog',value)
    print(json.dumps(dict(report=str(path),sha256=digest(path),summary=value['summary'],runtime_activated=False)))
