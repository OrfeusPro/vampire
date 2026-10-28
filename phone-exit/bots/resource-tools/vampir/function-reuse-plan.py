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
ADDRESS=re.compile(r'0x[0-9a-f]+')
SHA=re.compile(r'[0-9a-f]{64}')
WINDOW=65536
MAX_BATCH=128
MAX_CONTEXTS=512
MAX_ROLES=4096


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


# Compatibility API for existing callers/tests. Operational selection reads the
# validated registry supplied with the run, rather than a Python release list.
_DEFAULT_REGISTRY=load('native-release-registry').read(HERE/'knowledge')
SOURCES={row['id']:row['source_sha256'] for row in _DEFAULT_REGISTRY['releases']}
FAMILY_ALIASES=_DEFAULT_REGISTRY['family_aliases']


def registry_data(knowledge,root=None):
    value=load('native-release-registry').read(knowledge,fallback=SOURCES)
    if not (Path(knowledge)/'native-release-registry.json').is_file():
        value['family_aliases']={version:aliases for version,aliases in FAMILY_ALIASES.items() if version in SOURCES}
    if root is not None:
        api=load('native-release-registry');known={row['source_sha256'] for row in value['releases']}
        generated=api.generated_contexts(root,value)
        generated.extend(load('update-native-string-writer').published_contexts(root,value))
        for _,context,rank in generated:
            sha=context['source_sha256']
            if sha not in known:
                value['releases'].append(dict(id='auto-'+sha,order=rank,source_sha256=sha));known.add(sha)
        api.validate(value)
    return value


def sources(knowledge=None,root=None):
    value=registry_data(knowledge or HERE/'knowledge',root)
    return {row['id']:row['source_sha256'] for row in sorted(value['releases'],key=lambda x:x['order'])}


def ordered_sources(knowledge=None,root=None):
    return [row['source_sha256'] for row in sorted(registry_data(knowledge or HERE/'knowledge',root)['releases'],key=lambda x:x['order'],reverse=True)]


def context_files(knowledge,registry=None,root=None):
    registry=registry or registry_data(knowledge,root);api=load('native-release-registry')
    result=[path for path in sorted((Path(knowledge)/'native-contexts').glob('*.json'))
        if api.context_identity(path,json.loads(path.read_text('utf-8')),registry) is not None]
    if root is not None:
        result.extend(path for path,_,_ in api.generated_contexts(root,registry))
        result.extend(path for path,_,_ in load('update-native-string-writer').published_contexts(root,registry))
    return sorted(set(result))


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def nested_inputs(context):
    groups=[]
    for name in ('input','native_input'):
        value=context.get(name)
        if not isinstance(value,dict) or 'functions' not in value:continue
        if value.get('source_sha256',context.get('source_sha256'))!=context.get('source_sha256'):
            raise ValueError('Nested input source differs from context')
        if (not isinstance(value['functions'],dict)
                or any(not isinstance(role,str) or not isinstance(at,str) or not ADDRESS.fullmatch(at)
                       for role,at in value['functions'].items())):
            raise ValueError('Invalid nested executable function declarations')
        if not isinstance(value.get('exports',{}),dict):
            raise ValueError('Invalid nested input exports')
        groups.append(value)
    return groups


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
    for group in nested_inputs(context):
        for role,address in group['functions'].items():
            key='input:functions:'+role
            if key in result and result[key]!=address:
                raise ValueError('Conflicting normalized nested input role')
            result[key]=address
    return result


def inventory(root,knowledge,*,source_store=None):
    root,knowledge=Path(root),Path(knowledge)
    contexts=[];exports={};sources={};queue=[]
    registry=registry_data(knowledge,root);api=load('native-release-registry')
    releases={row['id']:row for row in registry['releases']}
    paths=context_files(knowledge,registry,root)
    if len(paths)>MAX_CONTEXTS:raise ValueError('Function context budget exceeded')
    declarations_to_read=[(str(path),json.loads(path.read_text('utf-8')),digest(path)) for path in paths]
    declarations_to_read.extend(api.projected_contexts(knowledge,registry))
    for name,context,context_digest in declarations_to_read:
        path=Path(name);roles=declarations(context)
        dependency_only=context.get('dependency_only',False)
        if type(dependency_only) is not bool:raise ValueError('Dependency-only declaration must be boolean')
        if not roles:continue
        version,declared_family=api.context_identity(path,context,registry)
        expected=releases[version]['source_sha256'];actual=context.get('source_sha256')
        if actual!=expected:
            queue.append(dict(context=str(path),reason='context_source_not_verified',source_sha256=actual));continue
        if expected not in sources:
            source=root/'client-code-snapshots'/expected/'ProjectRED-Win64-Shipping.exe'
            if source_store is not None:source_store.source(expected)
            elif digest(source)!=expected:raise ValueError('Context baseline source changed')
            sources[expected]=str(source)
        declared=context.get('exports')
        if context.get('native_admission'):
            adapter=load('update-native-contexts')
            admitted=adapter.admitted_instructions(context,root,
                {int(context['bindings'][key],16) for key in ('length','convert')},
                {int(context['bindings']['encoder'],16):context['encoder_leaf']['bytes']},source_store=source_store)
            proof=context['native_admission'];export=proof['path']
            exports[export]=dict(sha256=proof['sha256'],report=dict(source_sha256=expected,functions=admitted['functions']),source_sha256=expected)
            family=registry['family_aliases'].get(version,{}).get(declared_family,declared_family)
            contexts.append(dict(path=str(path),sha256=context_digest,family=family,declared_family=declared_family,
                version=version,order=releases[version]['order'],source_sha256=expected,roles=roles,exports=[export],dependency_only=dependency_only))
            continue
        if not isinstance(declared,dict) or not declared:
            queue.append(dict(context=str(path),reason='context_exports_not_declared',source_sha256=expected));continue
        declared=dict(declared)
        for group in nested_inputs(context):
            for run,sha in group.get('exports',{}).items():
                if run in declared and declared[run]!=sha:raise ValueError('Conflicting nested input export digest')
                declared[run]=sha
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
        family=registry['family_aliases'].get(version,{}).get(declared_family,declared_family)
        contexts.append(dict(path=str(path),sha256=context_digest,family=family,declared_family=declared_family,
            version=version,order=releases[version]['order'],source_sha256=expected,roles=roles,exports=material,dependency_only=dependency_only))
    if sum(len(c['roles']) for c in contexts)>MAX_ROLES:raise ValueError('Function role budget exceeded')
    return contexts,exports,sources,queue


def inputs(root,knowledge,*,source_store=None):
    contexts,exports,sources,queue=inventory(root,knowledge,**({'source_store':source_store} if source_store is not None else {}))
    # Include all eligible context files, even rejected declarations, so correcting
    # an unknown source/export declaration invalidates the cached stage.
    files=context_files(knowledge,root=root)
    registry=Path(knowledge)/'native-release-registry.json'
    tools=('function-reuse-plan.py','native-release-registry.py','update-native-contexts.py','update-native-string-writer.py','verify-utf8-context.py','update-native-harness.py','update-bindings.py','build-native-entry-code.py','extract-native-enums.py','research-workflow.py','update-contracts.py')
    runtime=load('build-native-entry-code').capstone
    import importlib.metadata
    distribution=importlib.metadata.distribution('capstone')
    record=distribution.read_text('RECORD')
    if runtime.__version__!='5.0.6' or distribution.version!='5.0.6' or not record:raise ValueError('Pinned function catalog runtime required')
    return dict(present=bool(files),approved_data_sha256=digest(Path(knowledge)/'update-contracts.json') if (Path(knowledge)/'update-contracts.json').is_file() else None,capstone_version=runtime.__version__,capstone_record_sha256=hashlib.sha256(record.encode()).hexdigest(),contexts={str(p):digest(p) for p in files},
        registry_sha256=digest(registry) if registry.is_file() else None,
        generated_index_sha256=digest(Path(root)/'knowledge/generated-native/index.json') if (Path(root)/'knowledge/generated-native/index.json').is_file() else None,
        exports={p:v['sha256'] for p,v in exports.items()},sources={sha:sha for sha in sources},
        tools={name:digest(HERE/name) for name in tools},queue=queue)


def choose(contexts):
    """Newest declaration per family/role; deduplicate the source/address work."""
    latest={};all_records={}
    for context in contexts:
        for role,address in context['roles'].items():
            item=dict(context=context['path'],context_sha256=context['sha256'],family=context['family'],role=role,
                declared_family=context.get('declared_family',context['family']),version=context['version'],order=context['order'] if 'order' in context else int(context['version']),source_sha256=context['source_sha256'],address=address,exports=context['exports'])
            record=all_records.setdefault((item['source_sha256'],address),dict(source_sha256=item['source_sha256'],address=address,aliases=[],exports=set()))
            record['aliases'].append({k:item[k] for k in ('context','context_sha256','family','declared_family','role','version')})
            record['exports'].update(context['exports'])
            if context.get('dependency_only',False):continue
            identity=(context['family'],role)
            if identity not in latest or item['order']>latest[identity]['order']:latest[identity]=item
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


def build(root,knowledge,target_sha,*,execute=True,source_store=None):
    root,knowledge=Path(root),Path(knowledge)
    bindings,native=load('update-bindings'),load('build-native-entry-code')
    identity=inputs(root,knowledge,source_store=source_store)
    contexts,exports,sources,queue=inventory(root,knowledge,**({'source_store':source_store} if source_store is not None else {}))
    if (any(identity['contexts'].get(c['path'],c['sha256'])!=c['sha256'] for c in contexts)
            or identity['exports']!={p:v['sha256'] for p,v in exports.items()}):
        raise ValueError('Function inventory changed during planning')
    target=source_store.source(target_sha) if source_store is not None else bindings.source(None,root,target_sha)
    records,selected,latest=choose(contexts)
    primary=set(selected)
    identity['target_sha256']=target_sha
    identity['approved_data_sha256']=digest(knowledge/'update-contracts.json') if (knowledge/'update-contracts.json').is_file() else None
    images={};decoded={};data_specs=approved_data(knowledge)
    def image(sha):
        if sha not in images:images[sha]=source_store.image(native,sha) if source_store is not None else native.Image(Path(sources[sha]).read_bytes())
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
            outcome=bindings.resolve(index,SimpleNamespace(root=root,source_store=source_store),dict(contracts=[contract]),target_sha,[])['contracts'][contract['id']]
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
    current_files={str(p) for p in context_files(knowledge,root=root)}
    if current_files!=set(identity['contexts']):raise ValueError('Function context inventory changed during planning')
    registry_path=knowledge/'native-release-registry.json'
    if (digest(registry_path) if registry_path.is_file() else None)!=identity['registry_sha256']:
        raise ValueError('Native release registry changed during planning')
    generated_index=root/'knowledge/generated-native/index.json'
    if (digest(generated_index) if generated_index.is_file() else None)!=identity['generated_index_sha256']:
        raise ValueError('Generated native context index changed during planning')
    for name,sha in identity['exports'].items():
        if digest(name)!=sha:raise ValueError('Function exports changed during planning')
    if source_store is None:
        for sha,path in sources.items():
            if digest(path)!=sha:raise ValueError('Function baseline changed during planning')
        if hashlib.sha256(bindings.source(None,root,target_sha)).hexdigest()!=target_sha:raise ValueError('Function target changed')
    verified_keys={(v['baseline_sha256'],proof['baseline_address']) for v in verifications
        for proof in v['verification'].values() if proof['state'] in ('unchanged','moved_verified')}
    # Group actual call edges once so shared blockers can be researched in
    # bounded batches. Consumer counts overlap; they are not predicted closures.
    frontier={}
    for key in sorted(selected-verified_keys):
        recipe,deps,reasons=inspect(key)
        missing={(key[0],reason[len('undeclared_callee_'):]) for reason in reasons if reason.startswith('undeclared_callee_')}
        for dependency in (set(deps)|missing)-verified_keys:
            frontier.setdefault(dependency,set()).add(key)
    frontier=[dict(source_sha256=sha,address=address,declared=(sha,address) in records,
        direct_consumers=len(consumers),consumers=[dict(source_sha256=s,address=a) for s,a in sorted(consumers)],
        reasons=rejected.get((sha,address),['target_shape_not_verified'] if (sha,address) in records else ['dependency_not_declared']))
        for (sha,address),consumers in sorted(frontier.items(),key=lambda item:(-len(item[1]),item[0]))]
    summary=dict(contexts=len(contexts),roles=sum(len(c['roles']) for c in contexts if not c['dependency_only']),functions=len(selected),
        dependency_declarations=sum(len(c['roles']) for c in contexts if c['dependency_only']),
        primary_functions=len(primary),primary_verified=len(primary&verified_keys),
        primary_requires_review=len(primary-verified_keys),dependency_functions=len(selected-primary),
        dependency_verified=len((selected-primary)&verified_keys),
        baseline_counts={sha:sum(key[0]==sha for key in selected) for sha in sorted(sources)},
        planned=planned,verified=verified,requires_review=len(selected)-verified,executed=execute)
    report=dict(schema=1,identity=identity,target_sha256=target_sha,summary=summary,
        inventory=[records[key] for key in sorted(selected)],contracts=contracts,verification=verifications,queue=queue,
        dependency_frontier=frontier,
        scope='function_only',runtime_activated=False,profile_activated=False,
        limits=['Newest explicit context role selected from reviewed 1.13.16/1.13.18/1.13.20/1.13.22 declarations per normalized family/role; older declarations apply only where a newer role is absent. Release presence does not establish complete role coverage.',
            'Only reviewed registry projections, explicit family aliases and executable input/native_input groups are normalized; arbitrary address fields remain excluded.',
            'Unwind roots and explicit export instructions are verified. Undeclared data/callees, leaves and indirect/tail branches remain queued.',
            'Only bounded declared instruction/callee/data equivalence is verified; native semantic suites and runtime admission remain separate.'])
    return report


def run(index,args,sha):
    if not (Path(args.knowledge)/'native-contexts').is_dir():
        return dict(state='skipped',reason='No native context catalog',runtime_activated=False)
    report=build(args.root,args.knowledge,sha,execute=True,source_store=getattr(args,'source_store',None))
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
