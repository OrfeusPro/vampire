"""Resumable offline update journal. No login, active-profile or baseline writes."""
import hashlib
import copy
import ast
import fnmatch
import importlib.metadata
import json
import os
import re
from pathlib import Path
import time
from types import SimpleNamespace


def execution_inputs(index):
    """Hash local tool dependencies without importing/executing their code."""
    # Shared dependencies belong to several groups. Parse each file once in
    # this snapshot; the next execution_inputs call always reads fresh inputs.
    scanned={}
    def scan(path):
        if path in scanned:return scanned[path]
        digest=index.digest(path) if path.is_file() else None
        children=[]
        if path.suffix=='.py' and path.is_file():
            for node in ast.walk(ast.parse(path.read_text('utf-8-sig'))):
                if not isinstance(node,ast.Constant) or not isinstance(node.value,str):continue
                if len(node.value)>128 or not re.fullmatch(r'[A-Za-z0-9_./-]+',node.value):continue
                for name in (node.value,node.value+'.py'):
                    if not name.endswith('.py') or '\n' in name:continue
                    for parent in (index.HERE,index.HERE.parent):
                        child=(parent/name).resolve()
                        if child.is_relative_to(index.HERE.parent.resolve()) and child.is_file():children.append(child)
        scanned[path]=(digest,children)
        return scanned[path]
    def group(seeds):
        pending=[(index.HERE/name).resolve() for name in seeds]; found={}
        while pending:
            path=pending.pop()
            if str(path) in found:continue
            if len(found)>=256:raise ValueError('Tool dependency budget exceeded')
            digest,children=scan(path)
            found[str(path)]=digest
            pending.extend(children)
        return found
    # Journal/CLI changes create a new run identity, not a blanket cache miss.
    # Bump this format only when interpretation of stored stage results changes.
    common={'stage_format':2}
    groups={name:{**common,**group(seeds)} for name,seeds in {
        'resources':['recover-release-game-config.py','index-release-archives.py','compare-release-assets.py','extract-release-tables.py'],
        'discovery':['locate-release-update-targets.py'],
        'bindings':['update-bindings.py','update-contracts.py','function-reuse-plan.py','binary-diff-candidates.py'],
        'contracts':['update-contracts.py'],
        'context':['verify-version-login-context.py','verify-packet-writer-context.py','update-native-harness.py',
            'update-native-contexts.py','verify-utf8-context.py','native-release-registry.py'],
        'profile':['update-profile.py','update-bundle.py']}.items()}
    shared=index.HERE.parents[1]/'vampir-shared/vampir_core'
    for name in ('release_bundle.py','runtime_admission.py','sdk_config.py'):
        path=shared/name
        groups['profile'][str(path)]=index.digest(path) if path.is_file() else None
    if (shared/'runtime_admission.py').is_file():
        import sys
        sys.path.insert(0,str(shared.parent))
        from vampir_core.runtime_admission import CONSUMERS
        workspace=index.HERE.parents[3]
        groups['profile']['runtime_consumers']={name:index.digest(workspace/name) for name in CONSUMERS}
    runtime=index.extension('update-native-harness').runtime_inputs()
    for name in ('resources','discovery','bindings','context'):groups[name]['native_runtime']=runtime
    try:
        dist=importlib.metadata.distribution('cryptography')
        groups['resources']['cryptography']=dict(version=dist.version,
            record_sha256=hashlib.sha256((dist.read_text('RECORD') or '').encode()).hexdigest())
    except importlib.metadata.PackageNotFoundError:groups['resources']['cryptography']=None
    dll=Path(os.environ.get('PHONEEXIT_RF_RESOURCES','F:/PhoneExit Resources/RF Online Next'))/'tools/oodle-data-shared.dll'
    groups['resources'][str(dll)]=index.digest(dll) if dll.is_file() else None
    return groups


def resource_inputs(contract, rows):
    return [dict(archive=r['path'],sha256=(r.get('current') or {}).get('sha256'),
                 logical_path_pattern=dep['path'],logical_paths_verified=False)
        for dep in contract.get('resources',[]) for r in rows
        if fnmatch.fnmatchcase(r['path'].replace('\\','/'),dep['archive'])]


def definition_inputs(index, args, update):
    """All executable declarations, including reviewed check implementations."""
    paths = {args.knowledge/'update-contracts.json', args.knowledge/'research-checks.json',
        *update.target_plans(index,args.knowledge)}
    paths.update(index.HERE/name for name in ('update-run.py','research-update.py',
        'research-workflow.py','knowledge-index.py','knowledge-context.py') if (index.HERE/name).is_file())
    paths.update((args.knowledge/'native-contexts').glob('*.json'))
    paths.update(p for p in (args.knowledge/'native-release-registry.json',
        args.knowledge/'native-check-adapters.json') if p.is_file())
    workspace = index.HERE.parents[3]
    for check in index.read_json(args.knowledge/'research-checks.json').get('checks',[]):
        variants = [check, *check.get('source_variants',{}).values()]
        for item in variants:
            pattern = item.get('test_pattern')
            if pattern:
                paths.add(index.child(workspace,'phone-exit/bots/'+pattern))
            paths.update(index.child(workspace,name) for name in item.get('dependencies',[]))
    return {str(p.resolve()):index.digest(p) for p in sorted(paths)}


def resource_stage_inputs(index, args, row, tools, *, source_sha=None, audit_sha=None):
    """Selected archive material only; another archive's audit is irrelevant."""
    def material(value):
        if value is None:return None
        return {key:value.get(key) for key in ('sha256','size','pak_version')}
    historical = [args.root/'pak-extracted'/Path(row['path']).stem/'entries.json']
    cached = row.get('cached_index') or {}
    if cached.get('path'):historical.append(Path(cached['path']))
    entries=historical[0]
    if entries.is_file():
        for item in index.read_json(entries):
            if item.get('saved'):
                path=Path(item['saved']).resolve()
                if not path.is_relative_to(entries.parent.resolve()):raise ValueError('Historical blob outside extraction directory')
                historical.append(path)
    tables=table_baseline(index,args,row)
    for item in tables['tables']:historical.append(Path(item['file']))
    if Path(row['path']).name in ('ProjectRED-Windows.pak','pakchunk0-Windows.pak'):
        core=index.extension('recover-pak-game-config')
        historical.extend([args.root/'resource-config-snapshots/393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db/manifest.json',
            args.root/'client-code-snapshots'/core.EXE_SHA256/'ProjectRED-Win64-Shipping.exe'])
    result=dict(archive=str(Path(row['path']).resolve()),current=material(row.get('current')),
        baseline=material(row.get('baseline')),cached_index=cached,
        table_baseline=tables,
        historical={str(p.resolve()):index.digest(p) if p.is_file() else None for p in historical},tools=tools)
    if Path(row['path']).name in ('ProjectRED-Windows.pak','pakchunk0-Windows.pak'):
        result['config_source_sha256']=source_sha
    if any(value is not None and not re.fullmatch('[0-9a-f]{64}',str(value.get('sha256','')))
            for value in (row.get('current'),row.get('baseline'))):
        # Incomplete historical identities cannot authorize a narrower cache.
        result['incomplete_material_audit_sha256']=audit_sha
    return result


def table_baseline(index,args,row):
    """Only this archive's table identities and files affect its comparison."""
    path=args.root/'table-study/index.json'
    if not path.is_file():return dict(path=str(path),state='missing',tables=[])
    value=index.read_json(path)
    rows=value.get('tables',[])
    matching=[dict(item) for item in rows if Path(item.get('source',{}).get('path','')).resolve()==Path(row['path']).resolve()]
    for item in matching:
        file=(path.parent/item['file']).resolve()
        if not file.is_relative_to(path.parent.resolve()):raise ValueError('Historical CSV outside table directory')
        item['file']=str(file)
    return dict(path=str(path),state='foreign_only' if rows and not matching else 'selected',tables=matching)


def resource_work(index,args,report,contracts,changed,tools=None):
    """An inventory baseline is not an extraction-completion receipt."""
    selected={r['path']:r for r in changed}
    wanted=[r for r in report['files'] if r.get('current') and r['current'].get('pak_version')==11 and
        any(fnmatch.fnmatchcase(r['path'].replace('\\','/'),dep['archive'])
            for c in contracts['contracts'] for dep in c.get('resources',[]))]
    if not wanted:return list(selected.values())
    workflow=index.extension('research-workflow')
    for row in wanted:
        ready=False
        if tools is not None:
            inputs=resource_stage_inputs(index,args,row,tools,source_sha=report['exe']['sha256'],
                audit_sha=report.get('baseline_sha256'))
            name='resource-'+hashlib.sha256(row['path'].encode()).hexdigest()[:16]
            key=fingerprint(workflow,dict(stage=name,inputs=inputs))
            cache=args.root/'knowledge/update-stage-cache'/(key+'.json')
            if cache.is_file():
                path=Path(index.read_json(cache)['report']).resolve()
                if not path.is_relative_to((args.root/'knowledge/update-stages').resolve()):raise ValueError('Resource completion receipt outside stages')
                saved=workflow.checked_manifest(index,path)
                ready=(saved.get('key')==key and saved.get('inputs')==inputs and saved.get('state')=='completed'
                    and saved.get('result',{}).get('state')=='passed' and bool(saved.get('outputs')))
                if ready and any(index.digest(p)!=sha for p,sha in saved['outputs'].items()):
                    raise ValueError('Completed resource output changed')
        if not ready:selected[row['path']]=row
    return list(selected.values())


def affected_plan(model, contracts, checks, *, exe_changed, changes, previous, definitions, tools):
    """Impact includes check/tool/recipe changes and all reverse consumers."""
    dirty = set(model.affected(contracts,exe_changed=exe_changed,changes=changes))
    old = (previous or {}).get('plan',{})
    prior_contracts = {c['id']:c for c in old.get('contracts',{}).get('contracts',[])}
    prior_definitions = old.get('definition_sha256',{})
    changed_paths = {p for p in set(prior_definitions)|set(definitions)
        if prior_definitions.get(p)!=definitions.get(p)} if old else set()
    reasons = {name:['release_material_changed'] for name in dirty}
    registry = {c['id']:c for c in checks}
    previous_checks=old.get('checks',{})
    for contract in contracts['contracts']:
        causes=[]; name=contract['id']
        if old and prior_contracts.get(name)!=contract:causes.append('contract_definition_changed')
        for check_id in contract['checks']:
            check=registry.get(check_id,{})
            if exe_changed and check.get('source_scope','client')=='client':causes.append('client_check_source_changed')
            if old:
                inputs=[check,*check.get('source_variants',{}).values()]
                names={Path(p).name for item in inputs for p in item.get('dependencies',[])}
                names.update(item['test_pattern'] for item in inputs if item.get('test_pattern'))
                registry_changed=(previous_checks.get(check_id)!=check if previous_checks else
                    any(Path(p).name=='research-checks.json' for p in changed_paths))
                if registry_changed or any(Path(p).name in names for p in changed_paths):
                    causes.append('check_inputs_changed:'+check_id)
        old_tools=old.get('tools',{})
        for group,used in (('bindings',bool(contract['recipes'])),('context',bool(contract.get('context_checks'))),
                ('profile',bool(contract.get('builder')))):
            if old and used and old_tools.get(group)!=tools[group]:causes.append(group+'_tools_changed')
        if causes:dirty.add(name);reasons.setdefault(name,[]).extend(causes)
    for name in contracts['order']:
        contract=next(c for c in contracts['contracts'] if c['id']==name)
        deps=[d for d in contract['depends_on'] if d in dirty]
        if deps:dirty.add(name);reasons.setdefault(name,[]).extend('dependency_changed:'+d for d in deps)
    return dict(affected=[name for name in contracts['order'] if name in dirty],
        reasons={name:sorted(set(values)) for name,values in reasons.items()})


def root_blockers(contracts, outcomes, queue, native_queue=()):
    """Group shared causes; legacy queue entries are observations, not tasks."""
    groups={}
    def consumers(name):
        found={name} if name else set()
        for candidate in contracts['order']:
            c=next(c for c in contracts['contracts'] if c['id']==candidate)
            if any(dep in found for dep in c['depends_on']):found.add(candidate)
        return found
    for item in [*queue,*native_queue]:
        reason=item.get('reason','Unspecified blocker')
        if reason.startswith('Dependencies incomplete:'):continue
        contract=item.get('contract')
        resource_contracts=set()
        if item.get('capability')=='resources' and item.get('archive'):
            archive=item['archive'].replace('\\','/')
            resource_contracts={c['id'] for c in contracts['contracts'] if any(
                fnmatch.fnmatchcase(archive,dep['archive']) for dep in c.get('resources',[]))}
            problems=[s.get('tool','adapter')+': '+s.get('reason',s.get('state','unknown'))
                for s in (item.get('evidence') or {}).get('steps',[]) if s.get('state')!='passed']
            if problems:reason='; '.join(sorted(set(problems)))
        check=(item.get('evidence') or {}).get('id') if isinstance(item.get('evidence'),dict) else None
        entity=check or item.get('address') or item.get('source_sha256') or item.get('family')
        if reason in ('Contract coverage is partial','No registered semantic check'):entity=contract
        key=(reason,entity)
        entry=groups.setdefault(key,dict(reason=reason,details=item.get('details'),entity=entity,
            contracts=set(),capabilities=set(),resources=set(),observations=0))
        entry['contracts'].update(consumers(contract));entry['observations']+=1
        for name in resource_contracts:entry['contracts'].update(consumers(name))
        if item.get('archive'):entry['resources'].add(item['archive'])
        for name,capability in contracts['capabilities'].items():
            if any(required in entry['contracts'] for required in capability['requires']):entry['capabilities'].add(name)
    result=[]
    for number,entry in enumerate(sorted(groups.values(),key=lambda e:(-len(e['contracts']),e['reason']))):
        result.append(dict(id='blocker-'+str(number+1),**{k:sorted(v) if isinstance(v,set) else v for k,v in entry.items()}))
    return result


def function_blockers(index, reuse, contracts):
    """Expose intrinsic shared dependency gaps, without counting their callers twice."""
    if not reuse.get('report'):return []
    report=index.read_json(reuse['report'])
    result=[]
    for item in report.get('dependency_frontier',[]):
        reasons=item.get('reasons',[])
        if reasons and all(reason.startswith('callee_not_closed:') for reason in reasons):continue
        names={c['id'] for c in contracts['contracts'] if item['address'] in
            c['bindings'].get(item['source_sha256'],{}).values()}
        result.append(dict(id='function-'+item['source_sha256'][:12]+'-'+item['address'][2:],
            category='native_function',reason='; '.join(reasons),source_sha256=item['source_sha256'],
            address=item['address'],declared=item.get('declared',False),contracts=sorted(names),
            function_consumers=item.get('consumers',[]),direct_function_consumers=item.get('direct_consumers',0),
            scope='function_dependency_frontier',runtime_activated=False))
    return result


def ensure_index(index, args, database):
    """Verify current material without invoking a writer for an unchanged index."""
    if Path(database).is_file():
        db=index.open_index(database)
        try:
            stored=db.execute("SELECT value FROM metadata WHERE key='tool_inputs'").fetchone()
            reports={str(p) for p in index.discover(args.root)}
            rows=list(db.execute('SELECT path,sha,receipt,receipt_sha FROM artifacts'))
            contexts=index.extension('knowledge-context').inventory(index,args.root,args.knowledge)
            old_context={r['path']:r['sha'] for r in db.execute('SELECT * FROM context_inputs')}
            same=(stored and json.loads(stored['value'])==index.tool_inputs() and
                reports=={r['path'] for r in rows} and contexts==old_context and
                not any(not r['receipt'] and index.receipt_for(Path(r['path'])).is_file() for r in rows))
            if same:
                same=all(index.digest(r['path'])==r['sha'] and
                    (not r['receipt'] or index.digest(r['receipt'])==r['receipt_sha']) for r in rows)
                same=same and all(index.digest(r['pseudocode'])==r['pseudocode_sha'] for r in db.execute(
                    'SELECT DISTINCT o.pseudocode,v.pseudocode_sha FROM observations o JOIN variants v ON o.variant=v.id WHERE o.pseudocode IS NOT NULL'))
                same=same and db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            if same:return dict(database=str(database),counts=index.index_counts(db),reused=True,writer_started=False)
        finally:db.close()
    return index.build(args.root,database,knowledge=args.knowledge)


def fingerprint(workflow, value):
    return hashlib.sha256(workflow.canonical(value)).hexdigest()


def save(workflow, path, run):
    workflow.atomic(path, workflow.canonical(dict(schema=1, payload=run, sha256=fingerprint(workflow, run))))


def read(index, workflow, path, root):
    path = Path(path).resolve()
    if not path.is_relative_to((root/'knowledge/update-runs').resolve()) or path.name != 'run.json':
        raise ValueError('Run journal outside update-runs')
    value = index.read_json(path)
    if value.get('schema') != 1 or fingerprint(workflow, value['payload']) != value.get('sha256'):
        raise ValueError('Update journal digest mismatch')
    return value['payload']


def outputs(index, value, root):
    pinned = {}
    def visit(item):
        if isinstance(item, dict):
            if 'path' in item and 'sha256' in item and isinstance(item['path'],str):
                path = Path(item['path']).resolve()
                if path.is_relative_to(root.resolve()) and path.is_file():
                    if index.digest(path) != item['sha256']: raise ValueError('Stage artifact digest mismatch')
                    pinned[str(path)] = item['sha256']
            for key, child in item.items():
                if key in ('report', 'manifest', 'export', 'profile', 'context') and isinstance(child, str):
                    path = Path(child).resolve()
                    if not path.is_relative_to(root.resolve()):
                        raise ValueError('Stage output outside public resource library')
                    if not path.is_file(): raise ValueError('Stage output is missing')
                    pinned[str(path)] = index.digest(path)
                elif key != 'diagnostic': visit(child)
        elif isinstance(item, list):
            for child in item: visit(child)
    visit(value)
    return pinned


class Journal:
    def __init__(self, index, workflow, args, run, path):
        self.index, self.workflow, self.args, self.run, self.path = index, workflow, args, run, path
        self.reused = 0
        self.executed=[]
        self.validation_seconds={}

    def stage(self, name, inputs, action):
        key = fingerprint(self.workflow, dict(stage=name,inputs=inputs))
        old = self.run['stages'].get(name)
        cache=self.args.root/'knowledge/update-stage-cache'/(key+'.json')
        if (not old or old.get('key')!=key) and cache.is_file():
            target=Path(self.index.read_json(cache)['report']).resolve()
            if not target.is_relative_to((self.args.root/'knowledge/update-stages').resolve()):
                raise ValueError('Stage cache outside update-stages')
            old=self.workflow.checked_manifest(self.index,target)
            if old.get('key')!=key:raise ValueError('Stage cache key mismatch')
        if old and old.get('key') == key and old.get('state') == 'completed':
            started=time.perf_counter()
            if any(self.index.digest(p) != sha for p, sha in old['outputs'].items()):
                raise ValueError('Saved stage output changed: '+name)
            self.reused += 1
            self.run['stages'][name]=old
            self.validation_seconds[name]=round(time.perf_counter()-started,6)
            # This completed result already has its durable stage-cache receipt.
            # A crash can rediscover it; rewriting the growing full run for
            # every cache hit adds gigabytes of redundant writes. The next real
            # stage or the final checkpoint persists the in-memory inventory.
            print(json.dumps(dict(event='update_stage',stage=name,state='cached')),flush=True)
            return old['result']
        entry = dict(key=key, inputs=inputs, state='running', owner_pid=os.getpid(), started_at=time.time())
        self.run['stages'][name] = entry
        save(self.workflow, self.path, self.run)
        print(json.dumps(dict(event='update_stage',stage=name,state='running')),flush=True)
        start = time.perf_counter()
        self.executed.append(name)
        try:
            result = action()
            entry.update(state='completed', result=result, outputs=outputs(self.index, result, self.args.root))
        except BaseException as error:
            entry.update(state='interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', reason=str(error))
            self.run['state']=entry['state']
            raise
        finally:
            entry['seconds'] = round(time.perf_counter()-start, 6)
            entry['finished_at'] = time.time()
            save(self.workflow, self.path, self.run)
        target=self.workflow.snapshot(self.args.root,'update-stages',entry)
        self.workflow.atomic(cache,self.workflow.canonical(dict(report=str(target))))
        print(json.dumps(dict(event='update_stage', stage=name, seconds=entry['seconds'])), flush=True)
        return result


def valid_install(index, audit, install):
    expected = {str(Path(audit['exe']['path']).resolve()): audit['exe']['sha256']}
    expected.update({str(Path(r['path']).resolve()): r['current']['sha256'] for r in audit['files'] if r['current']})
    update = index.extension('research-update')
    found = update.signatures(install, {Path(p).parent for p in expected if p != str(Path(audit['exe']['path']).resolve())})
    if set(found) != set(expected): return False
    return all(index.digest(p) == sha for p, sha in expected.items()) and found == update.signatures(
        install, {Path(p).parent for p in expected if Path(p).suffix.lower() != '.exe'})


def definition_status(index, args, run):
    """Inspect current registry hashes only; never launch checks or analysis."""
    saved = run.get('plan', {}).get('definition_sha256')
    if not isinstance(saved, dict) or not saved:
        return dict(current=None, changed=[], reason='Legacy journal has no definition hashes; resume to audit current definitions')
    knowledge = getattr(args, 'knowledge', index.HERE / 'knowledge')
    update = index.extension('research-update')
    try:
        selected=SimpleNamespace(**vars(args));selected.knowledge=knowledge
        current = definition_inputs(index,selected,update)
    except (OSError, ValueError) as error:
        return dict(current=False, changed=[], reason='Cannot inspect update definitions: ' + str(error))
    changed = sorted(path for path in set(current) | set(saved) if current.get(path) != saved.get(path))
    return dict(current=not changed, changed=changed,
                reason='Resume required to apply changed definitions' if changed else None)


def status(index, args):
    workflow = index.extension('research-workflow')
    run = read(index, workflow, args.run, args.root)
    owners = {}
    for name in ('research','ghidra'):
        lock = args.root/'knowledge/locks'/(name+'.lock')
        if lock.is_file():
            pid = int(lock.read_text('utf-8'))
            owners[name] = dict(pid=pid, alive=owner_alive(pid),
                action='Inspect owner and its children; status never removes locks or starts another JVM')
    return dict(run=str(args.run), state=run['state'], source_sha256=run['source_sha256'], owners=owners,
        reason=run.get('reason'),
        stages={k:{x:v[x] for x in ('state','seconds','reason','owner_pid') if x in v} for k,v in run['stages'].items()},
        queue=run.get('queue', []), capabilities=run.get('capabilities', {}),
        root_blockers=run.get('root_blockers',[]),prepared_bundles=run.get('prepared_bundles',{}),
        results_current=False if run['state'] in ('running','failed','interrupted') else None,
        installed_inputs_checked=False,
        definitions=definition_status(index, args, run),
        metrics=run.get('metrics',{}),profile_activation=False, baseline_promoted=False)


def owner_alive(pid):
    if os.name == 'nt':
        import ctypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_uint]
        kernel.OpenProcess.restype=ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]
        kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        handle=kernel.OpenProcess(0x100000,False,pid)
        if not handle: return False if ctypes.get_last_error()==87 else None
        try:return kernel.WaitForSingleObject(handle,0)==258
        finally:kernel.CloseHandle(handle)
    try:os.kill(pid,0);return True
    except ProcessLookupError:return False
    except PermissionError:return None


def resource_step(index, update, workflow, args, manifest, row):
    current = row['current']
    if not current or current.get('pak_version') != 11:
        return dict(state='requires_review', reason='Removed archive or unsupported archive format', steps=[])
    steps = []
    if Path(row['path']).name in ('ProjectRED-Windows.pak', 'pakchunk0-Windows.pak'):
        steps.append(update.execute_adapter(index, args, 'recover-release-game-config.py', [manifest, '--archive', row['path']]))
    indexed = update.execute_adapter(index, args, 'index-release-archives.py', [manifest, '--archive-sha256', current['sha256']])
    steps.append(indexed)
    if indexed['state'] != 'passed': return dict(state='requires_review', reason='Archive indexing failed', steps=steps)
    summaries = [p for p in sorted((manifest.parent/'index-summaries').glob('*/manifest.json'))
        if workflow.checked_manifest(index, p).get('selected_archive_sha256') == current['sha256']]
    if len(summaries) != 1:
        return dict(state='requires_review', reason='Missing or ambiguous archive index summary', steps=steps)
    summary = workflow.checked_manifest(index, summaries[0])
    for archive in summary['archives']:
        record = Path(archive['report'])
        for tool, previous in (('compare-release-assets.py', args.root/'pak-extracted'/Path(row['path']).stem/'entries.json'),
                               ('extract-release-tables.py', args.root/'table-study/index.json')):
            if previous.is_file():
                if tool == 'extract-release-tables.py':
                    baseline=table_baseline(index,args,row)
                    if baseline['state']=='foreign_only':
                        steps.append(dict(tool=tool,state='requires_review',reason='Historical table index belongs to another archive'))
                        continue
                    previous=workflow.snapshot(args.root,'resource-table-baselines',dict(tables=baseline['tables']))
                steps.append(update.execute_adapter(index, args, tool, [record, previous]))
            else:
                steps.append(dict(tool=tool,state='requires_review',reason='No matching historical input'))
    result=dict(state='passed' if all(s['state'] == 'passed' for s in steps) else 'requires_review',
        reason='Resource extraction is not semantic compatibility; logical paths may remain unknown', steps=steps,
        manifest=str(summaries[0]))
    result['artifacts']=resource_artifacts(index,args.root,result)
    return result


def resource_artifacts(index, root, result):
    """Pin extracted CSV/config bytes as well as their immutable reports."""
    pinned=outputs(index,result,root)
    pending=list(pinned)
    seen=set()
    def pin(filename,expected):
        path=Path(filename).resolve()
        if not path.is_relative_to(root.resolve()):raise ValueError('Extracted resource outside public library')
        if index.digest(path)!=expected:raise ValueError('Extracted resource digest changed')
        pinned[str(path)]=expected
    while pending:
        filename=pending.pop()
        if filename in seen:continue
        seen.add(filename)
        if len(seen)>4096:raise ValueError('Resource artifact budget exceeded')
        path=Path(filename)
        if path.name!='manifest.json':continue
        # Index manifests may exceed the bounded JSON reader; their complete
        # bytes are already pinned and they do not create extracted files.
        if path.stat().st_size>32*1024*1024:continue
        value=index.read_json(path)
        for item in value.get('tables',[]):
            if item.get('file') and item.get('sha256'):pin(item['file'],item['sha256'])
        for item in value.get('configs',[]):
            if item.get('snapshot_file') and item.get('payload_sha256'):
                pin(path.parent/item['snapshot_file'],item['payload_sha256'])
        for key,name in (('directory_paths_file_sha256','directory.json'),('encoded_entries_file_sha256','encoded-entries.bin')):
            if value.get(key):pin(path.parent/name,value[key])
        for item in value.get('archives',[]):
            if item.get('report') and item.get('sha256'):
                pin(item['report'],item['sha256']);pending.append(str(Path(item['report']).resolve()))
    return [dict(path=path,sha256=sha) for path,sha in sorted(pinned.items())]


def run(index, args, database, *, audited=None):
    workflow=index.extension('research-workflow')
    with workflow.locked(args.root,'research'):
        return run_locked(index,args,database,audited=audited)


def run_locked(index, args, database, *, audited=None):
    run_started=time.perf_counter()
    workflow, update = index.extension('research-workflow'), index.extension('research-update')
    model = index.extension('update-contracts')
    path=None
    try:
        contracts = model.load(index, args.knowledge)
        definitions=definition_inputs(index,args,update)
        tools=execution_inputs(index)
        original_index=index
        store=index.extension('update-bindings').SourceStore(index,args.root,workers=getattr(args,'workers',2))
        args.source_store=store
        index=SimpleNamespace(**vars(index));index.digest=store.digest
        previous = None
        if getattr(args, 'resume', None):
            previous = read(index, workflow, args.resume, args.root)
            args.baseline, args.install = Path(previous['baseline']), Path(previous['install'])
            if index.digest(args.baseline) != previous['baseline_sha256']:
                raise ValueError('Update baseline changed')
        audit_started = time.perf_counter()
        if previous and valid_install(index, previous['audit'], args.install):
            baseline = workflow.checked_manifest(index, args.baseline)
            report, manifest = previous['audit'], Path(previous['audit_manifest'])
            if workflow.checked_manifest(index,manifest)!=report:raise ValueError('Saved audit differs from journal')
        else:
            baseline, report, manifest = audited if audited is not None else update.audit_install(index, workflow, args)
        sha = report['exe']['sha256']
        if (args.knowledge/'native-release-registry.json').is_file():
            contracts=index.extension('update-native-contexts').operational_model(index,args,contracts)
        roots={Path(r['path']).parent for r in report['files']}
        installed_stamps=update.signatures(args.install,roots)
        identity = dict(baseline_sha256=index.digest(args.baseline), install=str(args.install.resolve()),
            source_sha256=sha, audit_sha256=index.digest(manifest),
            definitions_sha256=fingerprint(workflow,definitions),tools_sha256=fingerprint(workflow,tools))
        run_id = fingerprint(workflow, identity)
        path = args.root/'knowledge/update-runs'/run_id/'run.json'
        if path.exists(): record = read(index, workflow, path, args.root)
        else:
            record = dict(schema=1, **identity, baseline=str(args.baseline.resolve()),
                audit=report, audit_manifest=str(manifest), stages={}, state='running', queue=[])
        journal = Journal(index, workflow, args, record, path)
        record['stages']['audit'] = dict(state='completed',inputs=identity,key=fingerprint(workflow,identity),
            result=dict(manifest=str(manifest)),outputs={str(manifest):index.digest(manifest)},
            seconds=round(time.perf_counter()-audit_started,6), reused=previous is not None and manifest==Path(previous['audit_manifest']))
        save(workflow, path, record)
        if callable(getattr(args,'journal_created',None)):args.journal_created(path,record)
        normalized = dict(baseline, files=[dict(r,path=str(Path(r['path']).resolve())) for r in baseline['files']])
        comparison = index.extension('compare-release-snapshots').compare(normalized, report)
        changed = [r for r in report['files'] if not r['current'] or
            r['current'].get('sha256') != (r.get('baseline') or {}).get('sha256')]
        pending_resources=resource_work(index,args,report,contracts,changed,tools['resources'])
        changes = [dict(archive=r['path'], paths=None) for r in changed]
        changes.extend(dict(archive=r['path'],paths=None) for r in pending_resources if r not in changed)
        check_registry=workflow.registry(index,args.knowledge)['checks']
        impact=affected_plan(model,contracts,check_registry,exe_changed=not comparison['exe']['full_hash_equal'],
            changes=changes,previous=previous,definitions=definitions,tools=tools)
        dirty=impact['affected']
        record['plan'] = dict(affected=dirty, impact_reasons=impact['reasons'],contracts=contracts,
            checks={c['id']:c for c in check_registry},tools=tools, definition_sha256=definitions,
            resource_work=[r['path'] for r in pending_resources])
        if getattr(args, 'plan_only', False) or getattr(args, 'audit_only', False):
            record['state'] = 'planned'; record['queue'] = []
            save(workflow, path, record)
            return dict(run=str(path), state='planned', source_sha256=sha, affected=dirty,
                baseline_promoted=False, profile_activation=False)
        record['state']='running'
        record.pop('reason',None)
        save(workflow,path,record)
        queue = []
        for row in pending_resources:
            result = journal.stage('resource-'+hashlib.sha256(row['path'].encode()).hexdigest()[:16],
                resource_stage_inputs(index,args,row,tools['resources'],source_sha=sha,audit_sha=index.digest(manifest)),
                lambda row=row:resource_step(index,update,workflow,args,manifest,row))
            if result['state'] != 'passed': queue.append(dict(contract=None, capability='resources',
                archive=row['path'],reason=result['reason'], evidence=result,
                next_check='Inspect the named resource adapter or add a matching baseline'))
        discoveries = []
        for plan in update.target_plans(index, args.knowledge):
            discoveries.append(journal.stage('discovery-'+plan.name,
                dict(source=sha, plan_sha256=index.digest(plan), tools=tools['discovery']),
                lambda plan=plan:update.execute_adapter(index,args,'locate-release-update-targets.py',
                    ['--root',args.root,'--source-sha256',sha,'--targets',plan])))
        # Function-only reuse is independent of whole-contract readiness. It
        # never adds a source SHA to semantic checks or activates a profile.
        function_reuse=dict(state='skipped',reason='No declared native contexts',
            summary=dict(verified=0,requires_review=0),runtime_activated=False,profile_activated=False)
        if (args.knowledge/'native-contexts').is_dir():
            reuse_tool=index.extension('function-reuse-plan')
            reuse_inputs=reuse_tool.inputs(args.root,args.knowledge,source_store=store)
            if reuse_inputs.get('present'):
                function_reuse=journal.stage('function-reuse',
                    dict(source=sha,catalog=reuse_inputs),
                    lambda:reuse_tool.run(index,args,sha))
        record['function_reuse']=function_reuse
        save(workflow,path,record)
        binding_tool = index.extension('update-bindings')
        candidate_tool=index.extension('binary-diff-candidates') if (index.HERE/'binary-diff-candidates.py').is_file() else None
        try:diff_receipts=candidate_tool.inputs(index,args.root,sha) if candidate_tool else []
        except (ValueError,OSError,KeyError) as error:
            diff_receipts=[]
            queue.append(dict(contract=None,capability='candidate-providers',reason='BinDiff inventory rejected: '+str(error),
                next_check='Repair the named ready comparison; no new BinExport is launched'))
        def resolve_one(contract):
            selected=dict(contracts=[contract])
            if diff_receipts:return candidate_tool.resolve(index,args,selected,sha,discoveries,diff_receipts)
            return binding_tool.resolve(index,args,selected,sha,discoveries)
        def resolve_contracts():
            results={}
            for contract in contracts['contracts']:
                binding_input={key:contract[key] for key in ('id','recipes','bindings')}
                result=journal.stage('bindings-'+contract['id'],dict(source=sha,contract=binding_input,
                    discoveries=discoveries,ready_binary_comparisons=diff_receipts,tools=tools['bindings']),
                    lambda contract=contract:resolve_one(contract))
                results.update(result['contracts'])
            return dict(source_sha256=sha,contracts=results)
        contexts = journal.stage('bindings', dict(source=sha, contracts=contracts, discoveries=discoveries,
            ready_binary_comparisons=diff_receipts,tools=tools['bindings']),
            resolve_contracts)
        contexts=apply_function_reuse(index,args.root,contracts,contexts,sha,function_reuse)
        started=time.perf_counter()
        indexed=ensure_index(index,args,database)
        record['stages']['index-before-exports']=dict(state='completed',inputs=dict(source=sha),
            result=indexed,seconds=round(time.perf_counter()-started,6),outputs={})
        save(workflow,path,record)
        exports = collect_batches(index, workflow, journal, args, database, contexts, sha)
        native_contexts=dict(checks=[],queue=[],state='skipped')
        native_checks=[]
        if (args.knowledge/'native-release-registry.json').is_file():
            native_tool=index.extension('update-native-contexts')
            generated=args.root/'knowledge/generated-native/index.json'
            def materialize_native():
                result=native_tool.materialize(index,args,sha,contexts,function_reuse)
                # The generated index is an atomic mutable pointer. Only the
                # immutable contexts and proof receipts are cached as outputs.
                result.pop('generated_index',None)
                return result
            native_contexts=journal.stage('native-materialize',dict(source=sha,contexts=contexts,
                reuse=function_reuse,definitions=definitions,tools=tools['context'],
                generated_index_sha256=index.digest(generated) if generated.is_file() else None),materialize_native)
            for declaration in native_contexts['checks']:
                try:
                    checked=journal.stage('native-check-'+declaration['id'],dict(source=sha,
                        declaration=declaration,suite_runtime=index.extension('update-native-harness').runtime_inputs()),
                        lambda declaration=declaration:native_tool.execute(index,args,sha,declaration))
                    if checked['state']=='passed' and hasattr(native_tool,'publish'):
                        native_tool.publish(index,args,sha,declaration,checked)
                except (ValueError,OSError,KeyError,StopIteration) as error:
                    checked=dict(id=declaration['id'],state='requires_review',reason=str(error))
                native_checks.append(checked)
            record['native_contexts']=native_contexts
            record['native_checks']=native_checks
        outcomes = {}
        checked_this_run={}
        def check_once(check_id):
            if check_id in checked_this_run:return checked_this_run[check_id]
            definition=next(x for x in check_registry if x['id']==check_id)
            started=time.perf_counter()
            try:checked=workflow.run_checks(index,args,sha,None,check_ids=[check_id])
            except (ValueError,OSError) as error:checked=[dict(id=check_id,state='requires_review',reason=str(error))]
            record['stages']['check-'+check_id]=dict(state='completed',inputs=dict(source=sha,definition=definition),
                key=fingerprint(workflow,checked),result=checked,outputs=outputs(index,checked,args.root),
                seconds=round(time.perf_counter()-started,6))
            save(workflow,path,record)
            checked_this_run[check_id]=checked
            return checked
        assigned={name for c in contracts['contracts'] for name in c['checks']}
        extra_checks=[]
        for definition in check_registry:
            if definition.get('on_update') is True and definition['id'] not in assigned:
                extra_checks.extend(check_once(definition['id']))
        for check in extra_checks:
            if check['state']!='passed':queue.append(dict(contract=None,capability='update-checks',
                reason=check['id']+': '+check['state'],evidence=check,
                next_check='Inspect or port this explicitly registered offline check; no live actions'))
        for name in contracts['order']:
            c = next(c for c in contracts['contracts'] if c['id'] == name)
            relevant_exports=[e for e in exports if e.get('address') in contexts['contracts'][name]['bindings'].values()]
            context = dict(schema=1, source_sha256=sha, source=str(args.root/'client-code-snapshots'/sha/Path(report['exe']['path']).name),
                contract={k:v for k,v in c.items() if k not in ('purpose','limits','next_check')},
                bindings=contexts['contracts'][name], exports=relevant_exports,
                resource_inputs=resource_inputs(c,report['files']),
                dependencies={d:outcomes[d] for d in c['depends_on']})
            cp = workflow.snapshot(args.root,'update-contexts',context)
            checks = []
            for adapter in c.get('context_checks',[]):
                def check_context():
                    module={'version-login-tag':'verify-version-login-context',
                            'packet-writer-projection':'verify-packet-writer-context'}.get(adapter)
                    if module is None:raise ValueError('Unreviewed context adapter')
                    try:proof=index.extension(module).verify(context,args.root)
                    except (ValueError,OSError,KeyError,StopIteration) as error:
                        # Offline rejection is reproducible for these exact
                        # source/context/tool inputs. Do not redisassemble it
                        # on every unchanged resume.
                        return dict(id=adapter,state='requires_review',reason=str(error))
                    proof['context_sha256']=index.digest(cp)
                    target=workflow.snapshot(args.root,'update-context-checks',proof)
                    return dict(id=adapter,state='passed',report=str(target),sha256=index.digest(target))
                try:
                    stage_name='context-check-'+name+('' if adapter=='version-login-tag' else '-'+adapter)
                    checked=journal.stage(stage_name,dict(context=index.digest(cp),
                        inputs=tools['context']),check_context)
                except (ValueError,OSError,KeyError,StopIteration) as error:
                    checked=dict(id=adapter,state='requires_review',reason=str(error))
                checks.append(checked)
            for check_id in c['checks']:
                # run_checks owns its own dependency cache; invoke it to validate inputs even on resume.
                checks.extend(check_once(check_id))
            missing = [d for d in c['depends_on'] if outcomes[d]['state'] != 'passed']
            reasons = contexts['contracts'][name]['queue'][:]
            for export in exports:
                if (export.get('address') in context['bindings']['bindings'].values()
                        and not export_satisfies(index,args.root,sha,name,context['bindings'],export)):
                    reasons.append('Export is not ready: '+export['address'])
            if missing: reasons.append('Dependencies incomplete: '+', '.join(missing))
            if c['coverage'] != 'source_checks': reasons.append('Contract coverage is partial')
            if not checks: reasons.append('No registered semantic check')
            for check in checks:
                if check['state'] != 'passed': reasons.append(check['id']+': '+check['state'])
            outcome = dict(state='passed' if not reasons else 'requires_review', context=str(cp), checks=checks, reasons=reasons)
            outcomes[name] = journal.stage('contract-'+name, dict(context=index.digest(cp), checks=checks, tools=tools['contracts']), lambda:outcome)
            for reason in reasons: queue.append(dict(contract=name, capability=[k for k,v in contracts['capabilities'].items() if name in v['requires']],
                reason=reason, evidence=dict(context=str(cp),checks=checks), next_check=c['next_check']))
        capabilities = model.readiness(contracts, outcomes)
        if definition_inputs(original_index,args,update)!=definitions or execution_inputs(original_index)!=tools:
            raise ValueError('Update definitions or tools changed during execution; resume with current inputs')
        profiles = []
        profile_validation_seconds=0
        for c in contracts['contracts']:
            if c.get('builder') and outcomes[c['id']]['state'] == 'passed':
                try:
                    started=time.perf_counter()
                    selected=index.extension('update-profile').inputs(index,workflow,args,c,outcomes,sha)
                    profile_validation_seconds+=time.perf_counter()-started
                    profiles.append(journal.stage('profile-'+c['id'], dict(context=outcomes[c['id']], inputs=selected,tools=tools['profile']),
                        lambda c=c:build_profile(index,workflow,args,c,outcomes,sha,contexts)))
                except (ValueError,OSError) as error:
                    # Do not poison a cached contract result with a later builder failure.
                    outcomes[c['id']]={**outcomes[c['id']], 'state':'requires_review'}
                    queue.append(dict(contract=c['id'],capability='launcher',reason='Profile build rejected: '+str(error),
                        evidence=outcomes[c['id']],next_check=c['next_check']))
        capabilities = model.readiness(contracts,outcomes)
        if definition_inputs(original_index,args,update)!=definitions or execution_inputs(original_index)!=tools:
            raise ValueError('Update definitions changed during profile preparation')
        source_metrics=store.validate()
        bundle=index.extension('update-bundle').prepare(index,args,contracts,outcomes,capabilities,profiles,contexts,report)
        # Preparation may read further immutable artifacts; validate them before
        # publishing the final journal and next-use pointers.
        source_metrics=store.validate()
        if update.signatures(args.install,roots)!=installed_stamps:
            raise ValueError('Installation inventory changed during update; resume after download completes')
        publisher=index.extension('update-bundle')
        if hasattr(publisher,'publish'):
            bundle=publisher.publish(index,args,bundle,
                tooling_checks=[c for c in extra_checks if c.get('source_scope')=='tooling'])
        queue.extend(bundle.get('queue',[]))
        record.update(state='needs_review' if queue else 'prepared_offline', queue=queue,
            capabilities=capabilities, profiles=profiles, reused_stages=journal.reused,
            update_checks=extra_checks,
            prepared_bundles=bundle,
            baseline_promoted=False, profile_activation=False, live_verified=False)
        native_blockers=[*native_contexts['queue'],*[dict(reason=c['id']+': '+c['state'],details=c.get('reason'))
            for c in native_checks if c['state']!='passed']]
        record['root_blockers']=root_blockers(contracts,outcomes,queue,native_blockers)+function_blockers(index,function_reuse,contracts)
        record['metrics']=dict(reused_stages=journal.reused,manual_tasks=len(queue),
            wall_seconds=round(time.perf_counter()-run_started,6),executed_stages=journal.executed,
            cached_stage_validation_seconds=journal.validation_seconds,
            source_store=source_metrics,unique_checks=len(checked_this_run)+len(native_checks),
            check_consumers=sum(len(c['checks']) for c in contracts['contracts'])+len(extra_checks),
            root_blockers=len(record['root_blockers']),legacy_queue_observations=len(queue),
            profile_validation_seconds=round(profile_validation_seconds,6),
            ready_exports=sum(e.get('state')=='ready' for e in exports),
            ghidra_batches=sum(k.startswith('exports-') for k in record['stages']),
            completed_ghidra_launches_this_run=sum(k.startswith('exports-') and
                record['stages'][k].get('result',{}).get('state')=='collected' for k in journal.executed),
            context_replays_this_run=sum(k.startswith('context-check-') for k in journal.executed),
            native_replays_this_run=sum(k.startswith('native-check-') for k in journal.executed),
            reused_phase_times_are_original=True,
            phase_seconds={k:v.get('seconds',0) for k,v in record['stages'].items()})
        save(workflow,path,record)
        return dict(run=str(path), state=record['state'], source_sha256=sha, queue=len(queue),
            capabilities=capabilities, profiles=profiles, reused_stages=journal.reused,
            prepared_bundles=bundle,root_blockers=len(record['root_blockers']),metrics=record['metrics'],
            baseline_promoted=False, profile_activation=False,
            function_reuse=function_reuse.get('summary',{}))
    except BaseException as error:
        if path is not None and path.is_file():
            try:
                failed=read(index,workflow,path,args.root)
                failed.update(state='interrupted' if isinstance(error,KeyboardInterrupt) else 'failed',reason=str(error))
                save(workflow,path,failed)
            except (ValueError,OSError,KeyError):pass  # Never overwrite a corrupt journal.
        raise


def function_equivalences(contexts, sha):
    """Only every occurrence of an address may authorize skipping its export.

    The binding resolver owns instruction/data/callee verification. This adapter
    requires its complete, source-bound result rather than a candidate address.
    """
    occurrences = {}
    if contexts.get('source_sha256',sha) != sha:
        raise ValueError('Function equivalence source differs')
    for contract, context in contexts['contracts'].items():
        for key, address in context['bindings'].items():
            proof = context.get('verification',{}).get(key,{})
            if not isinstance(proof,dict):proof={}
            shape = context.get('closed_shapes',{}).get(key)
            verified = (proof.get('state') in ('unchanged','moved_verified')
                and proof.get('address') == address
                and isinstance(shape,str) and re.fullmatch('[0-9a-f]{64}',shape)
                and proof.get('closed_shape_sha256') == shape
                and proof.get('scope') == 'declared_instruction_callee_data_closure'
                and proof.get('runtime_activated') is False
                and isinstance(proof.get('baseline_sha256'),str)
                and re.fullmatch('[0-9a-f]{64}',proof['baseline_sha256'])
                and isinstance(proof.get('baseline_address'),str)
                and re.fullmatch('0x[0-9a-f]+',proof['baseline_address'])
                and isinstance(address,str) and re.fullmatch('0x[0-9a-f]+',address)
                and (proof['state']=='unchanged') == (address==proof.get('baseline_address')))
            occurrences.setdefault(address,[]).append(dict(contract=contract,key=key,
                proof=proof if verified else None))
    return {address:rows for address,rows in occurrences.items()
        if rows and all(row['proof'] is not None for row in rows)}


def apply_function_reuse(index, root, model, contexts, sha, result):
    """Attach exact baseline-address proofs to missing reviewed bindings only."""
    if result.get('state')=='skipped' or not result.get('report'):return contexts
    path=Path(result['report']).resolve()
    if (not path.is_relative_to((root/'knowledge/function-reuse-catalog').resolve()) or path.name!='manifest.json'
            or index.digest(path)!=result.get('sha256') or path.parent.name!=result['sha256']):
        raise ValueError('Function catalog receipt changed')
    report=index.read_json(path)
    if (report.get('target_sha256')!=sha or report.get('identity',{}).get('target_sha256')!=sha
            or report.get('scope')!='function_only'
            or report.get('runtime_activated') is not False or report.get('profile_activated') is not False):
        raise ValueError('Function catalog source or scope changed')
    tools=report['identity'].get('tools',{})
    required={'function-reuse-plan.py','update-bindings.py','build-native-entry-code.py',
        'extract-native-enums.py','research-workflow.py','update-contracts.py','native-release-registry.py',
        'update-native-contexts.py','verify-utf8-context.py','update-native-harness.py'}
    if set(tools)!=required or any(index.digest(index.HERE/name)!=tools[name] for name in required):
        raise ValueError('Function catalog tools changed')
    sources=report['identity'].get('sources',{})
    if any(identity!=actual or not re.fullmatch('[0-9a-f]{64}',identity) for identity,actual in sources.items()):
        raise ValueError('Function catalog source identities changed')
    declared={item['id']:item for item in report['contracts']}
    candidates={}
    for batch in report['verification']:
        batch_id=batch['id']
        if batch_id not in declared:raise ValueError('Function catalog batch not declared')
        valid=function_equivalences(dict(source_sha256=sha,contracts={batch_id:batch}),sha)
        for address,rows in valid.items():
            for row in rows:
                proof=row['proof'];baseline=proof['baseline_sha256'];before=proof['baseline_address']
                if (baseline not in sources
                        or declared[batch_id].get('bindings',{}).get(baseline,{}).get(row['key'])!=before):
                    raise ValueError('Function catalog baseline binding changed')
                candidates.setdefault((baseline,before),[]).append(proof)
    revised=copy.deepcopy(contexts)
    planner=index.extension('function-reuse-plan')
    if hasattr(planner,'ordered_sources'):
        ordered=planner.ordered_sources(index.HERE/'knowledge',root)
    else:
        ordered=[source for version,source in sorted(planner.SOURCES.items(),key=lambda item:int(item[0]),reverse=True)]
    for contract in model['contracts']:
        selected=revised['contracts'][contract['id']]
        for recipe in contract['recipes']:
            key=recipe['key']
            if recipe['method']!='reviewed' or key in selected['bindings']:continue
            matches=[]
            applicable=[source for source in ordered if key in contract['bindings'].get(source,{})]
            # A newer declaration blocks an older role even when its proof is
            # still missing. Unknown multi-baseline histories stay unresolved.
            baselines=applicable[:1] if applicable else (list(contract['bindings']) if len(contract['bindings'])==1 else [])
            for baseline in baselines:
                bindings=contract['bindings'][baseline]
                before=bindings.get(key)
                matches.extend(candidates.get((baseline,before),[]))
            if not matches:continue
            addresses={proof['address'] for proof in matches}
            if len(addresses)!=1:continue
            # Same baseline proof can be shared by several aliases; selection is
            # by source/address, never by analytical role name or closest offset.
            proof=copy.deepcopy(sorted(matches,key=lambda item:(item['baseline_sha256'],item['baseline_address']))[0])
            proof['function_reuse_receipt']=dict(path=str(path),sha256=result['sha256'])
            selected['bindings'][key]=proof['address']
            selected.setdefault('closed_shapes',{})[key]=proof['closed_shape_sha256']
            selected.setdefault('verification',{})[key]=proof
            selected['queue']=[reason for reason in selected['queue']
                if reason!=key+': missing or ambiguous reviewed candidate']
    return revised


def export_satisfies(index, root, sha, contract, context, export):
    """Code equivalence is usable evidence, never a native export or semantic check."""
    if export.get('state') == 'ready':return True
    if export.get('state') != 'equivalent':return False
    try:
        path=Path(export['report']).resolve()
        if (not path.is_relative_to((root/'knowledge/function-equivalence-results').resolve())
                or path.name!='manifest.json' or index.digest(path)!=export['sha256']
                or path.parent.name!=export['sha256']):return False
        receipt=index.read_json(path)
        expected=function_equivalences(dict(source_sha256=sha,contracts={contract:context}),sha)
        address=export['address']
        wanted=expected.get(address,[])
        actual=[row for row in receipt['bindings'] if row.get('contract')==contract]
        return (receipt.get('source_sha256')==sha and receipt.get('address')==address
            and receipt.get('scope')=='function_only' and receipt.get('runtime_activated') is False
            and receipt.get('semantic_checks_bypassed') is False and bool(wanted) and actual==wanted
            and {sha}|{row['proof']['baseline_sha256'] for row in wanted} <= set(receipt['source_identities'])
            and receipt.get('tools')=={name:index.digest(index.HERE/name) for name in
                ('update-bindings.py','build-native-entry-code.py','extract-native-enums.py')})
    except (KeyError,ValueError,OSError,TypeError):return False


def collect_batches(index, workflow, journal, args, database, contexts, sha):
    addresses = sorted({at for c in contexts['contracts'].values() for at in c['bindings'].values()}, key=lambda a:int(a,16))
    source = args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
    results = []
    equivalent=function_equivalences(contexts,sha)
    receipts={}
    if equivalent:
        tools={name:index.digest(index.HERE/name) for name in
            ('update-bindings.py','build-native-entry-code.py','extract-native-enums.py')}
        # Both snapshots are checked in full; a receipt never trusts file metadata.
        identities={sha}|{row['proof']['baseline_sha256'] for rows in equivalent.values() for row in rows}
        for identity in identities:
            selected=args.root/'client-code-snapshots'/identity/'ProjectRED-Win64-Shipping.exe'
            if index.digest(selected)!=identity:raise ValueError('Function equivalence snapshot changed')
        for address,proofs in equivalent.items():
            binding_stage=getattr(journal,'run',{}).get('stages',{}).get('bindings',{})
            receipt=dict(schema=1,source_sha256=sha,address=address,bindings=proofs,tools=tools,
                binding_stage_key=binding_stage.get('key'),
                resolver_inputs_sha256=fingerprint(workflow,binding_stage['inputs']) if binding_stage.get('inputs') else None,
                resolver_tools=binding_stage.get('inputs',{}).get('tools'),
                source_identities=sorted(identities),scope='function_only',runtime_activated=False,
                semantic_checks_bypassed=False,
                limits=['Declared instruction/callee/data closure only; source semantic checks remain required.'])
            path=workflow.snapshot(args.root,'function-equivalence-results',receipt)
            receipts[address]=dict(report=str(path),sha256=index.digest(path))
    db = index.open_index(database)
    try: missing = [a for a in addresses if a not in equivalent and workflow.function_state(index,db,sha,a)['state'] != 'ready']
    finally: db.close()
    for start in range(0,len(missing),32):
        batch = missing[start:start+32]
        request = dict(schema=1,source_sha256=sha,source=str(source),require_installed_match=False,
            functions=[dict(address=a) for a in batch],inputs={str(source):sha},reason='Explicit resolved contract batch; no automatic call-tree expansion')
        path = workflow.snapshot(args.root,'update-export-requests',request)
        subargs = SimpleNamespace(**vars(args)); subargs.request = path
        projects={str(p):index.digest(p) for p in (args.root/'ghidra/request-projects'/sha).glob('project.json')}
        projects.update({str(p):index.digest(p) for p in (args.root/'ghidra/release-comparisons').glob('*/run-*/provenance.json')})
        result = journal.stage('exports-'+fingerprint(workflow,batch)[:16],dict(request=index.digest(path),source=sha,projects=projects,
            tools={n:index.digest(index.HERE/n) for n in ('collect-requested-functions.py','InspectVampirSdkProfile.java','ghidra-tools.lock.json')}),
            lambda:workflow.collector(index,subargs,request,batch))
        results.append(result)
    if missing: index.build(args.root,database,knowledge=args.knowledge)
    # Pin the actual ready materials, including exports reused without a JVM.
    db = index.open_index(database)
    try:
        for at in addresses:
            if at in receipts:
                results.append(dict(address=at,state='equivalent',artifacts=[],**receipts[at]))
                continue
            f = workflow.function_state(index,db,sha,at)
            results.append(dict(address=at,state=f['state'],artifacts=[dict(path=v['artifact'],sha256=index.digest(v['artifact']))
                for v in f['variants'] if v['completed']]))
    finally: db.close()
    return results


def build_profile(index, workflow, args, contract, outcomes, sha, contexts):
    # This dispatch is intentionally a fixed allowlist, never a command from JSON.
    if contract['builder'] != 'sdk-launcher': raise ValueError('Unreviewed builder')
    return index.extension('update-profile').build(index,workflow,args,contract,outcomes,sha,contexts)
