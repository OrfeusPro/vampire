"""Resumable offline update journal. No login, active-profile or baseline writes."""
import hashlib
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
    def group(seeds):
        pending=[(index.HERE/name).resolve() for name in seeds]; found={}
        while pending:
            path=pending.pop()
            if str(path) in found:continue
            if len(found)>=256:raise ValueError('Tool dependency budget exceeded')
            found[str(path)]=index.digest(path) if path.is_file() else None
            if path.suffix!='.py' or not path.is_file():continue
            for node in ast.walk(ast.parse(path.read_text('utf-8-sig'))):
                if not isinstance(node,ast.Constant) or not isinstance(node.value,str):continue
                if len(node.value)>128 or not re.fullmatch(r'[A-Za-z0-9_./-]+',node.value):continue
                for name in (node.value,node.value+'.py'):
                    if not name.endswith('.py') or '\n' in name:continue
                    for parent in (index.HERE,index.HERE.parent):
                        child=(parent/name).resolve()
                        if child.is_relative_to(index.HERE.parent.resolve()) and child.is_file():pending.append(child)
        return found
    common={str(index.HERE/name):index.digest(index.HERE/name) for name in
        ('update-run.py','research-update.py','research-workflow.py','knowledge-index.py','knowledge-context.py')}
    groups={name:{**common,**group(seeds)} for name,seeds in {
        'resources':['recover-release-game-config.py','index-release-archives.py','compare-release-assets.py','extract-release-tables.py'],
        'discovery':['locate-release-update-targets.py'],
        'bindings':['update-bindings.py','update-contracts.py'],
        'contracts':['update-contracts.py'],
        'context':['verify-version-login-context.py','update-native-harness.py'],
        'profile':['update-profile.py']}.items()}
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
            save(self.workflow,self.path,self.run)
            return old['result']
        entry = dict(key=key, inputs=inputs, state='running', owner_pid=os.getpid(), started_at=time.time())
        self.run['stages'][name] = entry
        save(self.workflow, self.path, self.run)
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
        results_current=False if run['state'] in ('running','failed','interrupted') else None,
        installed_inputs_checked=False,
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
                    old_tables=index.read_json(previous).get('tables',[])
                    if any(Path(t['source']['path']).resolve()!=Path(row['path']).resolve() for t in old_tables):
                        steps.append(dict(tool=tool,state='requires_review',reason='Historical table index belongs to another archive'))
                        continue
                steps.append(update.execute_adapter(index, args, tool, [record, previous]))
            else:
                steps.append(dict(tool=tool,state='requires_review',reason='No matching historical input'))
    return dict(state='passed' if all(s['state'] == 'passed' for s in steps) else 'requires_review',
        reason='Resource extraction is not semantic compatibility; logical paths may remain unknown', steps=steps,
        manifest=str(summaries[0]))


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
        definitions={str(p):index.digest(p) for p in [args.knowledge/'update-contracts.json',
            args.knowledge/'research-checks.json',*update.target_plans(index,args.knowledge)]}
        tools=execution_inputs(index)
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
        roots={Path(r['path']).parent for r in report['files']}
        installed_stamps=update.signatures(args.install,roots)
        identity = dict(baseline_sha256=index.digest(args.baseline), install=str(args.install.resolve()),
            source_sha256=sha, audit_sha256=index.digest(manifest))
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
        normalized = dict(baseline, files=[dict(r,path=str(Path(r['path']).resolve())) for r in baseline['files']])
        comparison = index.extension('compare-release-snapshots').compare(normalized, report)
        changed = [r for r in report['files'] if not r['current'] or
            r['current'].get('sha256') != (r.get('baseline') or {}).get('sha256')]
        changes = [dict(archive=r['path'], paths=None) for r in changed]
        dirty = model.affected(contracts, exe_changed=not comparison['exe']['full_hash_equal'], changes=changes)
        record['plan'] = dict(affected=dirty, contracts=contracts, tools=tools)
        if getattr(args, 'plan_only', False) or getattr(args, 'audit_only', False):
            record['state'] = 'planned'; record['queue'] = []
            save(workflow, path, record)
            return dict(run=str(path), state='planned', source_sha256=sha, affected=dirty,
                baseline_promoted=False, profile_activation=False)
        record['state']='running'
        record.pop('reason',None)
        save(workflow,path,record)
        queue = []
        for row in changed:
            result = journal.stage('resource-'+hashlib.sha256(row['path'].encode()).hexdigest()[:16],
                dict(archive=row, tools=tools['resources'], manifest=index.digest(manifest)),
                lambda row=row:resource_step(index,update,workflow,args,manifest,row))
            if result['state'] != 'passed': queue.append(dict(contract=None, capability='resources',
                reason=result['reason'], evidence=result, next_check='Inspect the named resource adapter or add a matching baseline'))
        discoveries = []
        for plan in update.target_plans(index, args.knowledge):
            discoveries.append(journal.stage('discovery-'+plan.name,
                dict(source=sha, plan_sha256=index.digest(plan), tools=tools['discovery']),
                lambda plan=plan:update.execute_adapter(index,args,'locate-release-update-targets.py',
                    ['--root',args.root,'--source-sha256',sha,'--targets',plan])))
        binding_tool = index.extension('update-bindings')
        contexts = journal.stage('bindings', dict(source=sha, contracts=contracts, discoveries=discoveries,
            tools=tools['bindings']),
            lambda:binding_tool.resolve(index, args, contracts, sha, discoveries))
        started=time.perf_counter()
        indexed=index.build(args.root,database,knowledge=args.knowledge)
        record['stages']['index-before-exports']=dict(state='completed',inputs=dict(source=sha),
            result=indexed,seconds=round(time.perf_counter()-started,6),outputs={})
        save(workflow,path,record)
        exports = collect_batches(index, workflow, journal, args, database, contexts, sha)
        outcomes = {}
        check_registry = workflow.registry(index,args.knowledge)['checks']
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
                    if adapter!='version-login-tag':raise ValueError('Unreviewed context adapter')
                    proof=index.extension('verify-version-login-context').verify(context,args.root)
                    proof['context_sha256']=index.digest(cp)
                    target=workflow.snapshot(args.root,'update-context-checks',proof)
                    return dict(id=adapter,state='passed',report=str(target),sha256=index.digest(target))
                try:
                    checked=journal.stage('context-check-'+name,dict(context=index.digest(cp),
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
                if export.get('address') in context['bindings']['bindings'].values() and export['state'] != 'ready':
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
        if any(index.digest(p)!=digest for p,digest in definitions.items()) or execution_inputs(index)!=tools:
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
        if any(index.digest(p)!=digest for p,digest in definitions.items()) or execution_inputs(index)!=tools:
            raise ValueError('Update definitions changed during profile preparation')
        if update.signatures(args.install,roots)!=installed_stamps:
            raise ValueError('Installation inventory changed during update; resume after download completes')
        record.update(state='needs_review' if queue else 'prepared_offline', queue=queue,
            capabilities=capabilities, profiles=profiles, reused_stages=journal.reused,
            update_checks=extra_checks,
            baseline_promoted=False, profile_activation=False, live_verified=False)
        record['metrics']=dict(reused_stages=journal.reused,manual_tasks=len(queue),
            wall_seconds=round(time.perf_counter()-run_started,6),executed_stages=journal.executed,
            cached_stage_validation_seconds=journal.validation_seconds,
            profile_validation_seconds=round(profile_validation_seconds,6),
            ready_exports=sum(e.get('state')=='ready' for e in exports),
            ghidra_batches=sum(k.startswith('exports-') for k in record['stages']),
            completed_ghidra_launches_this_run=sum(k.startswith('exports-') and
                record['stages'][k].get('result',{}).get('state')=='collected' for k in journal.executed),
            context_replays_this_run=sum(k.startswith('context-check-') for k in journal.executed),
            reused_phase_times_are_original=True,
            phase_seconds={k:v.get('seconds',0) for k,v in record['stages'].items()})
        save(workflow,path,record)
        return dict(run=str(path), state=record['state'], source_sha256=sha, queue=len(queue),
            capabilities=capabilities, profiles=profiles, reused_stages=journal.reused,
            baseline_promoted=False, profile_activation=False)
    except BaseException as error:
        if path is not None and path.is_file():
            try:
                failed=read(index,workflow,path,args.root)
                failed.update(state='interrupted' if isinstance(error,KeyboardInterrupt) else 'failed',reason=str(error))
                save(workflow,path,failed)
            except (ValueError,OSError,KeyError):pass  # Never overwrite a corrupt journal.
        raise


def collect_batches(index, workflow, journal, args, database, contexts, sha):
    addresses = sorted({at for c in contexts['contracts'].values() for at in c['bindings'].values()}, key=lambda a:int(a,16))
    source = args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
    results = []
    db = index.open_index(database)
    try: missing = [a for a in addresses if workflow.function_state(index,db,sha,a)['state'] != 'ready']
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
            f = workflow.function_state(index,db,sha,at)
            results.append(dict(address=at,state=f['state'],artifacts=[dict(path=v['artifact'],sha256=index.digest(v['artifact']))
                for v in f['variants'] if v['completed']]))
    finally: db.close()
    return results


def build_profile(index, workflow, args, contract, outcomes, sha, contexts):
    # This dispatch is intentionally a fixed allowlist, never a command from JSON.
    if contract['builder'] != 'sdk-launcher': raise ValueError('Unreviewed builder')
    return index.extension('update-profile').build(index,workflow,args,contract,outcomes,sha,contexts)
