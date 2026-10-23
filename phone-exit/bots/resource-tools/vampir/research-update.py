"""Explicit post-download audit and offline resource refresh; no scheduler/login."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def signatures(install, extra_roots=()):
    roots = {install / 'ProjectRED/Content/Paks', install / 'ProjectRED/Saved/PersistentDownloadDir/Patch/Install', *extra_roots}
    paths = {p.resolve() for root in roots if root.is_dir() for p in root.rglob('*')
        if p.is_file() and p.suffix.lower() in ('.pak', '.utoc', '.ucas')}
    exe = install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    paths.add(exe.resolve())
    return {str(p): (p.stat().st_size, p.stat().st_mtime_ns) for p in sorted(paths)}


def audit_install(index, workflow, args):
    baseline = workflow.checked_manifest(index, args.baseline)
    install = args.install.resolve()
    if Path(baseline['source']).resolve() != install: raise ValueError('Baseline belongs to another installation')
    audit = index.extension('audit-client-release')
    extra_roots = set()
    for row in baseline['files']:
        path = Path(row['path']).resolve()
        if not path.is_relative_to(install) or path.suffix.lower() not in ('.pak','.utoc','.ucas'):
            raise ValueError('Baseline archive outside public installation scope')
        extra_roots.add(path.parent)
    before = signatures(install,extra_roots)
    rows = []
    old = {str(Path(r['path']).resolve()):r.get('current') for r in baseline['files']}
    exe = str((install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe').resolve())
    exe_sha = None
    for name, stamp in before.items():
        path = Path(name)
        sha = index.digest(path)
        if (path.stat().st_size, path.stat().st_mtime_ns) != stamp:
            raise ValueError('Installation changed while hashing; no baseline accepted')
        if name == exe:
            exe_sha = sha
            continue
        sample = audit.inspect_archive(path)
        sample['sha256'] = sha
        previous = old.pop(name, None)
        rows.append(dict(path=name, current=sample, baseline=previous,
            status='sample_matches_unverified' if previous and previous.get('sha256') == sha else 'changed'))
    for name, previous in old.items():
        if not Path(name).resolve().is_relative_to(install): raise ValueError('Baseline archive outside installation')
        rows.append(dict(path=name, current=None, baseline=previous, status='removed'))
    if before != signatures(install,extra_roots): raise ValueError('Installation changed during audit; no baseline accepted')
    report = dict(schema=1, source=str(install), exe=dict(path=exe, sha256=exe_sha), files=rows,
        full_archive_coverage=True, compatibility='not_established', baseline_path=str(args.baseline.resolve()),
        baseline_sha256=index.digest(args.baseline), tool_sha256=index.digest(Path(__file__)),
        stability='Inventory, size and mtime checked before/after full hashes; not a launcher completion signal')
    target = workflow.snapshot(args.root, 'update-audits', report)
    # Existing adapters expect content-addressed release manifests; this shape is compatible.
    destination = args.root / 'client-code-snapshots' / exe_sha / Path(exe).name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if index.digest(destination) != exe_sha: raise ValueError('Existing EXE snapshot is corrupt')
    else:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
        try:
            shutil.copyfile(exe, temporary)
            if index.digest(temporary) != exe_sha: raise ValueError('EXE changed during snapshot copy')
            temporary.replace(destination)
        finally:
            if temporary.exists(): temporary.unlink()
    if before != signatures(install,extra_roots): raise ValueError('Installation changed during source snapshot')
    return baseline, report, target


def execute_adapter(index, args, tool, arguments):
    command = [sys.executable, '-X', 'utf8', str(index.HERE / tool), *map(str, arguments)]
    with tempfile.TemporaryFile() as log:
        try:
            env = os.environ.copy()
            env['PHONEEXIT_VAMPIR_RESOURCES'] = str(args.root.resolve())
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1800, env=env)
            state = 'passed' if completed.returncode == 0 else 'failed'
        except subprocess.TimeoutExpired: state = 'timeout'
        log.seek(0)
        raw = log.read(8*1024*1024)
    text = raw.decode('utf-8', errors='replace')
    payload = None
    position = 0
    while position < len(text):
        position = text.find('{',position)
        if position < 0: break
        try:
            parsed, length = json.JSONDecoder().raw_decode(text[position:])
            if isinstance(parsed, dict): payload = parsed
            position += length
        except ValueError: position += 1
    return dict(tool=tool, state=state, result=payload,
        # Public resource tools only; retain diagnostics outside Git.
        diagnostic=text if state != 'passed' else None)


def update(index, args, database):
    workflow = index.extension('research-workflow')
    with workflow.locked(args.root, 'research'):
        baseline, report, manifest = audit_install(index, workflow, args)
        normalized = dict(baseline, files=[dict(row, path=str(Path(row['path']).resolve())) for row in baseline['files']])
        comparison = index.extension('compare-release-snapshots').compare(normalized, report)
        tasks, resources = [], []
        native_targets = None
        for row in comparison['files']:
            if row['status'] == 'removed':
                tasks.append(dict(archive=row['path'],state='requires_review',reason='Archive removed; review resource dependents'))
        new_sha = report['exe']['sha256']
        if baseline['exe']['sha256'] != new_sha:
            for question in index.read_json(args.knowledge / 'questions.json')['questions']:
                tasks.append(dict(question=question['id'], source_sha256=new_sha, state='requires_review',
                    reason='EXE changed; historical addresses and claims are not transferred',
                    next_action='Find current function candidates, then prepare explicit addresses'))
            if not args.audit_only:
                native_targets = execute_adapter(index, args, 'locate-release-update-targets.py',
                    ['--root', args.root, '--source-sha256', new_sha,
                     '--targets', args.knowledge / 'release-update-targets.json'])
                if native_targets['state'] != 'passed':
                    tasks.append(dict(state='requires_review', reason='Native target discovery failed; inspect diagnostics, do not transfer old addresses'))
                elif any(row['state'] != 'candidate' for row in (native_targets.get('result') or {}).get('candidates', [])):
                    tasks.append(dict(state='requires_review', reason='Native anchors have missing, ambiguous or undecodable candidates; export explicit functions'))
        if not args.audit_only:
            for row in report['files']:
                current = row['current']
                if not current or current.get('sha256') == (row.get('baseline') or {}).get('sha256'): continue
                if current.get('pak_version') != 11:
                    tasks.append(dict(archive=row['path'], state='requires_review', reason='No reviewed resource adapter for this archive format'))
                    continue
                if Path(row['path']).name in ('ProjectRED-Windows.pak', 'pakchunk0-Windows.pak'):
                    config = execute_adapter(index,args,'recover-release-game-config.py',
                        [manifest,'--archive',row['path']])
                    resources.append(config)
                    if config['state'] != 'passed':
                        tasks.append(dict(archive=row['path'],state='requires_review',
                            reason='Named config extraction failed; historical key candidate is not assumed compatible'))
                result = execute_adapter(index, args, 'index-release-archives.py',
                    [manifest, '--archive-sha256', current['sha256']])
                resources.append(result)
                if result['state'] != 'passed':
                    tasks.append(dict(archive=row['path'], state='requires_review', reason='Resource indexing failed; inspect update report'))
                    continue
                # Existing adapter stores one summary per selected archive.
                summaries = sorted((manifest.parent / 'index-summaries').glob('*/manifest.json'))
                selected = [p for p in summaries if workflow.checked_manifest(index,p).get('selected_archive_sha256') == current['sha256']]
                if len(selected) != 1:
                    tasks.append(dict(archive=row['path'], state='requires_review', reason='Missing or ambiguous resource index summary'))
                    continue
                summary = workflow.checked_manifest(index, selected[0])
                for archive in summary['archives']:
                    record = Path(archive['report'])
                    for tool, previous in (
                        ('compare-release-assets.py', args.root / 'pak-extracted' / Path(row['path']).stem / 'entries.json'),
                        ('extract-release-tables.py', args.root / 'table-study/index.json')):
                        if previous.is_file():
                            step = execute_adapter(index,args,tool,[record,previous])
                            resources.append(step)
                            if step['state'] != 'passed': tasks.append(dict(archive=row['path'],state='requires_review',reason=tool+' failed'))
                        else: tasks.append(dict(archive=row['path'], state='requires_review', reason='Missing historical input for ' + tool))
                    tasks.append(dict(archive=row['path'], state='requires_review',
                        reason='Review affected UI/map/table links; extracted bytes alone do not prove semantic compatibility'))
        if args.audit_only:
            statuses = {r['status'] for r in comparison['files']}
            if statuses & {'content_changed','added'}:
                tasks.append(dict(state='requires_resources', reason='Audit-only: changed resources have not been processed'))
            if statuses & {'sample_equal_content_unverified','metadata_changed_content_unverified'}:
                tasks.append(dict(state='requires_review', reason='Baseline lacks full hashes for some archives; sample equality does not prove unchanged content'))
        index.build(args.root, database, knowledge=args.knowledge)
        final = dict(schema=1, source_sha256=new_sha, manifest=str(manifest), comparison=comparison,
            resources=resources, native_targets=native_targets, queue=tasks, baseline_promoted=False, compatibility='not_established',
            schedule='Manual post-download command; Wednesday is informational, no scheduled task created')
        target = workflow.snapshot(args.root, 'update-results', final)
        return dict(report=str(target), manifest=str(manifest), source_sha256=new_sha,
            changed_exe=not comparison['exe']['full_hash_equal'], queue=len(tasks),
            resource_steps=len(resources), baseline_promoted=False)
