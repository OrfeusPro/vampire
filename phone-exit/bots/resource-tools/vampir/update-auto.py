"""Automatic inventory baseline/resume selection; never logs in or activates runtime."""
import copy
import hashlib
import json
from pathlib import Path
import re

SHA=re.compile('[0-9a-f]{64}')
MAX_REPORTS=4096


def canonical(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_identity(path):
    stat=Path(path).stat()
    return dict(size=stat.st_size,modified_ns=stat.st_mtime_ns,changed_ns=stat.st_ctime_ns,
        device=stat.st_dev,file_id=stat.st_ino)


def inventory(index,install,extra_roots=()):
    install=Path(install).resolve()
    rows=index.extension('research-update').signatures(install,extra_roots)
    result={name:file_identity(name) for name in rows}
    patch=install/'ProjectRED/Saved/PersistentDownloadDir/Patch/windows.manifestlist'
    if patch.is_file():result[str(patch.resolve())]=dict(**file_identity(patch),sha256=index.digest(patch))
    return result


def definition_inputs(index,knowledge):
    """Actual definitions/tools, including helpers, tests and pinned runtime records.

    The watcher may use stamps as a change hint. Admission always uses these
    complete hashes; no mtime-only cross-run proof is introduced here.
    """
    knowledge=Path(knowledge).resolve()
    paths=set(knowledge.rglob('*.json'))
    paths.update(index.HERE.glob('*.py'));paths.update(index.HERE.glob('*.java'))
    paths.update(index.HERE.glob('*lock*.json'))
    bots=index.HERE.parents[1]
    paths.update(bots.glob('test_vampir*.py'))
    paths.update((bots/'vampir-shared/vampir_core').glob('*.py'))
    runtime=bots.parent/'.tools/vampir-analysis'
    paths.update(runtime.glob('*.dist-info/RECORD'))
    return {str(path.resolve()):index.digest(path) for path in sorted(paths) if path.is_file()}


def baseline_valid(value,install):
    if (value.get('full_archive_coverage') is not True or not isinstance(value.get('files'),list)
            or Path(value.get('source','')).resolve()!=Path(install).resolve()
            or not SHA.fullmatch(str(value.get('exe',{}).get('sha256','')))):
        return False
    expected=Path(install).resolve()/'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    if Path(value['exe'].get('path','')).resolve()!=expected:return False
    seen=set()
    for row in value['files']:
        path=Path(row.get('path','')).resolve()
        if not path.is_relative_to(Path(install).resolve()) or path in seen:return False
        seen.add(path)
        current=row.get('current')
        if current is not None and not SHA.fullmatch(str(current.get('sha256',''))):return False
    return True


def select_baseline(index,args):
    workflow=index.extension('research-workflow')
    candidates=[]
    for folder in ('knowledge/update-audits','release-snapshots'):
        candidates.extend((args.root/folder).glob('*/manifest.json'))
    if len(candidates)>MAX_REPORTS:raise ValueError('Inventory baseline search budget exceeded')
    # Modification time orders valid inventories, never certifies their bytes or
    # semantic readiness. The full content digest and source scope are checked.
    for path in sorted(candidates,key=lambda p:(p.stat().st_mtime_ns,str(p)),reverse=True):
        try:
            value=workflow.checked_manifest(index,path)
            if baseline_valid(value,args.install):return path,value
        except (OSError,ValueError,KeyError,TypeError):continue
    raise ValueError('Нет полного SHA inventory baseline этой установки; сначала нужен явный аудит')


def select(index,args):
    baseline,value=select_baseline(index,args)
    roots={Path(row['path']).parent for row in value['files']}
    before=inventory(index,args.install,roots)
    exe=Path(args.install)/'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    sha=index.digest(exe)
    definitions=definition_inputs(index,args.knowledge)
    if before!=inventory(index,args.install,roots):raise ValueError('Installation changed during automatic selection')
    identity=dict(install=str(Path(args.install).resolve()),source_sha256=sha,
        inventory=before,definitions=fingerprint(definitions))
    receipt=args.root/'knowledge/update-auto/selections'/(fingerprint(identity)+'.json')
    resume=None
    if receipt.is_file():
        saved=index.read_json(receipt)
        if saved.get('identity')!=identity:raise ValueError('Automatic selection receipt differs')
        path=Path(saved.get('run','')).resolve()
        if not path.is_relative_to((args.root/'knowledge/update-runs').resolve()):raise ValueError('Automatic run path outside journals')
        run=index.extension('update-run').read(index,index.extension('research-workflow'),path,args.root)
        if run.get('source_sha256')==sha and Path(run.get('install','')).resolve()==Path(args.install).resolve():resume=path
    return dict(baseline=baseline,baseline_value=value,resume=resume,identity=identity,receipt=receipt,
        definitions=definitions)


def execute(index,args,database):
    selection=select(index,args)
    explicit=copy.copy(args)
    explicit.auto=False;explicit.baseline=selection['baseline'];explicit.resume=selection['resume']
    def remember(path,record):
        if (record.get('source_sha256')!=selection['identity']['source_sha256']
                or Path(record.get('install','')).resolve()!=Path(args.install).resolve()):
            raise ValueError('Automatic journal source differs from frozen selection')
        index.extension('research-workflow').atomic(selection['receipt'],canonical(
            dict(schema=1,identity=selection['identity'],run=str(Path(path).resolve()))))
    explicit.journal_created=remember
    result=index.extension('research-update').update(index,explicit,database)
    workflow=index.extension('research-workflow')
    if result.get('run'):
        workflow.atomic(selection['receipt'],canonical(dict(schema=1,identity=selection['identity'],run=result['run'])))
    return dict(result,automatic_selection=dict(inventory_baseline=str(selection['baseline']),
        resumed=str(selection['resume']) if selection['resume'] else None,
        compatibility_baseline_promoted=False))
