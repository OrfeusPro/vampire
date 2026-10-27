"""Read-only current candidate proof validation; standard library, no analysis execution."""
import ctypes
import hashlib
import importlib.metadata
import json
import locale
from pathlib import Path
import platform
import sys

REQUIRED=frozenset(('native-archive-wire-context','native-login-prepare-context',
    'native-version-prepare-context','native-version-result-context',
    'native-version-result-handler-context','native-login-result-context',
    'native-waiting-end-context','native-character-list-records-context',
    'native-character-list-handler-context','compiled-tag-native-11316',
    'version-login-context','native-login-clock-ping-current','release-ping-producer',
    'release-ping-result','periodic-ping-policy','native-world-entry-probe-current'))
CAPABILITIES=['version','login','character-list','initial-ping','bounded-world-probe']


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def document(path,expected):
    path=Path(path)
    if path.stat().st_size>32*1024*1024 or digest(path)!=expected:
        raise ValueError('Current candidate proof changed')
    return json.loads(path.read_bytes())


def system_files(names):
    if names not in ([],['ucrtbase.dll']):raise ValueError('Unsupported candidate runtime library')
    if not names:return set()
    if sys.platform!='win32':raise ValueError('Candidate CRT requires Windows')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype=ctypes.c_uint
    value=ctypes.create_unicode_buffer(32768)
    size=kernel.GetSystemDirectoryW(value,len(value))
    if not 0<size<len(value):raise ValueError('Cannot resolve candidate CRT')
    return {(Path(value.value)/name).resolve() for name in names}


def current_definition(check,source_sha):
    if (check.get('source_scope','client')!='client' or check.get('offline_reviewed') is not True
            or source_sha not in check.get('source_sha256',[])):
        raise ValueError('Current candidate check is not reviewed')
    variant=check.get('source_variants',{}).get(source_sha)
    if variant is None:return check
    if not isinstance(variant,dict) or not variant or set(variant)-{
            'test_pattern','dependencies','artifact_dependencies','timeout_seconds'}:
        raise ValueError('Current candidate source variant changed')
    result={k:v for k,v in check.items() if k!='source_variants'}
    result.update(variant);result['selected_source_variant']=source_sha
    return result


def verify_candidate(*,root,workspace,source_sha,candidate_sha,config_sha):
    root,workspace=Path(root).resolve(),Path(workspace).resolve()
    tools=workspace/'phone-exit/bots/resource-tools/vampir'
    registry_path=tools/'knowledge/research-checks.json'
    registry_bytes=registry_path.read_bytes();registry=json.loads(registry_bytes)['checks']
    definitions={row['id']:row for row in registry}
    if len(definitions)!=len(registry):raise ValueError('Candidate check IDs ambiguous')
    path=root/'game-source-candidates'/candidate_sha/'manifest.json'
    candidate=document(path,candidate_sha)
    if (candidate.get('name')!='candidate-11318' or candidate.get('source_sha256')!=source_sha
            or candidate.get('capabilities')!=CAPABILITIES or set(candidate.get('reports',{}))!=REQUIRED
            or any(candidate.get(name) is not False for name in ('runtime_enabled','network_ready',
                'live_verified','profile_activated','baseline_promoted','active_runtime_settings_verified'))):
        raise ValueError('Current candidate scope changed')
    checked={}
    runtime_cache={}
    for name,item in candidate['reports'].items():
        report_path=Path(item['path']).resolve()
        if (set(item)!={'path','sha256'} or not report_path.is_relative_to(root/'knowledge/check-results')
                or report_path.name!='manifest.json' or report_path.parent.name!=item['sha256']):
            raise ValueError('Current candidate proof path changed')
        report=document(report_path,item['sha256']);definition=report['definition']
        check=current_definition(definitions[name],source_sha)
        if (report.get('state')!='passed' or definition.get('source_sha256')!=source_sha
                or definition.get('check')!=check):raise ValueError('Current candidate check definition changed')
        wanted={(workspace/'phone-exit/bots'/check['test_pattern']).resolve()}
        wanted.update((workspace/filename).resolve() for filename in check['dependencies'])
        if {Path(p).resolve() for p in definition['inputs']}!=wanted:
            raise ValueError('Current candidate dependency set changed')
        for filename,expected in definition['inputs'].items():
            dependency=Path(filename).resolve()
            if not dependency.is_relative_to(workspace):raise ValueError('Candidate dependency outside workspace')
            if dependency in checked and checked[dependency]!=expected:
                raise ValueError('Current candidate dependency proofs conflict')
            checked[dependency]=expected
        if (definition['runner_sha256']!=digest(tools/'research-workflow.py')
                or definition['python_version']!=platform.python_version()
                or definition['executable']!=sys.executable):raise ValueError('Candidate proof runtime changed')
        artifacts={(root/filename).resolve() for filename in check.get('artifact_dependencies',[])}
        artifacts.update(system_files(check.get('system_runtime_files',[])))
        if {Path(p).resolve() for p in definition['artifacts']}!=artifacts:
            raise ValueError('Current candidate artifact set changed')
        for filename,expected in definition['artifacts'].items():
            artifact=Path(filename).resolve()
            if artifact in checked and checked[artifact]!=expected:
                raise ValueError('Current candidate artifact proofs conflict')
            checked[artifact]=expected
        runtime={}
        for distribution in check.get('runtime_distributions',[]):
            if distribution not in runtime_cache:
                selected=[d for d in importlib.metadata.distributions(path=[str(workspace/'phone-exit/.tools/vampir-analysis')])
                          if d.metadata['Name'].lower()==distribution.lower()]
                if len(selected)!=1:raise ValueError('Candidate native runtime missing/ambiguous')
                runtime_cache[distribution]=dict(version=selected[0].version,
                    record_sha256=hashlib.sha256((selected[0].read_text('RECORD') or '').encode()).hexdigest())
            runtime[distribution]=runtime_cache[distribution]
        if runtime!=definition['runtime_metadata']:raise ValueError('Candidate native runtime changed')
        if check.get('system_runtime_files') and definition.get('system_runtime_locale')!=locale.setlocale(locale.LC_ALL):
            raise ValueError('Candidate CRT locale changed')
    for dependency,expected in checked.items():
        if digest(dependency)!=expected:raise ValueError('Current candidate dependency changed')
    resource=candidate['resource']
    if (resource.get('source_sha256')!=source_sha or resource.get('config_snapshot_sha256')!=config_sha
            or resource.get('app_version')!='1.13.18' or resource.get('config_prefix')!='real'
            or resource.get('active_game_cache_verified') is not False
            or resource.get('config_precedence_verified') is not False):
        raise ValueError('Current candidate resource scope changed')
    manifest_path=root/'resource-config-snapshots'/config_sha/'manifest.json'
    manifest=document(manifest_path,config_sha)
    source=Path(manifest['source_exe']).resolve();archive=Path(manifest['source_archive']['path']).resolve()
    if (manifest['exe_sha256']!=source_sha or resource['source_exe']!=str(source)
            or manifest['archive_sha256']!=resource['archive_sha256']
            or digest(source)!=source_sha or digest(archive)!=resource['archive_sha256']):
        raise ValueError('Current candidate installed source changed')
    configs=[r for r in manifest['configs'] if r['snapshot_file']=='DefaultGame.ini']
    if len(configs)!=1 or configs[0]['payload_sha256']!=resource['ini_sha256']:
        raise ValueError('Current candidate INI identity changed')
    if digest(manifest_path.parent/'DefaultGame.ini')!=resource['ini_sha256']:
        raise ValueError('Current candidate INI changed')
    audit_path=root/'knowledge/update-audits'/resource['release_audit_sha256']/'manifest.json'
    if audit_path.resolve()!=Path(resource['release_audit_path']).resolve():
        raise ValueError('Current candidate audit path changed')
    audit=document(audit_path,resource['release_audit_sha256'])
    rows=[r for r in audit['files'] if Path(r['path']).resolve()==archive]
    if (audit['exe']['sha256']!=source_sha or len(rows)!=1
            or rows[0]['current']['sha256']!=resource['archive_sha256']):
        raise ValueError('Current candidate audit source changed')
    if registry_path.read_bytes()!=registry_bytes:raise ValueError('Candidate registry changed during verification')
    return candidate
