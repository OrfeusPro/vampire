"""Assemble an explicitly disabled game candidate from current immutable proofs only."""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import locale
from pathlib import Path
import platform
import struct
import sys

HERE=Path(__file__).resolve().parent
WORKSPACE=HERE.parents[3]
ROOT=Path('F:/PhoneExit Resources/Vampir')
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
CONFIG='f93042b23066af7a5a6dfedaa554f12dc88302e4a9f260da4ced0538db7f5251'
TAG_POINTER=0x14b1bbe98
TAG_LITERAL=0x149961820
TAG='32283C4C6485307BCF524765A84409C3'
REQUIRED=frozenset(('native-archive-wire-context','native-login-prepare-context',
    'native-version-prepare-context','native-version-result-context',
    'native-version-result-handler-context','native-login-result-context',
    'native-waiting-end-context','native-character-list-records-context',
    'native-character-list-handler-context','compiled-tag-native-11316',
    'version-login-context','native-login-clock-ping-current','release-ping-producer',
    'release-ping-result','periodic-ping-policy','native-world-entry-probe-current'))
CAPABILITIES=('version','login','character-list','initial-ping','bounded-world-probe')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def document(path,expected):
    path=Path(path)
    if path.stat().st_size>32*1024*1024 or digest(path)!=expected:
        raise ValueError('Candidate manifest/report hash changed')
    return json.loads(path.read_bytes())


def verify_checks(proofs,root):
    """No execution: compare complete registered definitions and mutable dependencies."""
    root=Path(root).resolve()
    if type(proofs) is not dict or set(proofs)!=REQUIRED:
        raise ValueError('Candidate requires the complete explicit current check set')
    workflow=load('research-workflow')
    registry=json.loads((HERE/'knowledge/research-checks.json').read_bytes())['checks']
    definitions={c['id']:c for c in registry}
    result={}
    for name in sorted(REQUIRED):
        row=proofs[name]
        if type(row) is not dict or set(row)!={'path','sha256'}:
            raise ValueError('Candidate proof must contain only explicit path and SHA')
        path=Path(row['path']).resolve()
        if (not path.is_relative_to(root/'knowledge/check-results') or path.name!='manifest.json'
                or path.parent.name!=row['sha256']):
            raise ValueError('Candidate check report outside current proof library')
        report=document(path,row['sha256']);definition=report['definition']
        check=definitions[name]
        if (check.get('offline_reviewed') is not True or SHA not in check['source_sha256']
                or workflow.source_scope(check)!='client'):
            raise ValueError('Candidate check is not reviewed for this source')
        check=workflow.source_definition(check,SHA)
        if (report.get('state')!='passed' or definition.get('source_sha256')!=SHA
                or definition.get('check')!=check):
            raise ValueError('Candidate check source/state/definition differs')
        expected_paths={(WORKSPACE/'phone-exit/bots'/check['test_pattern']).resolve()}
        expected_paths.update((WORKSPACE/name).resolve() for name in check['dependencies'])
        if {Path(p).resolve() for p in definition['inputs']}!=expected_paths:
            raise ValueError('Candidate check dependency set differs')
        for filename,expected in definition['inputs'].items():
            path_input=Path(filename).resolve()
            if not path_input.is_relative_to(WORKSPACE) or digest(path_input)!=expected:
                raise ValueError('Candidate check dependency changed')
        if (definition['runner_sha256']!=digest(HERE/'research-workflow.py')
                or definition['python_version']!=platform.python_version()
                or definition['executable']!=sys.executable):
            raise ValueError('Candidate check runner/Python changed')
        declared={(root/name).resolve() for name in check.get('artifact_dependencies',[])}
        declared.update(Path(p).resolve() for p in workflow.system_runtime_files(check.get('system_runtime_files',[])))
        # The workflow can add full source-archive dependencies for resource
        # manifests. This candidate's required native checks use explicit exports.
        if {Path(p).resolve() for p in definition['artifacts']}!=declared:
            raise ValueError('Candidate check artifact set differs')
        for filename,expected in definition['artifacts'].items():
            if digest(filename)!=expected:raise ValueError('Candidate check artifact changed')
        runtime={}
        for distribution in check.get('runtime_distributions',[]):
            selected=[d for d in importlib.metadata.distributions(path=[str(HERE.parents[2]/'.tools/vampir-analysis')])
                      if d.metadata['Name'].lower()==distribution.lower()]
            if len(selected)!=1:raise ValueError('Candidate native runtime missing/ambiguous')
            runtime[distribution]=dict(version=selected[0].version,
                record_sha256=hashlib.sha256((selected[0].read_text('RECORD') or '').encode()).hexdigest())
        if runtime!=definition['runtime_metadata']:raise ValueError('Candidate native runtime changed')
        if check.get('system_runtime_files') and definition.get('system_runtime_locale')!=locale.setlocale(locale.LC_ALL):
            raise ValueError('Candidate CRT locale changed')
        result[name]=dict(path=str(path),sha256=row['sha256'])
    return result


def resource_profile(root):
    root=Path(root);path=root/'resource-config-snapshots'/CONFIG/'manifest.json'
    manifest=document(path,CONFIG)
    if (manifest['exe_sha256']!=SHA or manifest.get('authoritative_directory_for_archive') is not True
            or manifest.get('active_runtime_settings_verified') is not False):
        raise ValueError('Candidate resource source/boundary differs')
    source=Path(manifest['source_exe']);archive=Path(manifest['source_archive']['path'])
    if digest(source)!=SHA or digest(archive)!=manifest['archive_sha256']:
        raise ValueError('Candidate installed source/archive changed')
    # This snapshot was extracted from the update workflow's audit, whose
    # immutable storage category differs from the older release-snapshots.
    release=root/'knowledge/update-audits'/manifest['release_manifest_sha256']/'manifest.json'
    release_report=document(release,manifest['release_manifest_sha256'])
    rows=[row for row in release_report['files'] if Path(row['path']).resolve()==archive.resolve()]
    if (release_report['exe']['sha256']!=SHA
            or Path(release_report['exe']['path']).resolve()!=source.resolve()
            or len(rows)!=1 or rows[0]['current']['sha256']!=manifest['archive_sha256']
            or rows[0]['current']['size']!=archive.stat().st_size):
        raise ValueError('Candidate source/archive absent from exact release audit')
    configs=[c for c in manifest['configs'] if c['snapshot_file']=='DefaultGame.ini']
    if len(configs)!=1:raise ValueError('Candidate base config missing/ambiguous')
    config=configs[0];ini=path.parent/'DefaultGame.ini'
    if digest(ini)!=config['payload_sha256']:raise ValueError('Candidate INI changed')
    lines=ini.read_text('utf-8-sig').splitlines();values={}
    for row in config['values']:
        if row['section']!='NetworkSetting':continue
        key,separator,value=lines[row['line']-1].strip().partition('=')
        if not separator or (key.strip(),value.strip())!=(row['key'],row['value']) or row['key'] in values:
            raise ValueError('Candidate INI row provenance differs')
        values[row['key']]=row['value']
    if values.get('CdnConfig')!='True' or values.get('AppVersion')!='1.13.18' or values.get('ConfigPrefix')!='real':
        raise ValueError('Candidate recovered base values differ')
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sdk_config import prepare_cdn_config_url_ascii
    url='https://'+prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'],qa=values['CdnConfigUrlQA'],
        prefix=values['ConfigPrefix'],app_version=values['AppVersion'],platform_code=2)
    if url!='https://red.gcdn.netmarble.com/red/config/window/real/1_13_18/config.json':
        raise ValueError('Candidate CDN URL differs')
    native=load('build-native-entry-code');raw=source.read_bytes();image=native.Image(raw)
    pointer=image.offset(TAG_POINTER-image.pe.base);literal=image.offset(TAG_LITERAL-image.pe.base)
    if struct.unpack_from('<Q',raw,pointer)[0]!=TAG_LITERAL or raw[literal:literal+33]!=(TAG+'\0').encode():
        raise ValueError('Candidate compiled tag pointer/literal differs')
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Candidate EXE changed during tag check')
    if (digest(path)!=CONFIG or digest(ini)!=config['payload_sha256']
            or digest(source)!=SHA or digest(archive)!=manifest['archive_sha256']
            or digest(release)!=manifest['release_manifest_sha256']):
        raise ValueError('Candidate resource inputs changed during verification')
    return dict(source_exe=str(source),source_sha256=SHA,config_snapshot_sha256=CONFIG,
        archive_sha256=manifest['archive_sha256'],ini_sha256=config['payload_sha256'],
        app_version=values['AppVersion'],config_prefix=values['ConfigPrefix'],cdn_url=url,
        compiled_tag=TAG,tag_pointer=hex(TAG_POINTER),tag_literal=hex(TAG_LITERAL),
        release_audit_path=str(release),release_audit_sha256=manifest['release_manifest_sha256'],
        config_precedence_verified=False,active_game_cache_verified=False,
        key_binding_in_current_exe_verified=manifest['key_binding_in_current_exe_verified'])


def build(proofs,root=ROOT):
    # Validate scope before any expensive source reads; incomplete evidence is
    # never filled from a historical profile or a latest-directory heuristic.
    checked=verify_checks(proofs,root)
    resource=resource_profile(root)
    if verify_checks(proofs,root)!=checked:raise ValueError('Candidate proofs changed during build')
    return dict(schema=1,name='candidate-11318',source_sha256=SHA,resource=resource,
        capabilities=list(CAPABILITIES),reports=checked,runtime_enabled=False,
        live_verified=False,network_ready=False,profile_activated=False,baseline_promoted=False,
        active_runtime_settings_verified=False,tool_sha256=digest(Path(__file__)),
        limits=['Explicit offline candidate only; loading or activating the runtime requires a separately reviewed integration.',
                'Recovered DefaultGame.ini is a base profile; precedence and active game cache are unverified.',
                'Native storage/services/HTTP boundaries remain declared fixtures; server acceptance is unverified.',
                'No character creation, tutorial, quest automation or indefinite-session admission.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proofs',type=Path,required=True,help='Explicit check ID to path/SHA mapping')
    parser.add_argument('--root',type=Path,default=ROOT)
    args=parser.parse_args();candidate=build(json.loads(args.proofs.read_bytes()),args.root)
    print(load('audit-client-release').save_snapshot(args.root/'game-source-candidates',candidate))
