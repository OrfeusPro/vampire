"""Explicit SDK launcher profile promotion; no network, auth or game compatibility claim."""
import hashlib
import importlib.util
import json
import locale
from pathlib import Path

HERE=Path(__file__).resolve().parent
INSTALLED=Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
REPORTS={
 'nid_base':('nid-context-11316','ba7dcda923ed58e82967bfdf38444e9f1499afea95c18ddf2436837ff4f84204'),
 'nid_helpers':('nid-primitives-11316','4c9c0bd27f4cfa2c8b4baf4c3a28fe2f7bf393d549b9289ac38ba5a385958ecb'),
 'geo':('gmc2-geo-11316','990e41054b9d890ca9611a358645da4a3d28ccca06958f5dd397ada8e9ae1a72')}


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def build(root=None,installed=INSTALLED):
    candidate=load('sdk_runtime_candidate',HERE/'build-sdk-profile-11316.py')
    native=load('sdk_runtime_root',HERE/'build-native-entry-code.py')
    root=Path(root) if root else native.ROOT
    if digest(Path(installed))!=candidate.SHA:raise ValueError('Installed SDK source differs')
    base=candidate.build(root=root)
    reports={};evidence=dict(base['evidence'])
    for name,(folder,sha) in REPORTS.items():
        path=root/'code-clues'/folder/sha/'manifest.json'
        if digest(path)!=sha:raise ValueError('SDK auth report changed: '+name)
        report=json.loads(path.read_text('utf-8'))
        if report['source_sha256']!=candidate.SHA:raise ValueError('SDK auth report source differs')
        for filename,expected in report['dependencies'].items():
            dependency=(HERE/filename).resolve()
            if not dependency.is_relative_to(HERE.resolve()) or digest(dependency)!=expected:
                raise ValueError('SDK auth report dependency changed: '+filename)
        for artifact in report['evidence']:
            source=Path(artifact['path']).resolve()
            if not source.is_relative_to((root/'ghidra').resolve()) or digest(source)!=artifact['sha256']:
                raise ValueError('SDK auth export changed')
        reports[name]=report;evidence[name]=dict(path=str(path),sha256=sha,limits=report['limits'])
    if len(reports['nid_base']['cases'])!=32 or len(reports['geo']['cases'])!=672:
        raise ValueError('SDK auth report coverage differs')
    helpers=reports['nid_helpers']
    if not helpers['native_primitives'] or len(helpers['cases'])!=1124:
        raise ValueError('SDK result helper coverage differs')
    crt=helpers['primitive_evidence']['crt']
    if digest(Path(crt['path']))!=crt['sha256'] or locale.setlocale(locale.LC_ALL)!=crt['locale']:
        raise ValueError('SDK auth CRT environment changed')
    launcher=load('sdk_runtime_launcher',HERE/'audit-release-launcher-contract.py').audit(root=root,source_sha=candidate.SHA)
    # The launcher audit has its own source/export/whole-root guards.
    evidence['launcher']=dict(audit_tool='audit-release-launcher-contract.py',
        audit_tool_sha256=digest(HERE/'audit-release-launcher-contract.py'),report=launcher)
    return dict(schema=1,name='recovered-release',source=str(Path(installed)),source_sha256=candidate.SHA,
        public_gmc2=base['public_gmc2'],nid=base['nid'],evidence=evidence,
        runtime_scope='sdk-launcher-auth',supported_auth_flows=['launcher'],direct_sdk_operations_verified=False,
        active_runtime_settings_verified=False,network_ready=False,game_protocol_verified=False,
        tool_sha256=digest(Path(__file__)),
        local_choices=['Initial real environment, NMENV absent, PC/raw webview type 0 and English UI are explicit choices.',
            'Device identity, country and Windows version must be observed afresh by the runner; no game cache borrowed.'],
        next_checks=['Direct SDK sign-in/fetch/sign-up/terms source port remains required.',
            'Separate live launcher session and current game profile/protocol checks remain required.'])


if __name__=='__main__':
    report=build();native=load('sdk_runtime_save_root',HERE/'build-native-entry-code.py')
    audit=load('sdk_runtime_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(native.ROOT/'sdk-source-profiles',report)
    print(json.dumps(dict(profile=str(path),source_sha256=report['source_sha256'],scope=report['runtime_scope'],network_ready=False)))
