"""Assemble an offline candidate profile from six immutable native reports."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
REPORTS={
    'defaults':('sdk-defaults-11316','085c6a31a21012e5c69cad2ac827397bcedc4efe3e1493d99a2c482874e5f04d',9),
    'override':('sdk-overrides-11316','eba1cef5cee42df5652d6db3c1918cbeda2eff85f3c34f1410ec683d9356b33a',106),
    'platform':('sdk-platform-11316','10192549a166a8f1d6db5a4f7f9e89accc5499ce0412db530f20ff1f9984e828',12),
    'start':('gmc2-base-11316','9e51498c82c4f5b24c84808e7af80eff36fec25f1b8c55c03d5fd37c4e882b75',512),
    'url':('gmc2-url-11316','265a47ec3dc9994169d3b1830a98bb422248d77e5fa27e103a4ea2cb07ab8129',27),
    'headers':('gmc2-headers-11316','c584aa6b57b1c6408d01b8d137fc86a1b448a19273ffba5a5600087ef6926007',73),
}


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(reports):
    """Cross-check independently recorded outputs, without inventing missing cases."""
    def unique(items,label):
        if len(items)!=1:raise ValueError('Missing or ambiguous '+label)
        return items[0]
    default=unique([c['values'] for c in reports['defaults']['cases'] if c['kind']=='settings_prefix' and c['poison']==0],'default case')
    if (default['build_code'],default['sdk_zone'],default['market'])!=(0,1,''):
        raise ValueError('Initial settings differ')
    game=unique([c['actual'] for c in reports['override']['cases'] if c['environment']=='real' and c['nmenv'] is None
                 and c['sdk_present'] and c['sdk_handle']],'production override')
    if (game['build_code'],game['sdk_zone'],game['market'],game['game_code'],game['raw_c8'])!=(0,2,'nmp','thered',0):
        raise ValueError('Production override differs')
    pc=[c for c in reports['platform']['cases'] if c['platform_byte']==3]
    if len(pc)!=4 or any(c['actual']!='PC' or not c['canaries_unchanged'] for c in pc):
        raise ValueError('PC cases missing or different')
    gmc=unique([c['values'] for c in reports['defaults']['cases'] if c['kind']=='gmc_constructor' and c['poison']==0],'GMC constructor')
    start=reports['start']['cases']
    if len({(c['zone'],c['flag']) for c in start})!=512:
        raise ValueError('Incomplete Start matrix')
    for case in start:
        offset={0:'0x150',2:'0x170',3:'0x180'}.get(case['zone'],'0x160')
        if case['source_offset']!=offset or case['destination_offset']!='0x1e8' or case['active_base']!=gmc[offset]:
            raise ValueError('Constructor and Start disagree')
    base={c['active_base'] for c in start if c['zone']==game['sdk_zone']}
    if base!={'https://apis.netmarble.com/gc2'}:raise ValueError('Production base differs')
    version=unique([c['values']['0x0'] for c in reports['defaults']['cases'] if c['kind']=='sdk_version'],'SDK version')
    url=unique([c['actual'] for c in reports['url']['cases'] if (c['base'],c['group'],c['build_code'],c['market'])==
                (next(iter(base)),gmc['0x1c8'],game['build_code'],game['market'])],'production URL')
    capture=unique([c for c in reports['headers']['cases'] if c['inputs']['url']==url and
        c['inputs']['game_code']==game['game_code'] and c['inputs']['service_code']==gmc['0x190'] and
        c['inputs']['build_code']==game['build_code'] and all(c['inputs'][key]=='' for key in
            ('device_key','access_token','player_id','etag'))],'public HTTP capture')
    profile=dict(base=next(iter(base)),group=gmc['0x1c8'],sdk_version=version,build_code=game['build_code'],
                 market=game['market'],game_code=game['game_code'],service_code=gmc['0x190'])
    # Portable code is an additional comparison, never a source for a missing native output.
    import sys
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sdk_config import assemble_gmc2_config_url_ascii
    from vampir_core.gmc2_request import plan_gmc2_get_request
    if url!=assemble_gmc2_config_url_ascii(**{k:profile[k] for k in ('base','group','sdk_version','build_code','market')}):
        raise ValueError('SDK version and native URL disagree')
    plan=plan_gmc2_get_request(**capture['inputs'])
    actual=capture['actual']
    if actual['url']!=url or actual['method']!=plan.method or tuple(map(tuple,actual['headers']))!=plan.headers:
        raise ValueError('Public HTTP capture disagrees')
    return dict(public_gmc2=dict(profile=profile,request=actual),nid=dict(profile=dict(
        game_code=game['game_code'],client_id=game['client_id'],build_code=game['build_code'],os_type='PC',
        raw_webview_type=0,country_code='',language='en',os_version='')))


def build(root=None):
    native=load('profile_11316_root',HERE/'build-native-entry-code.py')
    root=Path(root) if root else native.ROOT
    source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if digest(source)!=SHA:raise ValueError('Profile source SHA changed')
    reports,evidence={},{}
    for name,(folder,sha,count) in REPORTS.items():
        path=root/'code-clues'/folder/sha/'manifest.json'
        if digest(path)!=sha:raise ValueError('Profile native report changed: '+name)
        report=json.loads(path.read_text('utf-8'))
        if report['source_sha256']!=SHA or Path(report['source']).resolve()!=source.resolve():
            raise ValueError('Profile report source differs: '+name)
        if len(report['cases'])!=count:raise ValueError('Profile report case count differs: '+name)
        if not report['dependencies']:raise ValueError('Profile report dependencies missing')
        for filename,expected in report['dependencies'].items():
            dependency=(HERE/filename).resolve()
            if not dependency.is_relative_to(HERE.resolve()) or digest(dependency)!=expected:
                raise ValueError('Profile replay dependency changed: '+filename)
        for artifact in report['evidence']:
            file=Path(artifact['path']).resolve()
            if not file.is_relative_to((root/'ghidra').resolve()) or digest(file)!=artifact['sha256']:
                raise ValueError('Profile Ghidra evidence changed')
        if 'portable_helper_sha256' in report:
            helper='sdk_config.py' if name=='url' else 'gmc2_request.py'
            if digest(HERE.parents[1]/'vampir-shared/vampir_core'/helper)!=report['portable_helper_sha256']:
                raise ValueError('Profile portable helper changed')
        reports[name]=report
        evidence[name]=dict(path=str(path),sha256=sha,cases=count,limits=report['limits'])
    result=assemble(reports)
    return dict(schema=1,name='recovered-11316-candidate',source=str(source),source_sha256=SHA,
        evidence=evidence,**result,tool_sha256=digest(Path(__file__)),
        active_runtime_settings_verified=False,network_ready=False,runtime_enabled=False,
        local_choices=['Environment real and NMENV absent; actual startup inputs not read.',
                       'PC platform byte 3; NID caller binding and console/TLS overrides not verified.',
                       'Raw webview type 0, English UI and empty country/OS version are local choices.',
                       'Public GMC2 device/account fields explicitly empty; no real identities acquired.'],
        next_checks=['Current NID caller inputs and auth lifecycle source guards.',
                     'Explicit runtime integration and separate live validation when servers are available.'])


if __name__=='__main__':
    result=build();native=load('profile_save_root',HERE/'build-native-entry-code.py');audit=load('profile_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(native.ROOT/'sdk-source-profiles',result)
    print(json.dumps(dict(profile=str(path),source_sha256=SHA,runtime_enabled=False,network_ready=False)))
