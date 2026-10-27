"""Current installed-source launcher profile; cached SDK proof, no auth or game actions."""
import hashlib
import importlib.util
import locale
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
INSTALLED=Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
ROLES=dict(defaults='replay-sdk-defaults-11318',override='replay-sdk-overrides-11318',
    platform='replay-sdk-platform-11318',start='replay-gmc2-base-11318',url='replay-gmc2-url-11318',
    headers='replay-gmc2-headers-11318',nid_base='replay-nid-context-11318',
    nid_helpers='replay-nid-primitives-11318',geo='replay-gmc2-geo-11318')
FOLDERS=dict(defaults='sdk-defaults-11318',override='sdk-overrides-11318',platform='sdk-platform-11318',
    start='gmc2-base-11318',url='gmc2-url-11318',headers='gmc2-headers-11318',
    nid_base='nid-context-11318',nid_helpers='nid-primitives-11318',geo='gmc2-geo-11318')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(root=None,installed=INSTALLED,publish=False):
    root=Path(root) if root else Path('F:/PhoneExit Resources/Vampir')
    installed=Path(installed)
    if digest(installed)!=SHA:raise ValueError('Installed SDK source differs')
    batch_path,batch,_=load('run-sdk-batch-11318').run(root)
    crt=batch['reports'][ROLES['nid_helpers']]['primitive_evidence']['crt']
    if digest(crt['path'])!=crt['sha256'] or locale.setlocale(locale.LC_ALL)!=crt['locale']:
        raise ValueError('SDK auth CRT environment changed')
    evidence=dict(batch=dict(path=str(batch_path),sha256=digest(batch_path),cases=3667))
    storage=load('audit-client-release')
    for role,name in ROLES.items():
        report=batch['reports'][name]
        expected=hashlib.sha256(storage.canonical(report)).hexdigest()
        path=root/'code-clues'/FOLDERS[role]/expected/'manifest.json'
        if publish:storage.save_snapshot(root/'code-clues'/FOLDERS[role],report)
        if digest(path)!=expected:raise ValueError('SDK component report changed')
        evidence[role]=dict(path=str(path),sha256=expected,cases=len(report['cases']),limits=report['limits'])
    audit=load('audit-launcher-contract-11318').audit(root)
    evidence['launcher']=dict(tool='audit-launcher-contract-11318.py',tool_sha256=digest(HERE/'audit-launcher-contract-11318.py'),report=audit)
    if digest(installed)!=SHA:raise ValueError('Installed SDK source changed during build')
    return dict(schema=1,name='recovered-release',source=str(installed),source_sha256=SHA,
        **batch['profile_candidate'],evidence=evidence,runtime_scope='sdk-launcher-auth',
        supported_auth_flows=['launcher'],direct_sdk_operations_verified=False,
        active_runtime_settings_verified=False,network_ready=False,game_protocol_verified=False,
        tool_sha256=digest(Path(__file__)),
        local_choices=['Окружение real, NMENV отсутствует, платформа PC / WebView 0 и язык en заданы явно.',
                       'Device identity, страна, версия Windows и GMC2 configuration поступают заново в изолированный контекст аккаунта.'],
        next_checks=['Живой launcher вход требует отдельной проверки; direct SDK операции не разрешены.',
                     'Игровой профиль, CharacterList, heartbeat и вход в мир проверяются отдельно.'])


if __name__=='__main__':
    profile=build(publish=True)
    path=load('audit-client-release').save_snapshot(Path('F:/PhoneExit Resources/Vampir')/'sdk-source-profiles',profile)
    print(path)
