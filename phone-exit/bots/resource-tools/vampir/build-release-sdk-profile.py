"""Build a separate immutable SDK profile from current source-bound native reports."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
COMPARISON = ROOT / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
SOURCE_SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
INSTALLED = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
REPORTS = {
    'defaults': ('sdk-defaults-replay', 'cfe20931f09accfe2bd8b61152ee5ba5c84413f8040395cfaafd5abb3652510b', 'replay-release-sdk-defaults.py'),
    'platform': ('sdk-platform-replay', '034ee9fb7b3f4e4a36792105b6cd8a5e72ff53830edbf57fee9b67e0265286d0', 'replay-release-sdk-platform.py'),
    'override': ('sdk-overrides-replay', 'a38710b3406e7740be44169bf5b861c13c95e299e25ce535a3ad256339313953', 'replay-release-sdk-overrides.py'),
    'start': ('gmc2-start-replay', '9409d46095e5113f9929a9e6008f42791e397dbb08ffb0b7ff8b7cac59d8f841', 'replay-release-gmc2-start.py'),
    'url': ('gmc2-url-replay', 'ee859f52afb6bc496420d5c0164da52e230bbf7b9d452288452c4d8c9aaef429', 'replay-release-gmc2-url.py'),
    'headers': ('gmc2-headers-replay', 'ecb52e39f9bd1a3850761761a81e08f1aa88245dd18f17206259b973b537a255', 'replay-release-gmc2-headers.py'),
}


def build():
    spec = importlib.util.spec_from_file_location('sdk_profile_release_audit', HERE / 'audit-client-release.py')
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    if audit.sha256(INSTALLED) != SOURCE_SHA:
        raise ValueError('Installed SDK profile source changed')
    reports, evidence = {}, {}
    for name, (folder, sha, tool) in REPORTS.items():
        path = COMPARISON / folder / sha / 'manifest.json'
        if audit.sha256(path) != sha:
            raise ValueError('SDK replay manifest changed')
        report = json.loads(path.read_text('utf-8'))
        if report['source_sha256'] != SOURCE_SHA or audit.sha256(Path(report['source'])) != SOURCE_SHA:
            raise ValueError('SDK replay source mismatch')
        if audit.sha256(HERE / tool) != report['tool_sha256']:
            raise ValueError('SDK replay tool changed; run the revised replay')
        for dependency, digest in report['dependencies'].items():
            if audit.sha256(HERE / dependency) != digest:
                raise ValueError('SDK replay dependency changed')
        reports[name] = report
        evidence[name] = dict(path=str(path), sha256=sha, tool=tool, tool_sha256=report['tool_sha256'])
    default = next(c['values'] for c in reports['defaults']['cases'] if c['kind'] == 'settings-prefix')
    game_cases = [c for c in reports['override']['cases'] if c['environment'] == 'real' and c['nmenv'] is None
                  and c['sdk_present'] and c['sdk_handle']]
    if len(game_cases) != 1:
        raise ValueError('Ambiguous current initial production override')
    game = game_cases[0]['actual']
    if (default['BuildCode'], game['build_code'], game['sdk_zone'], game['market'], game['game_code']) != (0, 0, 2, 'nmp', 'thered'):
        raise ValueError('Current initial SDK settings differ')
    if not all(c['actual'] == 'PC' for c in reports['platform']['cases'] if c['platform_byte'] == 3):
        raise ValueError('Current PC platform label differs')
    base = {c['active_base'] for c in reports['start']['cases'] if c['zone'] == game['sdk_zone']}
    if base != {'https://apis.netmarble.com/gc2'}:
        raise ValueError('Current production base differs')
    gmc = next(c['values'] for c in reports['defaults']['cases'] if c['kind'] == 'gmc-constructor')
    urls = [c for c in reports['url']['cases'] if (c['base'], c['group'], c['build_code'], c['market']) ==
            (next(iter(base)), gmc['0x1c8'], game['build_code'], game['market'])]
    if len(urls) != 1:
        raise ValueError('Missing canonical current GMC2 URL replay')
    captures = [c for c in reports['headers']['cases'] if c['inputs']['url'] == urls[0]['actual']
                and c['inputs']['device_key'] == '' and c['inputs']['access_token'] == ''
                and c['inputs']['game_code'] == game['game_code'] and c['inputs']['service_code'] == gmc['0x190']]
    if len(captures) != 1:
        raise ValueError('Missing public current GMC2 HTTP capture')
    request = captures[0]['actual']
    public_profile = dict(base=next(iter(base)), group=gmc['0x1c8'], sdk_version='5.2.11', build_code=0,
                          market=game['market'], game_code=game['game_code'], service_code=gmc['0x190'])
    nid = dict(game_code=game['game_code'], client_id=game['client_id'], build_code=game['build_code'],
               os_type='PC', raw_webview_type=0, country_code='', language='en', os_version='')
    report = dict(schema=1, name='recovered-release', source=str(INSTALLED), source_sha256=SOURCE_SHA,
                  tool_sha256=audit.sha256(Path(__file__)), evidence=evidence,
                  public_gmc2=dict(profile=public_profile, request=request), nid=dict(profile=nid),
                  active_runtime_settings_verified=False, network_ready=False,
                  local_choices=['Initial production profile with NMENV absent; runtime command line/CDO overrides are not read.',
                                 'PC platform byte 3; TLS/console overrides are not reproduced.',
                                 'NID raw webview type 0 and English UI are explicit local choices.',
                                 'Country and OS version remain empty until observed by the live runner.',
                                 'Public GMC2 request has explicitly empty device identity and no account credentials.'])
    target = audit.save_snapshot(ROOT / 'sdk-source-profiles', report)
    print(json.dumps(dict(profile=str(target), sha256=audit.sha256(target), source_sha256=SOURCE_SHA,
                          active_runtime_settings_verified=False), indent=2))
    return report


if __name__ == '__main__':
    build()
