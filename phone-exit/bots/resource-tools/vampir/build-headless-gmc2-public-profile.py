"""Source-bound public GMC2 probe profile; no claim of active installed settings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gmc2_profile_config', HERE / 'build-headless-sdk-config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
sys.path.insert(0, str(HERE.parent.parent / 'vampir-shared'))
from vampir_core.sdk_config import assemble_gmc2_config_url_ascii
from vampir_core.gmc2_request import plan_gmc2_get_request


def build():
    prior = json.loads((config.native.ROOT / 'code-clues/headless-sdk-config.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Public SDK profile source changed')
    image = config.native.Image(raw)
    fragments = config.native.decode_ranges(image, {image.roots[image.containing(a)] for a in
        (0x1444bd970, 0x1444f5320, 0x1444f3f6a, 0x1444ac9f0, 0x144524390, 0x141258b10, 0x141258ae0)})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    def literal(address, expected):
        row = rows[address]
        value = config.read_literal(raw, image, row['rip_references'][0])
        if value['text'] != expected:
            raise ValueError('Public profile literal changed')
        return dict(instruction=address, **value)
    literals = [literal(a, text) for a, text in
        ((0x1444bdaf3, 'https://alpha-apis.netmarble.com/gc2'),
         (0x1444bdb19, 'https://apis.netmarble.com/gc2'),
         (0x1444bdb3f, 'netmarbles'), (0x1444bdb6f, 'netmarbles-v5'),
         (0x144524396, '5.2.11'))]
    # Game market/code initializer strings are decoded from the LEA source instructions.
    game_literals = []
    for function, expected in ((0x141258b10, 'nmp'), (0x141258ae0, 'thered')):
        candidates = [config.read_literal(raw, image, a) for f in fragments
            if f['root_begin_rva'] == function - image.pe.base for r in f['instructions']
            if r['mnemonic'] == 'lea' and r['operands'].startswith('rdx,') for a in r['rip_references']]
        found = [v for v in candidates if v and v['text'] == expected]
        if len(found) != 1:
            raise ValueError('Game initializer source changed')
        game_literals.extend(found)
    expected_rows = {
        0x1444bdb38: 'rcx, [rbx + 0x190]', 0x1444bdb5e: 'rcx, [rbx + 0x1c8]',
        0x1444f3f54: 'r8, [r15 + 0x190]', 0x1444f534d: 'qword ptr [rsp + 0x60], r8',
        0x1444aca3d: 'word ptr [rbx + 0x48], 0x100',
    }
    if any(rows[a]['operands'] != text for a, text in expected_rows.items()) or rows[0x1444f3f6a]['direct_target'] != 0x1444f5320:
        raise ValueError('Public request source binding changed')
    profile = dict(base='https://apis.netmarble.com/gc2', group='netmarbles-v5', sdk_version='5.2.11',
                   build_code=0, market='nmp', game_code='thered', service_code='netmarbles')
    url = assemble_gmc2_config_url_ascii(**{k: profile[k] for k in ('base', 'group', 'sdk_version', 'build_code', 'market')})
    request = plan_gmc2_get_request(url=url, service_code=profile['service_code'], game_code=profile['game_code'],
                                   build_code=profile['build_code'], device_key='')
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=fragments,
        literals=literals + game_literals, profile=profile, request=dict(url=request.url, method=request.method, headers=request.headers),
        source_service_code_verified=True, device_key_policy='empty explicit public probe; no identity generated/acquired',
        build_code_policy='compiled constructor default 0; late overrides not excluded',
        zone_policy='production profile derived from public CDN Zone real; not active installed state proof',
        active_settings_verified=False, network_ready=False)


if __name__ == '__main__':
    report = build()
    target = config.native.ROOT / 'code-clues/headless-gmc2-public-profile.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         source_service_code_verified=True), indent=2))
