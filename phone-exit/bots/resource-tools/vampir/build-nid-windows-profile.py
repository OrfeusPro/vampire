"""Export an explicit Windows initial NID profile, not a running SDK cache."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
spec = importlib.util.spec_from_file_location('nid_profile_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
SETTINGS_SHA = 'dca370b3cb47525bc16879fad4a6e0e116ea70dbe9d7a7c27df9caaa26fce573'


def build():
    path = ROOT / 'code-clues/headless-sdk-settings.json'
    if hashlib.sha256(path.read_bytes()).hexdigest() != SETTINGS_SHA: raise ValueError('SDK settings evidence changed')
    settings = json.loads(path.read_text('utf-8'))
    raw = Path(settings['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != settings['sha256']: raise ValueError('Installed client changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(0x1411b5bd0)]})
    manifest = json.loads((ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    getter_ranges = next(f['ranges'] for f in manifest['functions'] if f['name'] == 'SDK_PlatformLabel')
    for item in getter_ranges:
        length = int(item['end_exclusive'], 16) - int(item['start'], 16)
        if hashlib.sha256(raw[item['file_offset']:item['file_offset'] + length]).hexdigest() != item['sha256']:
            raise ValueError('Platform getter ranges changed')
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    if rows[0x1411b5bdb]['rip_references'] != [0x14b4f1608] or rows[0x1411b5be2]['direct_target'] != 0x141421150:
        raise ValueError('PC label initializer changed')
    address = rows[0x1411b5bd4]['rip_references'][0]
    offset = image.offset(address - image.pe.base)
    if raw[offset:offset + 6] != 'PC\0'.encode('utf-16le'): raise ValueError('PC platform label changed')
    game = settings['game_cases'][0]['values']
    if game['GameCode'] != 'thered' or game['SDKZone'] != 2: raise ValueError('Source game profile changed')
    return dict(schema_version=1, source=settings['source'], source_sha256=settings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), settings_evidence_sha256=SETTINGS_SHA,
        fragments=fragments, getter_ranges=getter_ranges,
        platform_label=dict(address=address, file_offset=offset, bytes=raw[offset:offset + 6].hex()),
        profile=dict(game_code=game['GameCode'], client_id=game['NetmarbleClientId'], build_code=0,
                     os_type='PC', raw_webview_type=0, country_code='', language='en', os_version=''),
        local_choices=['Initial production source profile; not an active SDK cache snapshot.',
                       'BuildCode 0 is the verified constructor default and public GMC2 build A.',
                       'PC is the compiled label for platform byte 3; console overrides are not reproduced.',
                       'English is an explicit UI language; country/osVersion left empty rather than invented.',
                       'SDK country after browser sign-in comes from returned provider joinedCountryCode.'],
        active_runtime_settings_verified=False)


if __name__ == '__main__':
    report = build()
    path = ROOT / 'code-clues/nid-windows-initial-profile.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(profile=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), active_cache=False)))
