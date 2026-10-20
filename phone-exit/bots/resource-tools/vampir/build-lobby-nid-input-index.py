"""Index only compiled NID collector keys and consumer callsites, no account IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lobby_nid_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
SOURCE_SHA = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


def build():
    upstream_path = native.ROOT / 'code-clues/lobby-login-path.json'
    upstream = json.loads(upstream_path.read_text('utf-8'))
    raw = Path(upstream['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA: raise ValueError('Client changed')
    image = native.Image(raw)
    targets = (0x145604bf0, 0x145604960, 0x145604090, 0x145606660, 0x144524d80, 0x144551060)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in targets})
    literals = []
    rows = sorted((r for f in fragments if f['root_begin_rva'] == 0x145604bf0 - image.pe.base
        for r in f['instructions']), key=lambda r: r['address'])
    keys = []
    for index, row in enumerate(rows):
        if row['direct_target'] != 0x1455fb550: continue
        prior = rows[max(0, index - 8):index]
        ctor_index = next((i for i in range(len(prior) - 1, -1, -1) if prior[i]['direct_target'] == 0x141421150), None)
        if ctor_index is None: raise ValueError('Collector key constructor not found')
        lea = next((r for r in reversed(prior[:ctor_index]) if r['mnemonic'] == 'lea'
            and r['operands'].startswith('rdx, ') and len(r['rip_references']) == 1), None)
        if lea is None: raise ValueError('Collector key literal not found')
        address = lea['rip_references'][0]
        offset = image.offset(address - image.pe.base)
        match = re.match(rb'(?:[\x20-\x7e]\x00){1,128}\x00\x00', raw[offset:offset + 260])
        if match is None: raise ValueError('Collector key is not bounded ASCII UTF16 literal')
        data = match.group()
        keys.append(dict(key=data[:-2].decode('utf-16le'), address=address, file_offset=offset,
            bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(), lea=lea,
            constructor_call=prior[ctor_index], select_call=row))
    for f in fragments:
        for r in f['instructions']:
            for address in r['rip_references']:
                try: offset = image.offset(address - image.pe.base)
                except ValueError: continue
                for encoding, pattern in [('utf-16le', rb'(?:[\x20-\x7e]\x00){5,128}\x00\x00'),
                        ('ascii', rb'[\x20-\x7e]{5,128}\x00')]:
                    match = re.match(pattern, raw[offset:offset + 260])
                    if match:
                        data = match.group()
                        literals.append(dict(address=address, file_offset=offset, encoding=encoding,
                            text=data[:-(2 if encoding == 'utf-16le' else 1)].decode(encoding),
                            referenced_by=r['address'], root=image.pe.base + f['root_begin_rva']))
                        break
    country_literal = next(r for r in literals if r['address'] == 0x1494e7150 and r['root'] == 0x144551060)
    if country_literal['text'] != 'I_JoinedCountryCode': raise ValueError('NID UserInfo field label changed')
    country_rows = [r for f in fragments if f['root_begin_rva'] == 0x144551060 - image.pe.base
        for r in f['instructions']]
    key_index = next(i for i, r in enumerate(country_rows) if r['address'] == country_literal['referenced_by'])
    country_value = next((r for r in reversed(country_rows[max(0, key_index - 12):key_index])
        if r['mnemonic'] == 'lea' and r['operands'].startswith('rdx, ') and '+ 0x170]' in r['operands']), None)
    if country_value is None: raise ValueError('NID UserInfo country offset changed')
    return dict(schema_version=1, source=upstream['source'], source_sha256=SOURCE_SHA,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream_sha256=hashlib.sha256(upstream_path.read_bytes()).hexdigest(),
        collector_keys=keys, literals=literals, fragments=fragments,
        country_field=dict(object_offset=0x170, value_reference=country_value, key_literal=country_literal),
        limitations=['Compiled keys/calls only; values, full UserInfo layout and serialization semantics are not inferred.',
            'No native runtime execution, SDK/NID request, live account or credentials.'])


if __name__ == '__main__':
    report = build()
    out = native.ROOT / 'code-clues/lobby-nid-input-index.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(out), sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
        keys=[r['key'] for r in report['collector_keys']])))
