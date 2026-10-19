"""Source-bound SDK Save/Load, path and separate Netmarble ID device key index."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sdk_storage_source', HERE / 'build-headless-device-identity.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
ADDRESSES = (0x14453cdf0, 0x14452c6e0, 0x14452a300, 0x144520bd0,
             0x144522b50, 0x14454b5c0, 0x14157fce0, 0x14157fd60,
             0x1414459a0, 0x14156f6b0, 0x14142c9d0)
GLOBALS = (0x14b4f1408, 0x14b4f1a98)


def build():
    native = source.config.native
    prior = json.loads((native.ROOT / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('SDK storage EXE changed')
    image = native.Image(raw)
    candidates = native.rip_candidates(image, set(GLOBALS))
    roots = {image.roots[image.containing(a)] for a in ADDRESSES}
    initializers = {image.roots[image.containing(a)] for a, _ in candidates
                    if image.containing(a) and image.roots[image.containing(a)][0] < 0x2000000}
    fragments = native.decode_ranges(image, roots | initializers)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    bindings = []
    literals = []
    for fragment in fragments:
        current_literals = []
        for row in fragment['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if literal := source.config.read_literal(raw, image, ref):
                        current_literals.append(dict(instruction=row['address'], **literal))
        literals.extend(current_literals)
        if image.roots[image.containing(image.pe.base + fragment['begin_rva'])] in initializers:
            for address, target in candidates:
                if address in {r['address'] for r in fragment['instructions']} and target in rows[address]['rip_references']:
                    bindings.append(dict(global_address=target, initializer_reference=address, literals=current_literals))
    address = 0x140bb4a10
    offset = image.offset(address - image.pe.base)
    data = raw[offset:offset + 3]
    if data != bytes.fromhex('b001c3'):
        raise ValueError('SDK path true predicate leaf changed')
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=fragments, bindings=bindings, literals=literals,
                path_predicate=dict(address=address, file_offset=offset, bytes=data.hex(),
                                    sha256=hashlib.sha256(data).hexdigest()),
                native_execution=False, user_storage_read=False, limitations=[
                    'Static Windows client Save/Load/path and separate Netmarble ID key branches only.',
                    'No real registry, profile, Saved files, tokens, process memory or network used.',
                    'True path predicate is source pinned; active base directory and filenames not read.',
                    'Source names/branches do not establish live storage success, active platform or server identity.'])


if __name__ == '__main__':
    report = build()
    path = source.config.native.ROOT / 'code-clues/headless-sdk-storage.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), fragments=len(report['fragments']))))
