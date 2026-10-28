"""Bounded discovery of changed LoginResult links; candidates are not admission."""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
TABLE, READER, GATE = 0x149929040, 0x1456dc140, 0x1467d0c60


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def discover(root):
    root = Path(root)
    source = root / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE:
        raise ValueError('LoginResult source changed')
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    image = native.Image(raw)
    table_bytes = raw[image.offset(TABLE - image.pe.base):image.offset(TABLE - image.pe.base) + 80]
    table = struct.unpack('<10Q', table_bytes)
    if table[4] != READER:
        raise ValueError('LoginResult table/reader identity changed')

    def rows(at):
        return bindings.rows(native, image, at)

    def search(center, predicate, prefilter):
        roots = {r for r in image.roots.values() if abs(image.pe.base + r[0] - center) <= 65536}
        if len(roots) > 4096:
            raise ValueError('LoginResult candidate budget')
        found = []
        for r in sorted(roots):
            at = image.pe.base + r[0]
            off = image.offset(r[0])
            if not prefilter(raw[off:off + r[1] - r[0]], at):
                continue
            try:
                body = rows(at)
            except ValueError:
                continue
            if predicate(body):
                found.append(hex(at))
        return found

    def references(code, at, target, call=False):
        # Cheap raw candidates only; full decoded boundaries are checked above.
        for i in range(len(code) - (4 if call else 6)):
            if call and code[i] == 0xe8 and at + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
                return True
            if not call and 0x48 <= code[i] <= 0x4f and code[i + 1] == 0x8d and code[i + 2] & 0xc7 == 5:
                if at + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
                    return True
        return False

    constructors = search(0x1456d7a70, lambda body: any(TABLE in r['rip_references'] for r in body),
                          lambda code, at: references(code, at, TABLE))
    # The first virtual slot is the deleting destructor, not a constructor.
    constructors = [at for at in constructors if int(at, 16) != table[0]]
    handlers = search(0x14679b390, lambda body: any(r['call'] and r['direct_target'] == GATE for r in body),
                      lambda code, at: references(code, at, GATE, call=True))
    body = rows(READER)
    operations, destination = [], None
    for row in body:
        if row['mnemonic'] == 'lea' and row['operands'].startswith('rdx, ['):
            destination = row['operands']
        if row['call']:
            if destination is None:
                raise ValueError('Unclassified reader destination')
            operations.append(dict(address=hex(row['address']), destination=destination,
                                   target=hex(row['direct_target']) if row['direct_target'] is not None else row['operands']))
            destination = None
    if len(operations) > 64:
        raise ValueError('Reader operation budget')
    owners = []
    if len(constructors) == 1:
        constructor = int(constructors[0], 16)
        owners = search(0x1467b5130, lambda body: any(r['call'] and r['direct_target'] == constructor for r in body),
                        lambda code, at: references(code, at, constructor, call=True))
    handler_links = []
    if len(owners) == 1:
        for row in rows(int(owners[0], 16)):
            for target in row['rip_references']:
                try:
                    off = image.offset(target - image.pe.base)
                    values = struct.unpack_from('<8Q', raw, off)
                except (ValueError, struct.error):
                    continue
                for i, value in enumerate(values):
                    if hex(value) in handlers:
                        handler_links.append(dict(instruction=hex(row['address']), table=hex(target), slot=i * 8, handler=hex(value)))
    linked = sorted({link['handler'] for link in handler_links})
    if len(linked) == 1:
        handlers = linked
    selected = [hex(READER)] + constructors + (handlers if len(handlers) == 1 else []) + (owners if len(owners) == 1 else [])
    if len(selected) > 32:
        raise ValueError('Explicit export budget')
    dependencies = ('discover-login-result-11320.py', 'build-native-entry-code.py',
                    'extract-native-enums.py', 'update-bindings.py', 'version-gate-switch-11320.py')
    inputs = {str(source): SOURCE, **{str(HERE / name): digest(HERE / name) for name in dependencies}}
    for name, sha in inputs.items():
        if digest(name) != sha:
            raise ValueError('LoginResult discovery inputs changed')
    return dict(schema=1, source_sha256=SOURCE, packet_table=hex(TABLE), table_bytes=table_bytes.hex(),
                table_slots=[hex(v) for v in table], reader=hex(READER), operations=operations,
                constructor_candidates=constructors, handler_candidates=handlers, registration_owner_candidates=owners,
                handler_table_links=handler_links,
                required_export_roots=selected, inputs=inputs,
                semantic_verification=False, runtime_activated=False, network_used=False,
                limits=['Explicit table and reader; constructor/handler search within +/-65536 only.',
                        'References identify candidates; reader operation extraction does not prove nested data layout.'])


def run(root):
    result = discover(root)
    return load('research-workflow').snapshot(Path(root), 'login-result-discovery-11320', result), result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    path, result = run(args.root)
    print(json.dumps(dict(report=str(path), sha256=digest(path), constructors=result['constructor_candidates'],
                          handlers=result['handler_candidates'], owners=result['registration_owner_candidates'], operations=len(result['operations']), roots=result['required_export_roots'])))
