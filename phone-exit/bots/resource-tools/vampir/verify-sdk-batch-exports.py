"""Check the complete SDK target exports independently of replay fixtures."""
import importlib.util
import json
from pathlib import Path
import struct


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(root, generation):
    native = load('build-native-entry-code')
    context = load('update-native-contexts')
    source = Path(root) / 'client-code-snapshots' / generation['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'
    if context.digest(source) != generation['source_sha256']:
        raise ValueError('SDK export source SHA differs')
    image = native.Image(source.read_bytes())
    wanted = set(generation['roots'].values())
    functions = {}
    inputs = {str(source): generation['source_sha256']}
    for run, sha in generation['exports'].items():
        path = Path(root) / 'ghidra/request-exports' / generation['source_sha256'] / run / 'details.json'
        if context.digest(path) != sha:
            raise ValueError('SDK target export SHA differs')
        inputs[str(path)] = sha
        document = json.loads(path.read_bytes())
        if document['new_source_sha256'] != generation['source_sha256']:
            raise ValueError('SDK export source differs')
        for function in document['functions']:
            address = function['address']
            if address in wanted:
                if address in functions:
                    raise ValueError('Duplicate SDK root export')
                functions[address] = function
    if set(functions) != wanted or len(wanted) != 34:
        raise ValueError('SDK complete root exports missing')
    switches = {item['current']: item for item in generation['switches']}
    fragments = {}
    for part, entry in image.roots.items():
        if hex(image.pe.base + entry[0]) in wanted:
            fragments.setdefault(entry, []).append(part)
    for address, function in functions.items():
        if not all(function.get(field) is True for field in (
                'decompilation_completed', 'block_coverage_complete', 'direct_flow_coverage_complete')):
            raise ValueError('Incomplete SDK root export')
        at = int(address, 16)
        entry = image.containing(at)
        if entry is None or image.roots[entry] != entry or image.pe.base + entry[0] != at:
            raise ValueError('SDK exported root has no matching unwind boundary')
        code = {int(row['address'], 16): row['bytes'] for row in function['instructions']}
        if len(code) != len(function['instructions']):
            raise ValueError('Duplicate SDK export instruction')
        if address in switches:
            item = switches[address]
            cursor = at
            for row in function['instructions']:
                data = bytes.fromhex(row['bytes'])
                if int(row['address'], 16) != cursor or context.image_bytes(image, cursor, len(data)) != data:
                    raise ValueError('SDK switch exported code has a gap or changed bytes')
                cursor += len(data)
            table = int(item['table'], 16)
            raw = context.image_bytes(image, table, item['count'] * 4)
            if (raw.hex() != item['bytes'] or table != cursor + 1
                    or context.image_bytes(image, cursor, 1).hex() != item['padding']
                    or table + len(raw) != image.pe.base + entry[1]):
                raise ValueError('SDK switch code/table extent differs')
            targets = [image.pe.base + rva for rva in struct.unpack('<' + 'I' * item['count'], raw)]
            if not set(targets) <= set(code) or [value - at for value in targets] != item['offsets']:
                raise ValueError('SDK switch relative targets differ')
        else:
            decoded = native.decode_ranges(image, {entry}, functions=fragments[entry])
            actual = {row['address']: row['bytes'] for part in decoded for row in part['instructions']}
            if code != actual:
                raise ValueError('SDK root export omits or adds native instructions')
    if any(context.digest(Path(path)) != sha for path, sha in inputs.items()):
        raise ValueError('SDK export input changed during verification')
    return dict(source_sha256=generation['source_sha256'], roots=34, switch_tables=len(switches),
                runtime_admitted=False)
