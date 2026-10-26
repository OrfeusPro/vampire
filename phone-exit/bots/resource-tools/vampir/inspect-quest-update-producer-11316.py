"""Current named QuestUpdate inputs and explicit sender. Static only, no game IO."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run():
    native, audit = load('build-native-entry-code'), load('audit-client-release')
    source = native.ROOT / 'client-code-snapshots' / SHA / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('Current source differs')
    image = native.Image(raw)
    export = native.ROOT / 'ghidra/request-exports' / SHA / 'run-22845de261d6/details.json'
    report = json.loads(export.read_text('utf-8'))
    if report['new_source_sha256'] != SHA:
        raise ValueError('Producer export source differs')
    roots = (0x145d85360, 0x145d6f9b0, 0x145837030)
    functions = [f for f in report['functions'] if int(f['address'], 16) in roots]
    if len(functions) != len(roots):
        raise ValueError('Missing explicit producer roots')
    instructions = {}
    for function in functions:
        if not function['decompilation_completed'] or not function['block_coverage_complete']:
            raise ValueError('Incomplete producer export')
        for row in function['instructions']:
            at = int(row['address'], 16)
            content = bytes.fromhex(row['bytes'])
            offset = image.offset(at - image.pe.base)
            if raw[offset:offset + len(content)] != content:
                raise ValueError('Export instructions differ')
            instructions[at] = row
    anchors = {
        0x145d6f9d4:'488d15fd3eb903', 0x145d6f9e3:'e8187b85fe',
        0x145d6f9e8:'488d15f944b903', 0x145d6f9fd:'e81e7b85fe',
        0x145d6fd33:'488d15ce41b903', 0x145d6fd4b:'48897d37',
        0x145d6fd4f:'4488753f', 0x145d6fd5b:'e8a07785fe', 0x145d6fd60:'4889452f',
        0x145d8537b:'e8306983ff', 0x145d8538d:'e86e37aaff',
        0x145d853b2:'48895c2470', 0x145d853b7:'e8542186ff', 0x145d853bc:'88442478',
    }
    # Guard the named sender stores, not a heuristic search for nearby immediates.
    for at, expected in anchors.items():
        if instructions.get(at, {}).get('bytes') != expected:
            raise ValueError('Named producer anchor differs: ' + hex(at))
    literals = {0x1499038d8:'QuestInfoId', 0x149903ee8:'QuestTaskIndex', 0x149903f08:'TargetId'}
    for at, value in literals.items():
        content = (value + '\0').encode('utf-16le')
        offset = image.offset(at - image.pe.base)
        if raw[offset:offset + len(content)] != content:
            raise ValueError('Named argument literal differs')
    leaves = {
        0x1455e7510:'488b41304885c07503b0ffc30fb64029c3',
        0x145834490:'b812070000c3',
    }
    for at, content in leaves.items():
        offset = image.offset(at - image.pe.base)
        if raw[offset:offset + len(bytes.fromhex(content))].hex() != content:
            raise ValueError('Exact producer leaf differs')
    slots = struct.unpack_from('<8Q', raw, image.offset(0x149965670 - image.pe.base))
    if (slots[2], slots[4], slots[5]) != (0x145837030, 0x14582bc60, 0x145834490):
        raise ValueError('Current packet binding differs')
    result = dict(source_sha256=SHA, tool_sha256=audit.sha256(Path(__file__)),
        export=dict(path=str(export),sha256=audit.sha256(export)),
        functions=functions,anchors={hex(k):v for k,v in anchors.items()},
        literals={hex(k):v for k,v in literals.items()},leaves={hex(k):v for k,v in leaves.items()},
        packet=dict(id=1810,table='0x149965670',writer='0x145837030',reader='0x14582bc60'),
        named_fields={'0x28':'TargetId','0x30':'QuestInfoId','0x38':'QuestTaskIndex'},network_used=False,
        limits=['Static sender input/stores and current packet binding only; no native execution or socket commands.',
            'Named request property is not proof of incoming PktQuest.raw08 meaning.',
            '145d85360 uses a successful model lookup and state byte from model+0x30 pointer+0x29; no valid task index is guessed.',
            'UI click/delegate, route generation, movement, server acknowledgement and automatic completion remain unproved.'])
    path = audit.save_snapshot(native.ROOT / 'code-clues/quest-update-producer-11316', result)
    return path, result


if __name__ == '__main__':
    path, result = run()
    print(json.dumps(dict(report=str(path), fields=result['named_fields'])))
