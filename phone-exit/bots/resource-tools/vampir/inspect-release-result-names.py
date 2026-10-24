"""Verify selected local result-name / value pairs in one explicit native function.

Static instruction evidence only; no game IO or native execution.
"""
import importlib.util
import re
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
OWNER = 0x1457da4e0
VALUES = {0: 'Success', 58: 'BlockedIp', 59: 'BlockedInfo', 100: 'CharacterNotSelected'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*, source_sha256=SHA, owner_address=OWNER, values=None, constructor=0x141426a30):
    values = VALUES if values is None else values
    native = load('result_names_native', HERE / 'build-native-entry-code.py')
    audit = load('result_names_audit', HERE / 'audit-client-release.py')
    source = native.ROOT / 'client-code-snapshots' / source_sha256 / 'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(source) != source_sha256:
        raise ValueError('Result-name source changed')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    image = native.Image(source.read_bytes())
    owner = image.containing(owner_address)
    if owner is None or image.pe.base + image.roots[owner][0] != owner_address:
        raise ValueError('Result-name owner changed')
    root = image.roots[owner]
    fragments = native.decode_ranges(image, {root},
        functions=[f for f in image.ranges if image.roots[f] == root])
    pairs = []
    for fragment in fragments:
        instructions = fragment['instructions']
        for i, row in enumerate(instructions):
            match = re.fullmatch(r'dword ptr \[rbp \+ (0x[0-9a-f]+)\], (0x[0-9a-f]+|0)', row['operands'])
            if row['mnemonic'] != 'mov' or match is None:
                continue
            value = int(match[2], 0)
            if value not in values:
                continue
            # String construction precedes storing its name pointer; the next
            # interleaved entry supplies the LEA of this entry's integer slot.
            prefix = 5 if value == 59 else 6
            window = instructions[i - prefix:i + 6]
            if len(window) != prefix + 6:
                raise ValueError('Incomplete result-name window')
            def require(index, mnemonic, operands):
                if window[index]['mnemonic'] != mnemonic or window[index]['operands'] != operands:
                    raise ValueError('Result-name pairing instruction changed')
            require(0, 'lea', window[0]['operands'])
            if not window[0]['operands'].startswith('rdx, [rip + ') or len(window[0]['rip_references']) != 1:
                raise ValueError('Result-name literal reference changed')
            name_address = window[0]['rip_references'][0]
            offset = image.offset(name_address - image.pe.base)
            literal = image.data[offset:offset + 128].split(b'\0', 1)[0]
            if literal != values[value].encode('ascii'):
                raise ValueError('Result-name literal mismatch')
            local = re.fullmatch(r'rcx, (\[rbp \+ 0x[0-9a-f]+\])', window[2]['operands'])
            if local is None:
                raise ValueError('Result-name string slot changed')
            require(2, 'lea', 'rcx, ' + local[1])
            require(prefix - 2, 'call', hex(constructor))
            require(prefix - 1, 'lea', 'rax, ' + local[1])
            name_slot = re.fullmatch(r'qword ptr \[rbp \+ (0x[0-9a-f]+)\], rax', window[prefix + 1]['operands'])
            if name_slot is None:
                raise ValueError('Result-name pair slot changed')
            require(prefix + 1, 'mov', window[prefix + 1]['operands'])
            require(prefix + 3, 'lea', 'rax, [rbp + ' + match[1] + ']')
            require(prefix + 5, 'mov', f'qword ptr [rbp + {hex(int(name_slot[1], 0) + 8)}], rax')
            pairs.append(dict(value=value, name=values[value], literal_address=hex(name_address),
                literal_hex=(literal + b'\0').hex(), instructions=window))
    if sorted(p['value'] for p in pairs) != sorted(values):
        raise ValueError('Missing or ambiguous result-name pair')
    report = dict(source_sha256=source_sha256, tool_sha256=audit.sha256(Path(__file__)),
        owner=hex(owner_address), fragments=[{k:v for k,v in f.items() if k != 'instructions'} for f in fragments],
        pairs=pairs, limits=[
            'Whole unwind fragments decoded; selected local string/integer pointer pairs checked statically.',
            'No whole pseudocode export used for the large dictionary initializer.',
            'Map insertion, string constructor and lookup are not executed by this tool.',
            'No packet-specific handler, request field meaning or server-side cause is established.'])
    path = audit.save_snapshot(native.ROOT / 'code-clues/release-result-names', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), pairs=[dict(value=p['value'], name=p['name']) for p in report['pairs']])))
