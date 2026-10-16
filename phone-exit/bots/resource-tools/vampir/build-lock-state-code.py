"""Preserve checked lock-context reset, input-list update and level refresh."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('state_calls', HERE / 'build-entry-window-code.py')
calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calls)
native, ROOT = calls.native, calls.ROOT


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    targets = (0x145ced700, 0x145cf5c50)
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(data, section['raw'], section['raw_size'],
                                                        image.pe.address, set(targets)))
    addresses = targets + (0x145cf3440, 0x145ceb7e0, 0x145cf07f0)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    checks = [
        (0x145cf3464, 'mov', 'word ptr [rcx + 0x220], 1'),
        (0x145cf3470, 'mov', 'byte ptr [rcx + 0x222], 0'),
        (0x145cf3477, 'mov', 'qword ptr [rcx + 0x224], r13'),
        (0x145ceb7fc, 'mov', 'byte ptr [rbx + 0x221], 0'),
        (0x145ced732, 'mov', 'r14, rcx'),
        (0x145ced7d2, 'test', 'r8b, r8b'),
        (0x145ced7d7, 'lea', 'rbx, [r14 + 0x1b0]'),
        (0x145ced7de, 'mov', 'dword ptr [rbx + 8], r15d'),
        (0x145ced807, 'mov', 'dword ptr [rbx + 8], edi'),
        (0x145ced83b, 'call', '0x1487a2e19'),
        (0x145ced85a, 'lea', 'rbx, [r14 + 0x1b0]'),
        (0x145ced8b6, 'dec', 'dword ptr [rbx + 8]'),
        (0x145ced8e1, 'mov', 'dword ptr [rax + rsi*4], edi'),
        (0x145ced8f4, 'mov', 'byte ptr [r14 + 0x222], 1'),
        (0x145cedbab, 'cmp', 'byte ptr [r15 + 0xe], 1'),
        (0x145cedbb2, 'lea', 'rbx, [r14 + 0x1a0]'),
        (0x145cedbfa, 'mov', 'dword ptr [rax + r15*4], edi'),
        (0x145cedc88, 'mov', 'byte ptr [r14 + 0x221], 1'),
        (0x145cedc90, 'call', '0x145cf07f0'),
        (0x145cf0806, 'cmp', 'byte ptr [rcx + 0x221], 0'),
        (0x145cf0819, 'cmp', 'byte ptr [rcx + 0x222], 0'),
        (0x145cf083a, 'call', '0x145cf5c50'),
        (0x145cf5c5f, 'mov', 'rbp, rcx'),
        (0x145cf5c77, 'call', '0x145ce3dd0'),
        (0x145cf5c89, 'cmp', 'dil, 3'),
        (0x145cf5ca8, 'mov', 'dword ptr [rbp + 0x228], eax'),
        (0x145cf5cb8, 'mov', 'eax, dword ptr [rax + 0x1b0]'),
        (0x145cf5cbe, 'mov', 'dword ptr [rbp + 0x228], eax'),
        (0x145cf5d31, 'mov', 'edx, 3'),
        (0x145cf5d39, 'call', '0x1455e19d0'),
        (0x145cf5d3e, 'mov', 'dword ptr [rbp + 0x224], eax'),
        (0x145cf5d7f, 'cmp', 'edi, 0xb'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed state instruction changed: ' + hex(address))
    verified = []
    for address, target in candidates:
        if not calls.checked_call(rows.get(address), target):
            raise ValueError('Unresolved state direct caller')
        verified.append(rows[address])
    if {(r['address'], r['direct_target']) for r in verified} != {(0x145cf083a, 0x145cf5c50)}:
        raise ValueError('Reviewed direct caller set changed')
    attribute = [r for r in source['enums']['EAttributeType'] if r['value'] == 3]
    if len(attribute) != 1 or attribute[0]['name'] != 'EAttributeType::Attribute3':
        raise ValueError('Attribute key changed')
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  anchors=[rows[a] for a, _, _ in checks], direct_callers=verified,
                  attribute3=attribute[0],
                  context_fields=dict(flags=[0x221, 0x222], character_level=0x224,
                                      guild_level=0x228, saved_type1_ids=0x1a0, received_ids=0x1b0),
                  ordered_path=[0x145ced700, 0x145cf07f0, 0x145cf5c50],
                  runtime_evaluator_enabled=False,
                  limitations=['Input list origin and indirect handler dispatch remain unresolved.',
                               'Field roles follow predicate consumers; original flag names are unknown.',
                               'Attribute3 is the source key, not a newly proven symbolic Level enum.',
                               'Guild helper and source object initialization remain unresolved.',
                               'Input replacement versus merge does not prove server synchronization protocol.',
                               'No Android, process memory or player state read.'])
    output = ROOT / 'code-clues/lock-state-code.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), fragments=len(fragments), direct_callers=len(verified),
                          attribute3=attribute[0]['name'], runtime_evaluator_enabled=False)))


if __name__ == '__main__':
    main()
