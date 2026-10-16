"""Checked initialization, writes and reads of condition-type readiness."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gate_spans', HERE / 'build-lock-predicate-code.py')
spans = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spans)
native, ROOT = spans.native, spans.native.ROOT


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    type_path = ROOT / 'quest-graph/condition-types.json'
    type_bytes = type_path.read_bytes()
    source = json.loads(type_bytes)
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)]
        for a in (0x145cf3440, 0x145ced600, 0x145cf5b10, 0x145cd16c0)})
    getter = spans.decode_span(image, 0x145ce3dd0, 0x145ce3e69)
    rows = {r['address']: r for f in fragments + [getter] for r in f['instructions']}
    checks = [
        (0x145cf3a4a, 'xor', 'r13d, r13d'),
        (0x145cf3a4d, 'mov', 'ebx, r13d'),
        (0x145cf3a54, 'movzx', 'r8d, bl'),
        (0x145cf3a58, 'cmp', 'r8b, 0xa'), (0x145cf3a60, 'sete', 'sil'),
        (0x145cf3ad4, 'lea', 'rcx, [r14 + 0x60]'),
        (0x145cf3ae1, 'lea', 'rcx, [rax + rax*2]'),
        (0x145cf3ae9, 'lea', 'rax, [rax + rcx*4]'),
        (0x145cf3aed, 'inc', 'ebx'), (0x145cf3aef, 'mov', 'byte ptr [rax + 1], sil'),
        (0x145cf3af3, 'cmp', 'ebx, 0xb'), (0x145cf3af6, 'jl', '0x145cf3a50'),
        (0x145ced611, 'movzx', 'edi, r8b'),
        (0x145ced65e, 'cmp', 'byte ptr [rcx + r8], dl'),
        (0x145ced676, 'lea', 'rcx, [rbx + 0x60]'),
        (0x145ced67a, 'call', '0x145cd16c0'),
        (0x145ced67f, 'mov', 'byte ptr [rax], dil'),
        (0x145ced685, 'je', '0x145ced694'),
        (0x145ced68f, 'call', '0x145cf07f0'),
        (0x145ced6d4, 'cmp', 'byte ptr [rax], dil'),
        (0x145ced6d7, 'jne', '0x145ced66e'),
        (0x145ced6dc, 'je', '0x145ced6b3'),
        (0x145ced6e3, 'call', '0x145cf07f0'),
        (0x145cf5b83, 'mov', 'edx, 4'),
        (0x145cf5b8c, 'call', '0x145cd16c0'),
        (0x145cf5b99, 'mov', 'byte ptr [rax], 1'),
        (0x145cf5b9c, 'call', '0x145cf07f0'),
        (0x145ce3dd0, 'cmp', 'byte ptr [rcx + 0x221], 0'),
        (0x145ce3de0, 'cmp', 'byte ptr [rcx + 0x222], 0'),
        (0x145ce3e3e, 'cmp', 'byte ptr [rcx + rdx], r9b'),
        (0x145ce3e58, 'lea', 'rax, [rax + 1]'),
        (0x145ce3e65, 'movzx', 'eax, byte ptr [rax]'),
        (0x145cd1706, 'cmp', 'byte ptr [rdx + rcx*4], r8b'),
        (0x145cd1740, 'lea', 'rcx, [rax + rax*2]'),
        (0x145cd1747, 'lea', 'rax, [rax + rcx*4]'),
        (0x145cd174b, 'inc', 'rax'),
        (0x145cd1759, 'inc', 'rax'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed readiness path changed: ' + hex(address))
    types = {p['value']: p['name'] for p in source['types']}
    if set(types) != set(range(11)) or types[10] != 'ForcedLock' or types[4] != 'EnterArea':
        raise ValueError('Condition type map changed')
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  getter=getter, anchors=[rows[a] for a, _, _ in checks],
                  condition_type_report_sha256=hashlib.sha256(type_bytes).hexdigest(),
                  context_map_offset=96, entry_stride=12, key_offset=0, value_offset=1,
                  reset_values=[dict(type=k, name=types[k], value=k == 10) for k in range(11)],
                  setter=dict(address=0x145ced600, type_register='DL', value_register='R8B'),
                  enter_area_writer=0x145cf5b10, runtime_evaluator_enabled=False,
                  limitations=['Setter event sources and full registration paths are not yet linked.',
                               'Readiness is separate from completion of a condition.',
                               'ForcedLock readiness true does not unlock it; predicate returns false.',
                               'The type-11 special path is separate from this 0..10 reset loop.',
                               'Notification callback meaning and flag names remain unknown.',
                               'No player state read or Android verification.'])
    output = ROOT / 'code-clues/lock-gate-code.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), fragments=len(fragments), reset_types=len(types),
                          default_true_types=[k for k in types if k == 10], runtime_evaluator_enabled=False)))


if __name__ == '__main__':
    main()
