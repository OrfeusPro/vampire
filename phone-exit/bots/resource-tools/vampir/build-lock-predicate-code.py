"""Checked client condition predicate and group loop; no game execution."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('predicate_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def decode_span(image, begin, end):
    """Decode a reviewed code-only span; embedded switch data stays separate."""
    offset = image.offset(begin - image.pe.base)
    raw = image.data[offset:offset + end - begin]
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    rows = []
    for ins in decoder.disasm(raw, begin):
        direct = (ins.operands[0].imm if ins.operands and
                  ins.operands[0].type == native.X86_OP_IMM and
                  (ins.group(native.capstone.CS_GRP_JUMP) or ins.group(native.capstone.CS_GRP_CALL))
                  else None)
        rows.append(dict(address=ins.address, bytes=bytes(ins.bytes).hex(),
                         mnemonic=ins.mnemonic, operands=ins.op_str, direct_target=direct,
                         file_offset=offset + ins.address - begin,
                         rip_references=[ins.address + ins.size + op.mem.disp for op in ins.operands
                                         if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]))
    if sum(len(bytes.fromhex(r['bytes'])) for r in rows) != len(raw):
        raise ValueError('Reviewed code span not fully decoded')
    return dict(begin=begin, end=end, file_offset=offset,
                sha256=hashlib.sha256(raw).hexdigest(), instructions=rows)


def checked_switch(raw, image_base, boundaries):
    if len(raw) != 44:
        raise ValueError('Expected eleven switch entries')
    targets = [image_base + value for value in struct.unpack('<11I', raw)]
    if any(target not in boundaries for target in targets):
        raise ValueError('Switch target outside reviewed instruction boundaries')
    return targets


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    type_path = native.ROOT / 'quest-graph/condition-types.json'
    type_bytes = type_path.read_bytes()
    source = json.loads(type_bytes)
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    code = decode_span(image, 0x145cda340, 0x145cda480)
    gate = decode_span(image, 0x145ce3dd0, 0x145ce3e69)
    addresses = (0x145cf2dc0, 0x145cf33c0, 0x1458de420, 0x145de21b0, 0x145de2250)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {r['address']: r for part in [code, gate] + fragments for r in part['instructions']}
    checks = [
        (0x145cda360, 'cmp', 'sil, 0xb'), (0x145cda364, 'je', '0x145cda447'),
        (0x145cda36e, 'call', '0x145ce3dd0'), (0x145cda375, 'je', '0x145cda47a'),
        (0x145cda37b, 'cmp', 'esi, 0xa'), (0x145cda395, 'jmp', 'rcx'),
        (0x145cda39e, 'cmp', 'rbx, rax'), (0x145cda3a1, 'setbe', 'al'),
        (0x145cda3ac, 'call', '0x145de21b0'), (0x145cda3b9, 'call', '0x145de2250'),
        (0x145cda3c9, 'cmp', 'rbx, rax'), (0x145cda3cc, 'setbe', 'al'),
        (0x145cda41c, 'cmp', 'rbp, rax'), (0x145cda41f, 'setbe', 'al'),
        (0x145cda472, 'cmp', 'rax, rbp'), (0x145cda475, 'setae', 'al'),
        (0x145cda447, 'mov', 'al, 1'), (0x145cda47a, 'xor', 'al, al'),
        (0x145cf2dcf, 'mov', 'r8b, 0xa'), (0x145cf2dd8, 'call', '0x145cf33c0'),
        (0x145cf2ddf, 'jne', '0x145cf2eb6'),
        (0x145cf3413, 'cmp', 'byte ptr [rax + 0x10], bl'),
        (0x145cf2e8e, 'movzx', 'edx, byte ptr [rax + 0x10]'),
        (0x145cf2e92, 'call', '0x145cda340'),
        (0x145cf2e99, 'je', '0x145cf2eb6'),
        (0x145cf2ea2, 'jne', '0x145cf2e80'),
        (0x145cf2ea4, 'mov', 'al, 1'), (0x145cf2ebb, 'xor', 'al, al'),
        (0x145cf2e60, 'je', '0x145cf2ea4'),
        (0x145cf2e7a, 'je', '0x145cf2ea4'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed predicate changed: ' + hex(address))
    table_offset = image.offset(0x5cda480)
    table = data[table_offset:table_offset + 44]
    targets = checked_switch(table, image.pe.base, {r['address'] for r in code['instructions']})
    expected = [0x145cda397, 0x145cda3a9, 0x145cda3b6, 0x145cda3c3,
                0x145cda3d1, 0x145cda47a, 0x145cda47a, 0x145cda3da,
                0x145cda424, 0x145cda45e, 0x145cda47a]
    if targets != expected:
        raise ValueError('Reviewed type dispatch changed')
    # Type names come from the independently checked native converter report.
    names = {int(p['value']): p['name'] for p in source['types']}
    if set(names) != set(range(11)):
        raise ValueError('Condition type map incomplete')
    report = dict(source=source['source'], sha256=source['sha256'],
                  condition_type_report_sha256=hashlib.sha256(type_bytes).hexdigest(),
                  code_spans=[code, gate], fragments=fragments,
                  anchors=[rows[a] for a, _, _ in checks],
                  switch=dict(address=0x145cda480, file_offset=table_offset, bytes=table.hex(),
                              entries=[dict(type=k, name=names[k], target=t) for k, t in enumerate(targets)]),
                  group_loop='all_conditions_until_first_false_after_prechecks_and_overrides',
                  missing_or_empty_group_result=True, forced_lock_presence_checked_first=True,
                  runtime_evaluator_enabled=False,
                  limitations=['Windows client predicate only; gate and override state sources unresolved.',
                               'CompletedQuest and CompletedQuestTask helpers are stateful, not simple ID membership.',
                               'Do not generalize the AND loop to server behavior or ignore early branches.',
                               'Code span ends before embedded switch table; table bytes are not instructions.',
                               'No Android or player-state evaluation performed.'])
    output = native.ROOT / 'code-clues/lock-predicate-code.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(anchors=len(checks), switch_types=len(targets), fragments=len(fragments),
                          group_loop=report['group_loop'], runtime_evaluator_enabled=False)))


if __name__ == '__main__':
    main()
