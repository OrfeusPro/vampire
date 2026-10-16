"""Record checked condition-row loader layout, without inventing evaluation."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('loader_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((native.ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    fragments = native.decode_ranges(image, {
        image.roots[image.containing(address)] for address in (0x1458dc430, 0x1458f1970)})
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    checks = [
        (0x1458dc516, 'mov', 'qword ptr [rsi + 8], rax'),
        (0x1458dc51c, 'mov', 'byte ptr [rsi + 0x18], 0xb'),
        (0x1458f1dab, 'call', '0x1458dc430'),
        (0x1458f1db5, 'imul', 'rbx, rax, 0x38'),
        (0x1458f1dc3, 'add', 'rbx, 8'),
        (0x1458f1dcc, 'mov', 'dword ptr [rbx + 8], eax'),
        (0x1458f1de9, 'mov', 'dword ptr [rbx + 0xc], eax'),
        (0x1458f1e06, 'mov', 'byte ptr [rbx + 0x10], al'),
        (0x1458f1e1f, 'mov', 'qword ptr [rbx + 0x18], rax'),
        (0x1458f1e39, 'mov', 'qword ptr [rbx + 0x20], rax'),
        (0x1458f19d4, 'lea', 'r12, [rbx + 0x60]'),
        (0x1458f1b2f, 'mov', 'qword ptr [rbp + 0x128], rax'),
        (0x1458f1cc4, 'mov', 'word ptr [rbp + r13*2 + 0x148], bx'),
        (0x1458f1dd8, 'movzx', 'edx, word ptr [rbp + 0x14a]'),
        (0x1458f2101, 'mov', 'r8d, dword ptr [rdi + 0x14]'),
        (0x1458f2149, 'cmp', 'dword ptr [rax], r8d'),
        (0x1458f2142, 'shl', 'rax, 5'),
        (0x1458f218d, 'lea', 'rbx, [rax + 8]'),
        (0x1458f2191, 'lea', 'rsi, [rdi + 8]'),
        (0x1458f2195, 'movsxd', 'rdi, dword ptr [rbx + 8]'),
        (0x1458f219c, 'mov', 'dword ptr [rbx + 8], eax'),
        (0x1458f21b8, 'mov', 'qword ptr [rax + rdi*8], rsi'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed loader changed: ' + hex(address))
    vtable = rows[0x1458dc50f]['rip_references']
    if vtable != [0x149938848]:
        raise ValueError('Condition vtable changed')
    offset = image.offset(vtable[0] - image.pe.base)
    # Only slots +8 through +0x28 are used in the reviewed field-loading block.
    slots = struct.unpack_from('<6Q', data, offset)
    if slots[1:] != (0x1413fe190,) * 5:
        raise ValueError('Condition post-load methods changed')
    noop = image.offset(0x1413fe190 - image.pe.base)
    if data[noop:noop + 3] != bytes.fromhex('c20000'):
        raise ValueError('Post-load method no longer an empty return')
    fields = []
    for address, name, field_offset, width in [
            (0x1458f1b17, 'Id', 8, 4), (0x1458f1b28, 'GroupId', 12, 4),
            (0x1458f1b36, 'ConditionType', 16, 1),
            (0x1458f1b44, 'ConditionTypeValue1', 24, 8),
            (0x1458f1b52, 'ConditionTypeValue2', 32, 8)]:
        instruction = rows[address]
        if instruction['mnemonic'] != 'lea' or len(instruction['rip_references']) != 1:
            raise ValueError('Column header reference changed')
        literal_offset = image.offset(instruction['rip_references'][0] - image.pe.base)
        literal = data[literal_offset:literal_offset + len(name) + 1]
        if literal != name.encode('ascii') + b'\0':
            raise ValueError('Column header changed')
        fields.append(dict(name=name, offset=field_offset, width=width,
                           header_instruction=instruction, literal_file_offset=literal_offset,
                           literal_bytes=literal.hex()))
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  anchors=[rows[a] for a, _, _ in checks],
                  vtable_address=vtable[0], vtable_file_offset=offset,
                  vtable_slots=list(slots), noop=dict(address=0x1413fe190, bytes='c20000'),
                  entry_stride=56, condition_object_offset=8,
                  loaded_fields=fields,
                  group_index=dict(manager_relative_offset=96, entry_stride=32,
                                   key='GroupId', value_offset=8, member_width=8,
                                   members='pointers_to_condition_objects',
                                   combination='unknown_do_not_assume_AND_OR'),
                  default_type=11, evaluator_found=False,
                  limitations=['Field layout is storage, not comparison semantics.',
                               'Empty post-load methods are not condition evaluation.',
                               'AND/OR, server checks and Android behavior remain unverified.'])
    output = native.ROOT / 'code-clues/lock-loader-links.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(fragments=len(fragments), checked_anchors=len(checks),
                          entry_stride=56, empty_post_load_slots=5, evaluator_found=False)))


if __name__ == '__main__':
    main()
