"""Inspect exact NkTileView class-function candidates after explicit request preparation."""
import argparse
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tile_getter', HERE / 'inspect-nktileview-registration.py')
getter = importlib.util.module_from_spec(spec); spec.loader.exec_module(getter)
native = getter.native
ROOTS = (0x1416b2c10, 0x144a6a620, 0x144a6f9e0, 0x144a7b370, 0x144a88f70)


def inspect(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in ROOTS} <= {f['address'] for f in request['functions']}:
        raise ValueError('Не все явные функции входят в задание')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA:
        raise ValueError('Изменился EXE; старые адреса не используются')
    image = native.Image(raw); roots = set()
    for address in ROOTS:
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address:
            raise ValueError('Не совпадает unwind root')
        roots.add(image.roots[row])
    fragments = native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    checks = {
        0x144a88f74: ('call', '0x144a66f20'),
        0x144a88f79: ('mov', 'r8d, 1'),
        0x144a88f7f: ('lea', 'rdx, [rip + 0x4bd2ac2]'),
        0x144a88f8d: ('jmp', '0x1416b2c10'),
        0x144a6a626: ('mov', 'rbx, qword ptr [rcx]'),
        0x144a6a631: ('call', '0x144a6f9e0'),
        0x144a6a63d: ('mov', 'byte ptr [rbx + 0x428], 1'),
        0x144a6a654: ('mov', 'qword ptr [rbx + 0x408], rax'),
        0x144a6a65b: ('mov', 'qword ptr [rbx + 0x410], rax'),
        0x144a6a662: ('mov', 'qword ptr [rbx + 0x418], rax'),
        0x144a6a669: ('mov', 'qword ptr [rbx + 0x420], rax'),
        0x144a6a670: ('mov', 'dword ptr [rbx + 0x460], eax'),
        0x1416b2c60: ('mov', 'rdi, qword ptr [rsi]'),
        0x1416b2c63: ('mov', 'r12, qword ptr [rsi + 8]'),
        0x1416b2d58: ('mov', 'qword ptr [rcx + 8], r12'),
        0x1416b2d6e: ('add', 'rsi, 0x10'),
    }
    for at, expected in checks.items():
        row = rows.get(at)
        if row is None or (row['mnemonic'], row['operands']) != expected:
            raise ValueError('Изменился проверяемый путь: ' + hex(at))
    table = rows[0x144a88f7f]['rip_references'][0]
    offset = image.offset(table - image.pe.base)
    name_pointer, callback = struct.unpack_from('<QQ', raw, offset)
    name_offset = image.offset(name_pointer - image.pe.base)
    if raw[name_offset:name_offset + 8] != b'Refresh\0' or callback != 0x144a8f220:
        raise ValueError('Изменилась пара имени / указателя функции')
    class_pointer = rows[0x144a7b3b6]['rip_references'][0]
    class_offset = image.offset(class_pointer - image.pe.base)
    if raw[class_offset:class_offset + 26] != 'NkScrollView\0'.encode('utf-16le'):
        raise ValueError('Изменился литерал базового кандидата')
    return dict(source_sha256=getter.SHA, source=request['source'], fragments=fragments,
        callback_table=dict(address=hex(table), file_offset=offset, bytes=raw[offset:offset + 16].hex(),
            count_argument=1, name='Refresh', name_pointer=hex(name_pointer), callback=hex(callback),
            status='static_name_pointer_association_not_runtime_dispatch'),
        initialization=dict(pointer_source='[rcx]', first_call='0x144a6f9e0',
            byte_428=1, zero_qwords=['0x408', '0x410', '0x418', '0x420'], zero_dword='0x460',
            property_names='unknown', defaults_for_serialization_verified=False),
        base_candidate=dict(getter='0x144a7b370', literal='NkScrollView',
            status='related_class_getter_not_complete_inheritance_schema'),
        next_candidates=['0x144a8f220'],
        limits=['Static instructions / tables only; no native execution or registration side effects.',
            'Refresh callback body not inspected here; association is not a proved button binding.',
            'Initialization writes do not name reflected properties or establish serialized defaults.',
            'NkScrollView metadata and inheritance order remain unresolved; old cooked compatibility unverified.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Прежний отчёт не перезаписывается')
    result = inspect(json.loads(args.request.read_text('utf-8')))
    result['request_sha256'] = getter.sha(args.request.read_bytes())
    result['inspector_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(source_sha256=getter.SHA, fragments=len(result['fragments']),
        callback=result['callback_table']), ensure_ascii=False))
