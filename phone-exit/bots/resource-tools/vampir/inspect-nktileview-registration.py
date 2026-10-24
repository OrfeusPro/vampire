"""Source-bound static NkTileView class-getter evidence; no native execution."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tile_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
ROOT = 0x144a66f20


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect(request):
    if request['source_sha256'] != SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Задание относится к другой версии / вопросу')
    if hex(ROOT) not in [f['address'] for f in request['functions']]:
        raise ValueError('Явный root не входит в задание')
    raw = Path(request['source']).read_bytes()
    if sha(raw) != SHA:
        raise ValueError('Изменился EXE; старые адреса не применяются')
    image = native.Image(raw); function = image.containing(ROOT)
    if function is None or image.pe.base + image.roots[function][0] != ROOT:
        raise ValueError('Изменилась unwind граница функции')
    fragments = native.decode_ranges(image, {image.roots[function]})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    required = {
        0x144a66f27: ('mov', 'rax, qword ptr [rip + 0x6b2a7ea]'),
        0x144a66f31: ('jne', '0x144a66fc9'),
        0x144a66f54: ('lea', 'r8, [rip + 0x6b2a7bd]'),
        0x144a66f66: ('lea', 'rdx, [rip + 0x4bec955]'),
        0x144a66f75: ('lea', 'rcx, [rip + 0x4bd6ca4]'),
        0x144a66fb5: ('mov', 'dword ptr [rsp + 0x20], 0x470'),
        0x144a66fbd: ('call', '0x1416ab8d0'),
        0x144a66fc2: ('mov', 'rax, qword ptr [rip + 0x6b2a74f]'),
    }
    for at, expected in required.items():
        row = rows.get(at)
        if row is None or (row['mnemonic'], row['operands']) != expected:
            raise ValueError('Изменилась выбранная последовательность инструкции')
    literals = {}
    for at, expected in [(0x144a66f66, 'NkTileView'), (0x144a66f75, '/Script/NkUMG')]:
        address = rows[at]['rip_references'][0]; offset = image.offset(address - image.pe.base)
        encoded = expected.encode('utf-16le') + b'\0\0'
        if raw[offset:offset + len(encoded)] != encoded:
            raise ValueError('Изменился литерал имени / пакета')
        literals[expected] = dict(address=hex(address), file_offset=offset, bytes=encoded.hex())
    return dict(source=request['source'], source_sha256=SHA, address=hex(ROOT), fragments=fragments,
        literals=literals, singleton_pointer='0x14b591718', helper='0x1416ab8d0',
        next_function_candidates=['0x144a88f70', '0x144a6a620', '0x144a2ec60'],
        observation='Getter returns a cached pointer; otherwise supplies NkTileView and /Script/NkUMG to helper, then reloads pointer.',
        limits=['Static class-getter shape and exact literals, no native execution or helper semantic proof.',
            '0x470 is a supplied argument, not a proved UObject size or serialization schema.',
            'Function pointers are next research candidates, not confirmed constructors / registration callbacks.',
            'No reflected properties, entry widget binding or compatibility with old cooked packages established.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Прежний отчёт не перезаписывается')
    result = inspect(json.loads(args.request.read_text('utf-8')))
    result['inspector_sha256'] = sha(Path(__file__).read_bytes())
    result['request_sha256'] = sha(args.request.read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(source_sha256=SHA, address=hex(ROOT), fragments=len(result['fragments'])), ensure_ascii=False))
