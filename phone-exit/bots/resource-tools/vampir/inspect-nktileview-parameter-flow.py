"""Source-bound static parameter transfers selected by exact class-vtable differences."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tile_getter', HERE / 'inspect-nktileview-registration.py')
getter = importlib.util.module_from_spec(spec); spec.loader.exec_module(getter)
native = getter.native
SELECTED = {0xd8: 0x144a863d0, 0x300: 0x144a898e0, 0x310: 0x144a84a60, 0x358: 0x144a82420}


def inspect(request):
    if request['source_sha256'] != getter.SHA or request['question'] != 'ui-nktileview-property-schema':
        raise ValueError('Другой источник / вопрос')
    if not {hex(a) for a in SELECTED.values()} <= {f['address'] for f in request['functions']}:
        raise ValueError('Нет явных функций выбранных слотов')
    raw = Path(request['source']).read_bytes()
    if getter.sha(raw) != getter.SHA:
        raise ValueError('Изменился источник')
    image = native.Image(raw)
    tables = []
    for start, end in ((0x14965b6a0, 0x14965ba08), (0x149657a50, 0x149657db8)):
        offset = image.offset(start - image.pe.base); length = end - start
        values = struct.unpack_from('<' + 'Q' * (length // 8), raw, offset)
        if any(not any(s['name'] == '.text' and image.pe.base + s['rva'] <= a < image.pe.base + s['rva'] + s['raw_size'] for s in image.pe.sections) for a in values):
            raise ValueError('Таблица содержит не-code pointer')
        tables.append(dict(address=hex(start), end_before_secondary_table=hex(end),
            file_offset=offset, sha256=getter.sha(raw[offset:offset + length]), values=[hex(a) for a in values]))
    differences = [dict(slot=hex(k * 8), tile=a, related=b) for k, (a, b) in enumerate(zip(tables[0]['values'], tables[1]['values'])) if a != b]
    roots = set()
    for slot, address in SELECTED.items():
        if tables[0]['values'][slot // 8] != hex(address):
            raise ValueError('Изменился выбранный virtual slot')
        row = image.containing(address)
        if row is None or image.pe.base + image.roots[row][0] != address:
            raise ValueError('Изменилась unwind граница')
        roots.add(image.roots[row])
    fragments = native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    expected = {
        0x144a89919: ('lea', 'rdx, [rbx + 0x430]'),
        0x144a89920: ('call', '0x144628e30'),
        0x144a89933: ('movups', 'xmm0, xmmword ptr [rbx + 0x440]'),
        0x144a8993a: ('movups', 'xmmword ptr [rax + 0x14d0], xmm0'),
        0x144a89948: ('movups', 'xmm0, xmmword ptr [rbx + 0x450]'),
        0x144a8994f: ('movups', 'xmmword ptr [rax + 0x14e0], xmm0'),
        0x144a89aa7: ('jmp', '0x144626640'),
        0x144a863fe: ('jmp', 'qword ptr [rax + 0x300]'),
        0x144a84a88: ('cmp', 'qword ptr [rcx + 0x408], 0'),
        0x144a84b6e: ('lea', 'rax, [r14 + 0x408]'),
        0x144a84b86: ('mov', 'qword ptr [rax], rdi'),
        0x144a824a1: ('call', '0x144604310'),
    }
    for at, pair in expected.items():
        row = rows.get(at)
        if row is None or (row['mnemonic'], row['operands']) != pair:
            raise ValueError('Изменился путь параметров: ' + hex(at))
    return dict(source_sha256=getter.SHA, tables=tables, differing_slots=differences, fragments=fragments,
        parameter_transfers=[
            dict(owner_offset='0x430', receiver_offset='0x14b8', bytes=16, via='0x144628e30', status='setter_verified_by_prior_bounded_replay'),
            dict(owner_offset='0x440', receiver_offset='0x14d0', bytes=16, status='static_movups_copy'),
            dict(owner_offset='0x450', receiver_offset='0x14e0', bytes=16, status='static_movups_copy')],
        receiver_pointer_owner_offset='0x408',
        unresolved=['Names/units/producers of owner blocks 430/440/450', 'reflection order and cooked compatibility',
            'factory/calculated entry binding', 'callbacks, scheduling and complete lifecycle'],
        limits=['Vtable spans are bounded by observed secondary-table addresses; no full class hierarchy recovered.',
            'Only four differing unwind roots decoded; other differing slots are candidates, not analyzed methods.',
            'Static transfers do not establish actual values, defaults, field names or successful widget creation.',
            'Current native SHA does not validate historical cooked fields. No game commands / native execution.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Прежний отчёт не перезаписывается')
    result = inspect(json.loads(args.request.read_text('utf-8')))
    result['inspector_sha256'] = getter.sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(differing_slots=len(result['differing_slots']), fragments=len(result['fragments']),
        parameter_transfers=result['parameter_transfers']), ensure_ascii=False))
