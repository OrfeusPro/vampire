"""Bind ContentsLock columns to native predicate fields and direct callers."""
import csv
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lock_field_calls', HERE / 'build-entry-window-code.py')
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
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(calls.direct_call_candidates(data, section['raw'], section['raw_size'],
                                                        image.pe.address, {0x145cf2dc0}))
    roots = {image.roots[image.containing(a)] for a, _ in candidates if image.containing(a)}
    roots.update(image.roots[image.containing(a)] for a in (0x1458f2350, 0x145cf2dc0))
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    verified, unresolved = [], []
    for address, target in candidates:
        row = rows.get(address)
        if calls.checked_call(row, target):
            verified.append(row)
        else:
            unresolved.append(dict(address=address, target=target))
    expected_callers = {0x145ce66a4, 0x145cf0992, 0x145cf0cfa, 0x145cf0fec, 0x145cf5411}
    if unresolved or {r['address'] for r in verified} != expected_callers:
        raise ValueError('Reviewed direct caller set changed')
    checks = [
        (0x1458f25c9, 'mov', 'r14, qword ptr [rbp + r15*8 + 0x180]'),
        (0x1458f271c, 'mov', 'word ptr [rbp + r15*2 + 0x210], bx'),
        (0x1458f2728, 'cmp', 'r15, 0x10'),
        (0x1458f2825, 'movzx', 'edi, word ptr [rbp + 0x210]'),
        (0x1458f2883, 'mov', 'dword ptr [rbx + 8], eax'),
        (0x1458f2889, 'movzx', 'edx, word ptr [rbp + 0x212]'),
        (0x1458f28a0, 'mov', 'byte ptr [rbx + 0xc], al'),
        (0x1458f28a6, 'movzx', 'edx, word ptr [rbp + 0x214]'),
        (0x1458f28b7, 'mov', 'byte ptr [rbx + 0xd], al'),
        (0x1458f28c3, 'movzx', 'edx, word ptr [rbp + 0x216]'),
        (0x1458f28d4, 'mov', 'byte ptr [rbx + 0xe], al'),
        (0x1458f2a2c, 'movzx', 'edx, word ptr [rbp + 0x21a]'),
        (0x1458f2a3d, 'mov', 'dword ptr [rbx + 0x20], eax'),
        (0x145cf2de5, 'cmp', 'byte ptr [rbx + 0xe], 1'),
        (0x145cf2df9, 'mov', 'eax, dword ptr [rbx + 8]'),
        (0x145cf2e24, 'mov', 'eax, dword ptr [rbx + 8]'),
        (0x145cf2e3d, 'mov', 'eax, dword ptr [rbx + 0x20]'),
        (0x145cf2e4e, 'call', '0x1458de420'),
    ]
    for address, mnemonic, operands in checks:
        if (rows[address]['mnemonic'], rows[address]['operands']) != (mnemonic, operands):
            raise ValueError('Reviewed field binding changed: ' + hex(address))
    fields = []
    for address, name, index, object_offset, width in [
            (0x1458f24b1, 'Id', 0, 8, 4),
            (0x1458f24c8, 'OpenNotification', 1, 12, 1),
            (0x1458f24e3, 'SystemMessageNotify', 2, 13, 1),
            (0x1458f24fb, 'SaveType', 3, 14, 1),
            (0x1458f2517, 'ContentsLockConditionGroupId', 5, 32, 4)]:
        row = rows[address]
        if row['mnemonic'] != 'lea' or len(row['rip_references']) != 1:
            raise ValueError('Column header instruction changed')
        offset = image.offset(row['rip_references'][0] - image.pe.base)
        raw = data[offset:offset + len(name) + 1]
        if raw != name.encode('ascii') + b'\0':
            raise ValueError('Column literal changed')
        fields.append(dict(name=name, column_index=index, object_offset=object_offset, width=width,
                           header_instruction=row, literal_file_offset=offset, literal_bytes=raw.hex()))
    tables = json.loads((ROOT / 'table-study/index-pakchunk1-Windows.json').read_text(encoding='utf-8'))['tables']
    meta = next(row for row in tables if row['entry'] == 69)
    path = ROOT / 'table-study' / meta['file']
    if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('ContentsLock CSV changed')
    with path.open(encoding='utf-8-sig', newline='') as stream:
        csv_rows = [dict(csv_record=index, row=row) for index, row in enumerate(csv.DictReader(stream), 2)]
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
                  fields=fields, anchors=[rows[a] for a, _, _ in checks],
                  predicate=0x145cf2dc0, direct_callers=verified, unresolved_candidates=unresolved,
                  csv_source=meta, csv_rows=csv_rows,
                  save_type_counts=dict(Counter(r['row']['SaveType'] for r in csv_rows)),
                  limitations=['Names of SaveType numeric values remain unknown.',
                               'Direct E8 callers only; indirect calls not enumerated.',
                               'Field names do not prove initialization or freshness of player state.',
                               'No Android or player-state evaluation performed.'])
    output = ROOT / 'code-clues/contents-lock-fields.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(fields=len(fields), anchors=len(checks), direct_callers=len(verified),
                          unresolved=len(unresolved), fragments=len(fragments),
                          csv_rows=len(csv_rows), save_type_counts=report['save_type_counts'])))


if __name__ == '__main__':
    main()
