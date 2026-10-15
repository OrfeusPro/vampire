"""Recover native non-reflected condition name/value initialization and CSV links."""
import csv
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lock_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
ROOT = native.ROOT


def pair_initializers(rows, read_name):
    pairs = []
    for index, row in enumerate(rows):
        if row['mnemonic'] != 'lea' or not row['operands'].startswith('rdx, [rip ') or len(row['rip_references']) != 1:
            continue
        name = read_name(row['rip_references'][0])
        if not name:
            continue
        following = rows[index + 1:index + 10]
        call_index = next((i for i, r in enumerate(following) if r['mnemonic'] == 'call'), None)
        if call_index is None or following[call_index]['direct_target'] != 0x141420f70:
            raise ValueError('Condition name construction changed')
        stores = []
        for candidate in following[call_index + 1:]:
            match = re.fullmatch(r'byte ptr \[rsp \+ (0x[0-9a-f]+)\], (0x[0-9a-f]+|[0-9]+)', candidate['operands'])
            if candidate['mnemonic'] == 'mov' and match:
                stores.append((candidate, int(match[1], 16), int(match[2], 0)))
                break
            if candidate['mnemonic'] == 'call':
                break
        if len(stores) != 1:
            raise ValueError('Condition enum initializer missing')
        store, slot, value = stores[0]
        if not 0 <= value <= 255:
            raise ValueError('Condition enum value outside byte')
        pairs.append(dict(name=name, value=value, stack_slot=slot,
                          name_instruction=row, construction_call=following[call_index], value_instruction=store))
    if len({p['name'] for p in pairs}) != len(pairs) or len({p['value'] for p in pairs}) != len(pairs):
        raise ValueError('Duplicate condition enum initializer')
    if pairs and [p['stack_slot'] for p in pairs] != list(range(pairs[0]['stack_slot'], pairs[0]['stack_slot'] + len(pairs))):
        raise ValueError('Condition initializer slots not contiguous')
    return pairs


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source = json.loads((ROOT / 'code-clues/native-enums.json').read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    addresses = (0x145901730, 0x1457a9000)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = sorted((row for part in fragments if part['root_begin_rva'] == 0x57a9000
                   for row in part['instructions']), key=lambda row: row['address'])
    name_proofs = {}
    def read_name(address):
        offset = image.offset(address - image.pe.base)
        raw = data[offset:offset + 128].split(b'\0')[0]
        if not re.fullmatch(rb'[A-Za-z][A-Za-z0-9]+', raw):
            raise ValueError('Invalid condition name literal')
        name = raw.decode('ascii')
        name_proofs[name] = dict(file_offset=offset, bytes=(raw + b'\0').hex())
        return name
    # Bound the reviewed initialization block, preserving only its instructions.
    init_rows = [row for row in rows if 0x1457a9108 <= row['address'] <= 0x1457a92bc]
    pairs = pair_initializers(init_rows, read_name)
    if len(pairs) != 11 or {p['value'] for p in pairs} != set(range(11)):
        raise ValueError('Expected complete 11-value condition map')
    for pair in pairs:
        pair['literal'] = name_proofs[pair['name']]
    schema_rows = {r['address']: r for part in fragments for r in part['instructions']}
    for address, operands in [(0x1459018ae, '0x1457f6dc0'), (0x1459018b3, 'byte ptr [rbx + 0x10], al'),
                              (0x145901916, 'qword ptr [rbx + 0x18], rax'), (0x145901955, 'qword ptr [rbx + 0x20], rax')]:
        if schema_rows[address]['operands'] != operands:
            raise ValueError('Condition modifier field mapping changed')
    thunk_offset = image.offset(0x57f6dc0)
    if data[thunk_offset:thunk_offset + 5] != bytes.fromhex('e93b22fbff'):
        raise ValueError('Condition conversion thunk changed')
    tables = json.loads((ROOT / 'table-study/index-pakchunk1-Windows.json').read_text(encoding='utf-8'))['tables']
    meta = next(row for row in tables if row['entry'] == 70)
    path = ROOT / 'table-study' / meta['file']
    if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Condition CSV changed')
    names = {str(p['value']): p['name'] for p in pairs}
    with path.open(encoding='utf-8-sig', newline='') as stream:
        conditions = [dict(row=row, csv_record=index, type_name=names[row['ConditionType']],
                           evaluation='not_evaluated') for index, row in enumerate(csv.DictReader(stream), 2)]
    report = dict(source=source['source'], sha256=source['sha256'], fragments=fragments,
        conversion_thunk=dict(address=0x1457f6dc0, file_offset=thunk_offset, bytes=data[thunk_offset:thunk_offset + 5].hex(), target=0x1457a9000),
        types=pairs, condition_source=meta, conditions=conditions,
        limitations=['Name/value map is native initializer evidence, not reflected enum descriptor order.',
                     'Modifier links field conversion to map; numeric comparison and AND/OR evaluator unresolved.',
                     'Windows source data; character/server state and Android parity not inspected.'])
    (ROOT / 'quest-graph/condition-types.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(types=[dict(name=p['name'], value=p['value']) for p in pairs], conditions=len(conditions))))


if __name__ == '__main__':
    main()
