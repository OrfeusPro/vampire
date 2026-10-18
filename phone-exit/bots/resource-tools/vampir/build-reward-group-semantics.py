"""Prove Reward.RewardGroup names; do not infer ItemBox.RewardGroupType."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('reward_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed client or decoder')
    image = native.Image(data)
    roots = {image.roots[image.containing(a)] for a in [0x1457dd970, 0x145b7ef30]}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    anchors = []

    def check(address, mnemonic, operands):
        row = rows[address]
        if (row['mnemonic'], row['operands']) != (mnemonic, operands):
            raise ValueError('Changed reward group anchor '+hex(address))
        anchors.append(row)
        return row

    def literal(address, name):
        row = rows[address]
        offset = image.offset(row['rip_references'][0]-image.pe.base)
        raw = name.encode()+b'\0'
        if row['mnemonic'] != 'lea' or data[offset:offset+len(raw)] != raw:
            raise ValueError('Changed reward group literal '+name)
        anchors.append(row)
        return offset

    pairs = [(1,'ClassFixed',0x1457dda6f,0x1457dda83),
             (3,'ClassRandom',0x1457dda8c,0x1457ddaa9),
             (6,'ClassSelect',0x1457ddab2,0x1457ddacf),
             (0,'Fixed',0x1457ddad8,0x1457ddaf7),
             (2,'Random',0x1457ddb00,0x1457ddb1f),
             (4,'RandomEach',0x1457ddb28,0x1457ddb47),
             (5,'Select',0x1457ddb50,0x1457ddb6f)]
    types = {}
    enum = {r['value']:r for r in source['enums']['ERewardGroup']}
    for i, (value, name, lea, store) in enumerate(pairs):
        offset = literal(lea, name)
        check(store, 'mov', f'byte ptr [rsp + {hex(0x20+i)}], {value}')
        if enum[value]['name'] != 'ERewardGroup::'+name:
            raise ValueError('Changed native enum')
        types[str(value)] = dict(value=value, name=name, name_offset=offset, field_name_verified=True)
    # Keep the complete dictionary construction, including stack pointer pairings.
    for address, row in rows.items():
        if 0x1457dda6f <= address <= 0x1457ddb9f and row not in anchors:
            anchors.append(row)
    check(0x1457ddb9f, 'call', '0x14450dc60')
    check(0x1457dda16, 'mov', 'al, 7')
    literal(0x145b7efd4, 'FRdRewardInfoManagerTemplate::ModifyValue')
    literal(0x145b7f3f7, 'RewardGroup')
    check(0x145b7f3ee, 'cmp', 'r14, 0xb')
    check(0x145b7f3fe, 'call', '0x1487a2e49')
    check(0x145b7f43e, 'call', '0x1457fd300')
    check(0x145b7f443, 'mov', 'byte ptr [rbx + 0x38], al')
    address = 0x1457fd300; offset = image.offset(address-image.pe.base); raw = data[offset:offset+5]
    if raw[0] != 0xe9 or address+5+int.from_bytes(raw[1:], 'little', signed=True) != 0x1457dd970:
        raise ValueError('Changed reward parser thunk')
    anchors.append(dict(address=address, file_offset=offset, bytes=raw.hex(), mnemonic='jmp', operands='0x1457dd970'))
    report = dict(source=source['source'], sha256=source['sha256'], field='Reward.RewardGroup',
                  types=types, unknown_value=7, anchors=anchors, fragments=fragments,
                  limitations=['Parser names and values verified for Reward.RewardGroup only.',
                               'This report does not establish ItemBox.RewardGroupType; see item-box-mode-binding.json.',
                               'Names do not prove runtime selection, quantities, class gates or percentage formulas.'])
    path = native.ROOT/'code-clues/reward-group-semantics.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(dict(types=len(types), anchors=len(anchors), sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
