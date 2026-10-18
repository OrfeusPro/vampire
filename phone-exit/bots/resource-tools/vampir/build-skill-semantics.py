"""Extract Skill.FireCondition names from the pinned client parser, not ID guesses."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def extract_dictionary(rows, data, image, start, end, first_slot, stop_slot, value_width='byte', constants=None):
    """Follow the initializer's explicit string/value pointer pairs on the stack."""
    registers, strings, values, pointers = {}, {}, {}, {}
    for row in sorted(rows, key=lambda r:r['address']):
        if not start <= row['address'] < end:
            continue
        op = row['operands']
        if row['mnemonic'] == 'lea':
            reg, address = op.split(', ', 1)
            registers[reg] = address
            if reg == 'rdx' and row['rip_references']:
                offset = image.offset(row['rip_references'][0] - image.pe.base)
                match = re.match(rb'[A-Za-z]+\x00', data[offset:offset+100])
                if not match:
                    raise ValueError('Changed condition literal')
                registers['literal'] = dict(name=match.group()[:-1].decode(), name_offset=offset, literal_anchor=row)
        elif row['mnemonic'] == 'call':
            if op != '0x141420f70':
                raise ValueError('Changed string constructor')
            strings[registers['rcx']] = registers['literal']
            registers.pop('rax', None)
        elif row['mnemonic'] == 'mov':
            match = re.fullmatch(value_width+r' ptr (\[(?:rsp|rbp)(?: [+-] (?:0x[0-9a-f]+|\d+))?\]), (0x[0-9a-f]+|\d+|edi)', op)
            if match:
                value = (constants or {}).get(match[2]) if match[2]=='edi' else int(match[2],0)
                if value is None:
                    raise ValueError('Unverified dictionary register constant')
                values[match[1]] = (value, row)
            match = re.fullmatch(r'qword ptr \[rbp(?: ([+-]) (0x[0-9a-f]+|\d+))?\], rax', op)
            if match:
                slot = int(match[2],0)*(-1 if match[1]=='-' else 1) if match[2] else 0
                pointers[slot] = (registers['rax'], row)
    result = {}
    for slot in range(first_slot, stop_slot, 16):
        name_ptr, name_anchor = pointers[slot]
        value_ptr, value_anchor = pointers[slot+8]
        value, byte_anchor = values[value_ptr]
        if str(value) in result:
            raise ValueError('Duplicate condition value')
        result[str(value)] = dict(strings[name_ptr], value=value,
            byte_anchor=byte_anchor, name_pointer_anchor=name_anchor, value_pointer_anchor=value_anchor)
    return result


def extract_conditions(rows, data, image):
    result = extract_dictionary(rows,data,image,0x1457e3638,0x1457e3da0,0x1e0,0x460)
    if len(result) != 40 or result['0']['name'] != 'Always' or '43' in result:
        raise ValueError('Changed condition dictionary')
    return result


def main():
    spec = importlib.util.spec_from_file_location('skill_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed executable or decoder')
    image = native.Image(data)
    roots = {image.roots[image.containing(a)] for a in [0x1457e3530, 0x145bc6470, 0x145bd69f0]}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']:r for f in fragments for r in f['instructions']}
    conditions = extract_conditions(list(rows.values()), data, image)
    expected = [
        (0x145bc6690,'lea','rax, [rip + 0x3df3bb1]'),
        (0x145bc71d5,'mov','byte ptr [rbx + 0x81], al'),
        (0x145bd7216,'lea','rdx, [rip + 0x3de302b]'),
        (0x145bd725c,'call','0x1457fe4e0'),
        (0x145bd7261,'mov','byte ptr [rbx + 0x81], al'),
        (0x1457e35dc,'mov','al, 0x2b'),
        (0x1457e3da0,'lea','rax, [rbp + 0x1e0]'),
        (0x1457e3dac,'lea','rax, [rbp + 0x460]'),
        (0x1457e3dc4,'call','0x14450dc60'),
        (0x145bc75a9,'mov','dword ptr [rbx + 0xc8], eax'),
        (0x145bc75cc,'mov','dword ptr [rbx + 0xcc], eax'),
        (0x145bc75ef,'mov','dword ptr [rbx + 0xd0], eax'),
    ]
    anchors = []
    for address, mnemonic, operands in expected:
        row = rows[address]
        if (row['mnemonic'],row['operands']) != (mnemonic,operands):
            raise ValueError('Changed skill anchor: '+hex(address))
        anchors.append(row)
    for address in [0x145bc6690, 0x145bd7216]:
        offset = image.offset(rows[address]['rip_references'][0]-image.pe.base)
        if data[offset:offset+14] != b'FireCondition\0':
            raise ValueError('Changed field literal')
    offset = image.offset(0x1457fe4e0-image.pe.base)
    # Explicit relative JMP binds the ModifyValue parser call to this dictionary.
    raw = data[offset:offset+5]
    if raw[0] != 0xe9 or 0x1457fe4e5+int.from_bytes(raw[1:],'little',signed=True) != 0x1457e3530:
        raise ValueError('Changed parser thunk')
    result = dict(source=source['source'],sha256=source['sha256'],
        conditions=conditions,unknown_parser_value=43,
        parser_thunk=dict(address=0x1457fe4e0,file_offset=offset,bytes=raw.hex()),
        anchors=anchors,fragments=fragments,
        relation='Skill.FireCondition / ModifyValue → byte +0x81 → parser thunk → string/value dictionary',
        timing=dict(TotalTime=dict(record_offset=0xc8),MaxCoolTime=dict(record_offset=0xcc),MinCoolTime=dict(record_offset=0xd0),unit=None),
        limitations=['Names are verified; runtime predicates and FireConditionParam semantics are not.',
            '43 is the parser fallback, not Always; its runtime behavior is unknown.',
            'Time fields are loaded as integers; seconds/milliseconds and damage formula remain unverified.'])
    path = native.ROOT/'code-clues/skill-semantics.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(conditions=len(conditions),anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
