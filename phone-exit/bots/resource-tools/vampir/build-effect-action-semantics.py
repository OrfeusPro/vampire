"""Verify Effect.ActionType parser dictionary; preserve unknown fallback and raw time."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def main():
    native=module('effect_action_native','build-native-entry-code.py')
    extractor=module('effect_dictionary','build-skill-semantics.py')
    source=json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256'] or native.capstone.__version__!='5.0.6':
        raise ValueError('Changed executable or decoder')
    image=native.Image(data)
    roots={image.roots[image.containing(a)]for a in [0x145975db0,0x1457ac630]}
    fragments=native.decode_ranges(image,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    expected=[(0x145976653,'lea','rdx, [rip + 0x388caee]'),
        (0x145976699,'call','0x1457f7ab0'),(0x14597669e,'mov','dword ptr [rdi + 0x90], eax'),
        (0x1457ac66d,'xor','edi, edi'),(0x1457ac6db,'mov','eax, 0x38'),
        (0x1457ad26f,'lea','rax, [rbp + 0x390]'),(0x1457ad27a,'lea','rax, [rbp + 0x710]'),
        (0x1457ad285,'call','0x14450d970'),
        (0x1459762c9,'lea','rdx, [rip + 0x3525508]'),(0x1459762e1,'mov','dword ptr [rdi + 0x58], eax'),
        (0x14597630c,'lea','rdx, [rip + 0x3fcff4d]'),(0x145976357,'call','0x1457f9f60')]
    anchors=[]
    for address,mnemonic,operands in expected:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
            raise ValueError('Changed effect action anchor '+hex(address))
        anchors.append(row)
    for address,name in [(0x145976653,'ActionType'),(0x1459762c9,'Duration'),(0x14597630c,'MinDuration')]:
        offset=image.offset(rows[address]['rip_references'][0]-image.pe.base);literal=name.encode()+b'\0'
        if data[offset:offset+len(literal)]!=literal:
            raise ValueError('Changed effect field name')
    actions=extractor.extract_dictionary(list(rows.values()),data,image,0x1457ac73a,0x1457ad268,0x390,0x710,
        value_width='dword',constants={'edi':0})
    for value in actions.values():
        value['value_anchor']=value.pop('byte_anchor')
    if len(actions)!=56 or actions['0']['name']!='None' or actions['6']['name']!='Stun' or '56'in actions:
        raise ValueError('Changed action dictionary')
    address=0x1457f7ab0;offset=image.offset(address-image.pe.base);raw=data[offset:offset+5]
    if raw[0]!=0xe9 or address+5+int.from_bytes(raw[1:],'little',signed=True)!=0x1457ac630:
        raise ValueError('Changed effect action thunk')
    result=dict(source=source['source'],sha256=source['sha256'],actions=actions,unknown_parser_value=56,
        anchors=anchors,parser_thunk=dict(address=address,file_offset=offset,bytes=raw.hex()),fragments=fragments,
        relation='Effect.ActionType → ModifyValue record+0x90 → parser 0x1457f7ab0 → 56 string/dword pairs',
        limitations=['Names are verified; runtime action behavior and ActionParam role are not.',
            '56 is parser fallback; None is 0.',
            'SkillOperation parameter-to-Effect link remains a candidate. Time units remain unknown.'])
    path=native.ROOT/'code-clues/effect-action-semantics.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(actions=len(actions),anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':
    main()
