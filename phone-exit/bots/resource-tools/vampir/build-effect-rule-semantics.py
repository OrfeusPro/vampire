"""Extract Effect BuffType/OverlayType names without evaluating lifecycle rules."""
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
    native=module('effect_rule_native','build-native-entry-code.py')
    extractor=module('effect_rule_dictionary','build-skill-semantics.py')
    source=json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256'] or native.capstone.__version__!='5.0.6':
        raise ValueError('Changed executable or decoder')
    image=native.Image(data)
    roots={image.roots[image.containing(a)]for a in [0x145975db0,0x1457f5e50,0x1457ad640]}
    fragments=native.decode_ranges(image,roots);rows={r['address']:r for f in fragments for r in f['instructions']}
    expected=[
        (0x145976250,'lea','rdx, [rip + 0x3fcfff9]'),
        (0x145976296,'call','0x1457f5e50'),(0x14597629b,'mov','byte ptr [rdi + 0x55], al'),
        (0x145976596,'lea','rdx, [rip + 0x3fac8ab]'),
        (0x1459765dc,'call','0x1457f7ac0'),(0x1459765e1,'mov','byte ptr [rdi + 0x88], al'),
        (0x1457f5ef7,'mov','al, 3'),(0x1457ad6e6,'mov','al, 5'),
        (0x1457f5fc7,'lea','rax, [rbp + 0x17]'),(0x1457f5fcf,'lea','rax, [rbp + 0x47]'),
        (0x1457f5fd7,'call','0x14450dc60'),
        (0x1457ad7fe,'lea','rax, [rbp - 9]'),(0x1457ad806,'lea','rax, [rbp + 0x47]'),
        (0x1457ad80e,'call','0x14450dc60')]
    anchors=[]
    for address,mnemonic,operands in expected:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
            raise ValueError('Changed effect rule anchor '+hex(address)+': '+row['operands'])
        anchors.append(row)
    for address,name in [(0x145976250,'BuffType'),(0x145976596,'OverlayType')]:
        offset=image.offset(rows[address]['rip_references'][0]-image.pe.base);literal=name.encode()+b'\0'
        if data[offset:offset+len(literal)]!=literal:
            raise ValueError('Changed effect rule field')
    buff=extractor.extract_dictionary(list(rows.values()),data,image,0x1457f5f50,0x1457f5fc0,0x17,0x47)
    overlay=extractor.extract_dictionary(list(rows.values()),data,image,0x1457ad73f,0x1457ad7f7,-9,0x47)
    if {k:v['name']for k,v in buff.items()}!={'0':'Deadly','1':'DeadlyBuff','2':'Adrenaline'}:
        raise ValueError('Changed BuffType dictionary')
    if {k:v['name']for k,v in overlay.items()}!={'0':'Allow','1':'Deny','2':'Accum','3':'ForceAllow','4':'PrioritySuccession'}:
        raise ValueError('Changed OverlayType dictionary')
    a=0x1457f7ac0;offset=image.offset(a-image.pe.base);raw=data[offset:offset+5]
    if raw[0]!=0xe9 or a+5+int.from_bytes(raw[1:],'little',signed=True)!=0x1457ad640:
        raise ValueError('Changed OverlayType thunk')
    result=dict(source=source['source'],sha256=source['sha256'],buff_types=buff,overlay_types=overlay,
        unknown_buff_value=3,unknown_overlay_value=5,anchors=anchors,fragments=fragments,
        parser_thunk=dict(address=a,file_offset=offset,bytes=raw.hex()),
        relations=['Effect.BuffType → record+0x55 → parser 0x1457f5e50',
            'Effect.OverlayType → record+0x88 → parser thunk 0x1457f7ac0 → 0x1457ad640'],
        limitations=['Parser names verified; stacking, refresh timing, priority and expiration runtime rules remain unknown.'])
    path=native.ROOT/'code-clues/effect-rule-semantics.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(buff_types=len(buff),overlay_types=len(overlay),anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':
    main()
