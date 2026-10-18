"""Verify Skill / SkillOperation target dictionaries from client native code."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name,HERE/file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def main():
    native = module('target_native','build-native-entry-code.py')
    semantics = module('target_dictionary','build-skill-semantics.py')
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed executable or decoder')
    image = native.Image(data)
    roots = {image.roots[image.containing(a)] for a in [0x1457e8300,0x1457e7e70,
        0x145bc6470,0x145bd69f0,0x145bc97d0,0x145bd86f0]}
    fragments = native.decode_ranges(image,roots)
    rows = {r['address']:r for f in fragments for r in f['instructions']}
    targets = semantics.extract_dictionary(list(rows.values()),data,image,0x1457e8408,0x1457e868b,0x30,0x120)
    conditions = semantics.extract_dictionary(list(rows.values()),data,image,0x1457e7f78,0x1457e81fb,0x30,0x120)
    if len(targets)!=15 or targets['4']['name']!='Enemy' or targets['1']['name']!='Self' or '15' in targets:
        raise ValueError('Changed target dictionary')
    if len(conditions)!=15 or conditions['0']['name']!='LowHpRate' or '17' in conditions:
        raise ValueError('Changed target condition dictionary')
    expected = [
        (0x145bd7aa7,'call','0x1457fef90'),(0x145bd7aac,'mov','byte ptr [rbx + 0x109], al'),
        (0x145bc9d9d,'mov','byte ptr [rbx + 0x18], al'),(0x145bc9dbc,'mov','byte ptr [rbx + 0x19], al'),
        (0x145bd88e2,'call','0x1457fef90'),(0x145bd88e7,'mov','byte ptr [rbx + 0x18], al'),
        (0x145bd895c,'call','0x1457fef80'),(0x145bd8961,'mov','byte ptr [rbx + 0x19], al'),
        (0x1457e83ac,'mov','al, 0xf'),(0x1457e7f1c,'mov','al, 0x11'),
        (0x1457e8692,'lea','rax, [rbp + 0x30]'),(0x1457e869b,'lea','rax, [rbp + 0x120]'),
        (0x1457e86a7,'call','0x14450dc60'),
        (0x1457e8202,'lea','rax, [rbp + 0x30]'),(0x1457e820b,'lea','rax, [rbp + 0x120]'),
        (0x1457e8217,'call','0x14450dc60')]
    anchors = []
    for address,mnemonic,operands in expected:
        row = rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
            raise ValueError('Changed target anchor '+hex(address))
        anchors.append(row)
    for address,name in [(0x145bd7a61,'TargetType'),(0x145bc998f,'TargetType'),
        (0x145bd889b,'TargetType'),(0x145bc99a4,'TargetConditionType'),(0x145bd8915,'TargetConditionType')]:
        row=rows[address]; offset=image.offset(row['rip_references'][0]-image.pe.base)
        literal=name.encode()+b'\0'
        if row['mnemonic']!='lea' or data[offset:offset+len(literal)]!=literal:
            raise ValueError('Changed target field')
        anchors.append(row)
    thunks=[]
    for address,target in [(0x1457fef90,0x1457e8300),(0x1457fef80,0x1457e7e70)]:
        offset=image.offset(address-image.pe.base);raw=data[offset:offset+5]
        if raw[0]!=0xe9 or address+5+int.from_bytes(raw[1:],'little',signed=True)!=target:
            raise ValueError('Changed target parser thunk')
        thunks.append(dict(address=address,file_offset=offset,bytes=raw.hex(),target=target))
    result=dict(source=source['source'],sha256=source['sha256'],targets=targets,target_conditions=conditions,
        unknown_target_value=15,unknown_target_condition_value=17,anchors=anchors,parser_thunks=thunks,fragments=fragments,
        relations=['Skill.TargetType → ModifyValue record+0x109 → 0x1457fef90 → target dictionary',
            'SkillOperation.TargetType → record+0x18 → 0x1457fef90 → same target dictionary',
            'SkillOperation.TargetConditionType → record+0x19 → 0x1457fef80 → target condition dictionary'],
        limitations=['Names and field joins verified; runtime target selection predicates remain unverified.',
            'Fallback values do not establish unconditional or unrestricted targeting.'])
    path=native.ROOT/'code-clues/skill-target-semantics.json'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(targets=len(targets),target_conditions=len(conditions),anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':
    main()
