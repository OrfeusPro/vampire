"""Verify ItemLimit and ItemUseLimit parser names; do not evaluate runtime gates."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def main():
    spec=importlib.util.spec_from_file_location('limit_native',HERE/'build-native-entry-code.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    source=json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256'] or native.capstone.__version__!='5.0.6':
        raise ValueError('Changed client or decoder')
    image=native.Image(data)
    roots={image.roots[image.containing(a)] for a in [0x1457f9aa0,0x1457fd640,0x145a909d0,
        0x145aa3a90,0x145a92420,0x145aa43d0]}
    fragments=native.decode_ranges(image,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    expected=[
        (0x145a90e48,'mov','byte ptr [rbx + 0x10], al'),
        (0x145aa3c04,'call','0x1457f9aa0'),(0x145aa3c09,'mov','byte ptr [rdi + 0x10], al'),
        (0x145a92a56,'mov','dword ptr [r15 + 0x20], eax'),
        (0x145aa45cf,'call','0x1457fd640'),(0x145aa45d4,'mov','dword ptr [rsi + 0x20], eax'),
        (0x1457f9b47,'mov','al, 3'),(0x1457fd6df,'mov','eax, 2'),
        (0x1457f9bab,'call','0x141420f70'),(0x1457f9bcf,'call','0x141420f70'),(0x1457f9bf3,'call','0x141420f70'),
        (0x1457f9bb4,'mov','byte ptr [rbp - 0x39], 2'),
        (0x1457f9bb8,'mov','qword ptr [rbp + 0x17], rax'),
        (0x1457f9bc3,'lea','rax, [rbp - 0x39]'),(0x1457f9bcb,'mov','qword ptr [rbp + 0x1f], rax'),
        (0x1457f9bd8,'mov','byte ptr [rbp - 0x38], 0'),(0x1457f9bdc,'mov','qword ptr [rbp + 0x27], rax'),
        (0x1457f9be7,'lea','rax, [rbp - 0x38]'),(0x1457f9bef,'mov','qword ptr [rbp + 0x2f], rax'),
        (0x1457f9bfc,'mov','byte ptr [rbp - 0x37], 1'),(0x1457f9c00,'mov','qword ptr [rbp + 0x37], rax'),
        (0x1457f9c08,'lea','rax, [rbp - 0x37]'),(0x1457f9c0c,'mov','qword ptr [rbp + 0x3f], rax'),
        (0x1457f9c17,'lea','rax, [rbp + 0x17]'),(0x1457f9c1f,'lea','rax, [rbp + 0x47]'),
        (0x1457f9c27,'call','0x14450dc60'),
        (0x1457fd65c,'xor','edi, edi'),(0x1457fd72c,'call','0x141420f70'),(0x1457fd75f,'call','0x141420f70'),
        (0x1457fd736,'mov','dword ptr [rsp + 0x80], 1'),(0x1457fd741,'mov','qword ptr [rsp + 0x50], rax'),
        (0x1457fd74d,'lea','rax, [rsp + 0x80]'),(0x1457fd75a,'mov','qword ptr [rsp + 0x58], rax'),
        (0x1457fd769,'mov','dword ptr [rsp + 0x88], edi'),(0x1457fd770,'mov','qword ptr [rsp + 0x60], rax'),
        (0x1457fd77a,'lea','rax, [rsp + 0x88]'),(0x1457fd782,'mov','qword ptr [rsp + 0x68], rax'),
        (0x1457fd78e,'lea','rax, [rsp + 0x50]'),(0x1457fd798,'lea','rax, [rsp + 0x70]'),
        (0x1457fd7a2,'call','0x14450d970')]
    anchors=[]
    for address,mnemonic,operands in expected:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
            raise ValueError('Changed limit anchor '+hex(address))
        anchors.append(row)
    dictionaries={}
    for key,entries in [('item_limits',[(0,'DisableEnchant',0x1457f9bbc),(1,'DisableRefinement',0x1457f9be0),(2,'DisableDisassembly',0x1457f9ba0)]),
        ('room_limits',[(0,'UseOnly',0x1457fd746),(1,'UseExcept',0x1457fd720)])]:
        dictionaries[key]={}
        for value,name,address in entries:
            row=rows[address];offset=image.offset(row['rip_references'][0]-image.pe.base)
            literal=name.encode()+b'\0'
            if row['mnemonic']!='lea' or data[offset:offset+len(literal)]!=literal:
                raise ValueError('Changed limit name')
            anchors.append(row);dictionaries[key][str(value)]=dict(value=value,name=name,name_offset=offset)
    for address,name in [(0x145aa3bbd,'LimitType'),(0x145aa4588,'RoomLimitType')]:
        row=rows[address];offset=image.offset(row['rip_references'][0]-image.pe.base);literal=name.encode()+b'\0'
        if data[offset:offset+len(literal)]!=literal:
            raise ValueError('Changed field literal')
        anchors.append(row)
    result=dict(source=source['source'],sha256=source['sha256'],**dictionaries,anchors=anchors,fragments=fragments,
        unknown_item_limit_value=3,unknown_room_limit_value=2,
        limitations=['Parser names and field stores verified; runtime enforcement and World/Room list combination remain unknown.'])
    path=native.ROOT/'code-clues/item-limit-semantics.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':
    main()
