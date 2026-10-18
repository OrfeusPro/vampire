"""Verify rate post-load callbacks by following record creation and vtable writes."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('record_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)


def validate_slot(value,expected,code):
    if value!=expected:raise ValueError('Rate callback target changed')
    if code!=bytes.fromhex('c20000'):raise ValueError('Rate callback is no longer an empty ret0')


def main():
    root=native.ROOT
    prerequisite=json.loads((root/'code-clues/loot-rate-evidence.json').read_text('utf-8'))
    data=Path(prerequisite['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=prerequisite['sha256']:raise ValueError('Changed EXE')
    if native.capstone.__version__!='5.0.6':raise ValueError('Use pinned Capstone5.0.6')
    image=native.Image(data)
    targets=[0x145b6b950,0x145b70fc0,0x145b59a70,0x145b59c80,0x145b58940,0x145b59750,
             0x145b57b10,0x145b57dc0,0x145b5ae40,0x145b5b8d0]
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in targets})
    rows={r['address']:r for f in fragments for r in f['instructions']}
    specifications=[
        ('NpcReward',0x1499b01c0,0x58,[
            (0x145b6bdbc,'call','0x145b59a70'),
            (0x145b59ae8,'call','0x145b58940'),
            (0x145b58a1d,'call','0x145b57b10'),
            (0x145b57b79,'lea','rcx, [rdx + 8]'),
            (0x145b57b88,'call','0x145b5ae40'),
            (0x145b5ae4a,'lea','rax, [rip + 0x3e5536f]'),
            (0x145b5ae54,'mov','qword ptr [rcx], rax'),
            (0x145b5aea7,'mov','eax, dword ptr [rbx + 0x48]'),
            (0x145b5aeaa,'mov','dword ptr [rdi + 0x48], eax'),
            (0x145b6c0e8,'mov','dword ptr [rsi + 0x48], eax'),
            (0x145b6c0eb,'mov','rcx, rsi'),
            (0x145b6c0ee,'mov','rax, qword ptr [rsi]'),
            (0x145b6c0f1,'call','qword ptr [rax + 0x58]')]),
        ('Reward',0x1499aed48,0x70,[
            (0x145b7154c,'call','0x145b59c80'),
            (0x145b59cfa,'call','0x145b59750'),
            (0x145b5982a,'call','0x145b57dc0'),
            (0x145b57e44,'lea','rcx, [rdx + 8]'),
            (0x145b57e57,'call','0x145b5b8d0'),
            (0x145b5b8da,'lea','rax, [rip + 0x3e53467]'),
            (0x145b5b8e4,'mov','qword ptr [rcx], rax'),
            (0x145b71806,'mov','dword ptr [rbx + 0x50], eax'),
            (0x145b71809,'mov','rcx, rbx'),
            (0x145b7180c,'mov','rax, qword ptr [rbx]'),
            (0x145b7180f,'call','qword ptr [rax + 0x70]')])]
    links=[]
    for name,vtable,slot,checks in specifications:
        anchors=[]
        for address,mnemonic,operands in checks:
            row=rows[address]
            if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed record path at '+hex(address))
            anchors.append(row)
        vtable_anchor=next(r for r in anchors if r['rip_references'] and r['rip_references'][0]==vtable)
        offset=image.offset(vtable+slot-image.pe.base)
        target=struct.unpack_from('<Q',data,offset)[0]
        code_offset=image.offset(target-image.pe.base);code=data[code_offset:code_offset+3]
        validate_slot(target,0x1413fe190,code)
        links.append(dict(table=name,anchors=anchors,vtable_address=vtable,vtable_anchor=vtable_anchor,
            callback_slot=slot,slot_file_offset=offset,slot_bytes=data[offset:offset+8].hex(),
            callback_address=target,callback_file_offset=code_offset,callback_bytes=code.hex(),
            observation='Rate load callback resolves to ret 0; no normalization in this callback.',
            object_suboffset_in_map_record=8))
    report=dict(source=prerequisite['source'],sha256=prerequisite['sha256'],links=links,fragments=fragments,
        chance_percent_verified=False,limitations=[
            'Only the two reviewed rate post-load callbacks and record creation paths are resolved.',
            'Empty callbacks do not imply absence of downstream rate consumers or server-side rolls.',
            'No runtime vtable mutation, Android equivalent, probability denominator or RNG identified.'])
    path=root/'code-clues/loot-record-links.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(links=len(links),anchors=sum(len(r['anchors']) for r in links),fragments=len(fragments),rate_callbacks='ret0',chance_percent_verified=False)))
    return report


if __name__=='__main__':main()
