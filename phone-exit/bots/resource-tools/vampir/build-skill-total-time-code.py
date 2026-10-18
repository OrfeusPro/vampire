"""Freeze the verified TotalTime storage boundary without guessing runtime units."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    spec = importlib.util.spec_from_file_location('total_native', HERE/'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
    source = json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256'] or native.capstone.__version__ != '5.0.6':
        raise ValueError('Changed native source/decoder')
    image = native.Image(data)
    roots = {image.roots[image.containing(a)] for a in [0x145bc6470,0x145baf110,0x140d550ae]}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']:r for f in fragments for r in f['instructions']}
    expected = [(0x145bc75a9,'mov','dword ptr [rbx + 0xc8], eax'),
        (0x145baf147,'lea','rsi, [rip + 0x3e0a2f2]'),
        (0x145baf178,'mov','qword ptr [rdi + 8], rsi'),
        (0x140d550ae,'call','0x1438cbd10'),(0x140d550b3,'cmp','eax, 1')]
    anchors = []
    for address,mnemonic,operands in expected:
        row=rows[address]
        if (row['mnemonic'],row['operands']) != (mnemonic,operands):
            raise ValueError('Changed TotalTime anchor '+hex(address))
        anchors.append(row)
    byte_ranges=[]
    for address,raw in [(0x1438cbd10,bytes.fromhex('8b81c8000000c3')),
                        (0x1499b9440+0xb0,struct.pack('<Q',0x1438cbd10))]:
        offset=image.offset(address-image.pe.base)
        if data[offset:offset+len(raw)] != raw:
            raise ValueError('Changed TotalTime getter/vtable')
        byte_ranges.append(dict(address=address,file_offset=offset,bytes=raw.hex()))
    semantics_path=native.ROOT/'code-clues/skill-semantics.json'
    semantics=json.loads(semantics_path.read_text('utf-8'))
    if semantics['sha256'] != source['sha256'] or semantics['timing']['TotalTime']['record_offset'] != 0xc8:
        raise ValueError('Changed storage evidence')
    report=dict(source=source['source'],sha256=source['sha256'],fragments=fragments,
        anchors=anchors,byte_ranges=byte_ranges,
        dependency=dict(file='code-clues/skill-semantics.json',sha256=hashlib.sha256(semantics_path.read_bytes()).hexdigest()),
        verified=dict(field='Skill.TotalTime',record_offset=0xc8,vtable=0x1499b9440,getter_slot=0xb0),
        unit=None,runtime_consumer_verified=False,execution_duration_verified=False,
        rejected=[dict(address=0x14568ea04,reason='Virtual slot0xb0 on object from0x1456048e0; not proven Skill.'),
            dict(address=0x140d550ae,reason='Direct call to generic getter only compares with1. Receiver Skill type and time unit not established.')],
        limitations=['Storage/getter proof is not proof of execution duration, animation length, cast time or unit.',
            'Do not reuse cooldown milliseconds proof for this field.',
            'Raw FF90..97/B0 virtual-call scan is discovery only; other dispatch forms and inline field reads remain possible.'])
    path=native.ROOT/'code-clues/skill-total-time-code.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),fragments=len(fragments),unit=None,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
