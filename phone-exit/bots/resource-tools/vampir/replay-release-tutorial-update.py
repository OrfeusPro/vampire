"""Whole current tutorial notify reader with bounded fresh array storage. No game IO."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent


def run():
    spec=importlib.util.spec_from_file_location('tutorial_storage',HERE/'replay-release-fstring-input.py')
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    h=base.make_harness(extra_addresses=(0x1456b83a0,0x14584d070,0x1457ff1e0,0x1457ff270,
        0x1457ff150,0x144aad880),extra_leaves=(0x144aae4e0,0x1457fee70,0x145857190))
    evidence={
        'details/run-df3c5d97b2b8/details.json':'658e92284a85cbcd397427d8008910a209b148eb6c03151b6da3aa973b053f9b',
        'details/run-653eecec5371/details.json':'af30655ba1e062787af2fb28916d4719eedab9a421b2207dd6355b9bb1766597',
        'details/run-af62c6ff1a30/details.json':'82165d2e75185cce5c85e21655dc210448c02c4b9653579feb31f6d649535fd3',
        'details/run-74973e2905f8/details.json':'cde28a9f0e3e863d7183589da6c7418293cea47f3e4e0118d291690671991b1d'}
    for path,sha in evidence.items():
        if h.audit.sha256(h.comparison/path)!=sha:raise ValueError('Tutorial evidence changed')
    uc,x=h.uc,h.x
    for table,slot,target in ((0x14996b9f8,0x20,0x1456b83a0),(0x14996b9f8,0x28,0x145857190),
            (0x14992b000,0x20,0x1457ff1e0),(0x14992afc0,0x20,0x1457ff150),
            (0x149961ef0,0x10,0x1457ff270)):
        off=h.image.offset(table-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,off+slot)[0]!=target:raise ValueError('Tutorial binding changed')
        page=table&~4095
        if not any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()):
            uc.mem_map(page,4096);off=h.image.offset(page-h.image.pe.base);uc.mem_write(page,h.raw[off:off+4096])
    def cleanup(machine):
        if machine.reg_read(x.UC_X86_REG_RDX)&0xffffffff:raise ValueError('Fresh tutorial cleanup only')
        h.finish()
    def resize(machine):
        container=machine.reg_read(x.UC_X86_REG_RDX);count=machine.reg_read(x.UC_X86_REG_R8)&65535
        if count>64 or bytes(machine.mem_read(container,16))!=bytes(16):
            raise ValueError('Fresh bounded tutorial array required')
        pointer=h.allocate(count*0x18) if count else 0
        machine.mem_write(container,struct.pack('<QII',pointer,0,count));h.finish()
    for address,fn in ((0x1456b6c60,cleanup),(0x1456bb670,resize)):
        page=address&~4095
        if not any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()):
            uc.mem_map(page,4096);off=h.image.offset(page-h.image.pe.base);uc.mem_write(page,h.raw[off:off+4096])
        h.fixtures[address]=fn
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.tutorial_update import decode_tutorial_update
    packet=h.scratch+0x10000
    def read(body):
        h.string_heap[0]=h.scratch+0x20000
        uc.mem_write(packet,bytes(64));h.call(0x14584d070,packet)
        if int.from_bytes(uc.mem_read(packet,8),'little')!=0x14996b9f8 or h.call(0x145857190,packet)!=9905:
            raise ValueError('Tutorial constructor / ID differs')
        uc.mem_write(h.buffer,bytes(1024))
        if body:uc.mem_write(h.buffer,body)
        h.call(h.ctor,h.obj)
        uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,len(body)))
        uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
        accepted=h.call(0x1456b83a0,packet,h.obj,budget=200000)&255
        consumed=int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer
        return accepted,consumed
    cases=[]
    for flag in (0,1,255):
        for count in (0,1,2,8):
            for state in (0,1,2,3,4,255):
                body=struct.pack('<BH',flag,count)+b''.join(struct.pack('<IIIB',1001+i,0xffffffff-i,1001002+i,state) for i in range(count))
                expected=decode_tutorial_update(body,source_sha256=h.sha,max_records=64,max_payload_size=1024)
                if read(body)!=(1,len(body)):raise ValueError('Whole tutorial reader differs')
                if bool(uc.mem_read(packet+0x18,1)[0])!=expected.flag:raise ValueError('Tutorial flag differs')
                pointer,n,capacity=struct.unpack('<QII',uc.mem_read(packet+0x20,16))
                if n!=count or capacity!=count:raise ValueError('Tutorial count differs')
                for i,r in enumerate(expected.records):
                    if struct.unpack('<IIIB',uc.mem_read(pointer+i*0x18+8,13))!=(r.raw08,r.raw0c,r.raw10,r.state):
                        raise ValueError('Tutorial item differs')
                cases.append(dict(flag=flag,count=count,state=state,consumed=len(body)))
    short=[];body=struct.pack('<BH',1,2)+struct.pack('<IIIB',1001,2,1001002,1)*2
    for size in range(len(body)):
        accepted,consumed=read(body[:size])
        if accepted or consumed>size:raise ValueError('Short tutorial body accepted')
        short.append(dict(size=size,consumed=consumed))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence=evidence,
        fragments=h.fragments,leaves=h.leaves,cases=cases,short=short,native_execution=True,network_used=False,
        limits=['Whole current constructor, ID getter, notify/nested/item readers and array callback execute.',
            'Fresh array allocation and empty cleanup are fixtures; no reuse/growth or live state claim.',
            'Three scalar fields, state enum meaning, data flag and receiver semantics remain unknown.'])
    path=h.audit.save_snapshot(h.native.ROOT/'code-clues/release-tutorial-update-replay',report)
    return path,report


if __name__=='__main__':
    path,r=run();print(json.dumps(dict(report=str(path),cases=len(r['cases']),short=len(r['short']))))
