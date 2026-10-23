"""Current constructor plus Start to copy boundary, synthetic memory only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
EXPORTS={
    'run-0cdca2f717ea':'e5667cf351382f2ae5d7454010f6526cb24d0a11b49e86e87eb652c64babaf34',
    'run-d444f3f0abe1':'dc9da35e609aac46ae80416e86977844303165c937aece5e4a0c8ffeb3fb57c1',
}


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def replay(root=None):
    harness=load('base_harness',HERE/'native-request-harness-11316.py')
    h=harness.make_harness(EXPORTS,{0x1444c4210,0x144508210},root=root)
    receiver,manager,cls,settings=[h.scratch+n for n in (0x1000,0x2000,0x3000,0x4000)]
    heap,captured=[h.scratch+0x20000],[]
    h.uc.mem_write(receiver,struct.pack('<Q',manager))
    h.uc.mem_write(cls+0x110,struct.pack('<Q',settings))

    def text(address):
        pointer,count,capacity=struct.unpack('<QII',bytes(h.uc.mem_read(address,16)))
        if not 0<count<=capacity<=256 or not h.scratch<=pointer<=h.scratch+0x40000-count*2:
            raise ValueError('Base FString bounds')
        data=bytes(h.uc.mem_read(pointer,count*2))
        if data[-2:]!=bytes(2):raise ValueError('Base FString termination')
        return data[:-2].decode('utf-16le')

    def fixture(machine):
        at=machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b=[machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX)]
        if at==0x1444b1fe0:
            h.finish(cls)
        elif at==0x141441d60:
            if a!=manager+0x1e8 or b not in [manager+n for n in (0x150,0x160,0x170,0x180)]:
                raise ValueError('Base copy boundary arguments differ')
            captured.append(dict(destination_offset=hex(a-manager),source_offset=hex(b-manager),active_base=text(b)))
            machine.emu_stop()
        else:
            width=1 if at==0x141426950 else 2
            off=h.image.offset(b-h.image.pe.base);data=h.raw[off:off+512]
            end=next((i for i in range(0,512-width+1,width) if data[i:i+width]==bytes(width)),None)
            if end is None or not manager<=a<=manager+0x300-16:raise ValueError('Base literal bounds')
            payload=(data[:end].decode('ascii' if width==1 else 'utf-16le')+'\0').encode('utf-16le')
            pointer=heap[0];heap[0]+=(len(payload)+15)&~15
            if heap[0]>=h.scratch+0x2e000:raise ValueError('Base heap budget')
            machine.mem_write(pointer,payload);machine.mem_write(a,struct.pack('<QII',pointer,len(payload)//2,len(payload)//2))
            h.finish(a)

    for at in (0x141426950,0x141426b30,0x1444b1fe0,0x141441d60):h.add_fixture(at,fixture)
    h.uc.mem_write(manager-16,b'\xa5'*0x320)
    if h.call(0x1444c4210,manager)!=manager:raise ValueError('Base constructor return differs')
    cases=[]
    for zone in range(256):
        for flag in (0,1):
            h.uc.mem_write(0x14b5632e0,b'\0')
            h.uc.mem_write(settings+0x49,bytes([zone]));h.uc.mem_write(settings+0xc8,bytes([flag]))
            h.uc.reg_write(h.x.UC_X86_REG_RCX,receiver);h.uc.reg_write(h.x.UC_X86_REG_RSP,h.scratch+0x38000)
            before=len(captured);h.uc.emu_start(0x144508210,0,count=1000)
            if len(captured)!=before+1:raise ValueError('Base selection did not reach copy boundary')
            if bytes(h.uc.mem_read(0x14b1860f4,1))!=bytes([flag]):raise ValueError('Base flag differs')
            cases.append(dict(zone=zone,flag=flag,**captured[-1]))
    if any(bytes(h.uc.mem_read(a,16))!=b'\xa5'*16 for a in (manager-16,manager+0x300)):
        raise ValueError('Base manager canaries changed')
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,cases=cases,
        dependencies={n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in
            ('replay-gmc2-base-11316.py','native-request-harness-11316.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')},
        native_execution=True,network_ready=False,
        limits=['Constructor and Start execute to copy boundary; URL read from constructed source FString, destination copy not executed.',
                'FString storage, class/CDO getter, logging and final copy capture are fixtures; no active startup or network.'])


if __name__=='__main__':
    report=replay();native=load('base_root',HERE/'build-native-entry-code.py');audit=load('base_snapshot',HERE/'audit-client-release.py')
    path=audit.save_snapshot(native.ROOT/'code-clues/gmc2-base-11316',report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
