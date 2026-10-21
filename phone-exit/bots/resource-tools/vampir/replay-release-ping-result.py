"""Current ID17 constructor/reader/handler/receiver; explicit engine fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def run():
    spec=importlib.util.spec_from_file_location('ping17_archive',HERE/'replay-release-archive-input.py')
    archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    fixtures={a:None for a in (0x144ab1f90,0x145596590,0x144ab2440)}
    h=archive.make_harness(extra_addresses=(0x1456dc6e0,0x14679da80,0x1467d09b0),
        extra_leaves=(0x1456d8b60,0x1456e5f70,0x1445ce230),fixtures=fixtures)
    evidence={'details/run-f9f61ab4bfa9/details.json':'b2619413e0f269662614496342b1cb3fe6e85bb8350f43a937b16e576cc81177',
        'details/run-b3ab85ff66e0/details.json':'94c22d53d4a2c1063e6f0d0879884c509bffbdb2da709f21964c09e456d052d3'}
    for path,sha in evidence.items():
        if h.audit.sha256(h.comparison/path)!=sha:raise ValueError('ID17 Ghidra evidence changed')
    uc,x=h.uc,h.x
    packet,wrapper,clock,config=[h.scratch+n for n in (0x10000,0x11000,0x12000,0x13000)]
    global_pointer=0x14b567a40
    for address in (*fixtures,global_pointer):
        page=address&~4095
        if not any(a<=page<=b for a,b,_ in uc.mem_regions()):
            uc.mem_map(page,4096)
            try:off=h.image.offset(page-h.image.pe.base)
            except ValueError:continue  # Zero-initialized global page, supplied below.
            uc.mem_write(page,h.raw[off:off+4096])
    uc.mem_write(global_pointer,struct.pack('<Q',clock))
    off=h.image.offset(0x148afeab0-h.image.pe.base)
    if h.raw[off:off+8].hex()!='2d431cebe2361abf':raise ValueError('Receive clock multiplier changed')
    for table,slot,target in ((0x1499289b0,0x20,0x1456dc6e0),
            (0x1499289b0,0x28,0x1456e5f70),(0x149dc8638,0x10,0x14679da80)):
        off=h.image.offset(table-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,off+slot)[0]!=target:raise ValueError('ID17 table binding changed')
    events=[]
    def fixture(machine):
        address=machine.reg_read(x.UC_X86_REG_RIP)
        result=wrapper if address==0x144ab1f90 else config if address==0x145596590 else 0
        if address==0x144ab2440 and machine.reg_read(x.UC_X86_REG_RCX)!=wrapper:
            raise ValueError('Recovery wrapper differs')
        events.append(hex(address))
        sp=machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,result)
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    for address in fixtures:fixtures[address]=fixture
    def read(body):
        uc.mem_write(packet,bytes(32));h.call(0x1456d8b60,packet)
        if int.from_bytes(uc.mem_read(packet,8),'little')!=0x1499289b0:raise ValueError('Constructor table differs')
        if h.call(0x1456e5f70,packet)!=17:raise ValueError('Getter differs')
        uc.mem_write(h.buffer,bytes(32))
        if body:uc.mem_write(h.buffer,body)
        h.call(h.ctor,h.obj)
        uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,len(body)))
        uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
        accepted=h.call(0x1456dc6e0,packet,h.obj)&255
        consumed=int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer
        return accepted,consumed
    cases=[]
    for code in (0,16,0xffffffff):
        for value in (0,2**64-1):
            for flags in (0,512,1024):
                for outstanding in (0,6):
                    body=struct.pack('<IQ',code,value)
                    if read(body)!=(1,12):raise ValueError('Reader did not consume ID17')
                    if struct.unpack('<I',uc.mem_read(packet+0x10,4))[0]!=code or struct.unpack('<Q',uc.mem_read(packet+0x18,8))[0]!=value:
                        raise ValueError('Reader fields differ')
                    uc.mem_write(wrapper,bytes(0x200))
                    uc.mem_write(wrapper+0x16c,struct.pack('<I',outstanding))
                    uc.mem_write(wrapper+0x178,struct.pack('<q',10000))
                    uc.mem_write(clock+0x10,struct.pack('<q',100250000))
                    uc.mem_write(config+8,struct.pack('<I',flags));events.clear()
                    h.call(0x14679da80,0,0,packet,budget=1000)
                    index,counter=struct.unpack('<II',uc.mem_read(wrapper+0x168,8))
                    elapsed=struct.unpack('<q',uc.mem_read(wrapper+0x178,8))[0]
                    average=struct.unpack('<f',uc.mem_read(wrapper+0x170,4))[0]
                    recovery=events.count(hex(0x144ab2440))
                    if (counter,index,elapsed,average,recovery)!=(0,0,25,25.0,int(bool(flags&1024))):
                        raise ValueError('Ping receiver state differs')
                    cases.append(dict(result_bits=code,value_bits=value,flags=flags,
                        outstanding_before=outstanding,outstanding_after=counter,tracking_index_after=index,
                        elapsed=elapsed,recovery_calls=recovery))
    short=[]
    for size in range(12):
        accepted,consumed=read(bytes(12)[:size])
        if accepted or consumed>size:raise ValueError('Short ID17 accepted or overconsumed')
        short.append(dict(size=size,consumed=consumed))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence=evidence,
        fragments=h.fragments,leaves=h.leaves,cases=cases,short=short,native_execution=True,network_used=False,
        limits=['Whole current packet constructor/reader/handler/receiver execute.',
            'Global context and settings getters, clock cache contents and recovery call are bounded fixtures.',
            'Tracking index zero and one timing slot are tested; native recovery internals and clock resync are not executed.',
            'No real network, scheduling, reconnect or long-lived session claim.'])
    path=h.audit.save_snapshot(h.comparison/'ping-result-replay',report)
    return path,h.audit.sha256(path),len(cases)


if __name__=='__main__':
    path,sha,count=run();print(json.dumps(dict(report=str(path),sha256=sha,cases=count)))
