"""Current native ID2 registration pair -> reader -> handler -> clock setter."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
ROOT, REGISTER, INSERT = 0x1467b5e00, 0x1467ccbc0, 0x1467b5a90
CTOR, TIME_CTOR, TIME_BASE = 0x14574ab20, 0x1457a47d0, 0x1457fedc0
READER, TIME_READ, TIME_READ_CORE, ID = 0x145750670, 0x144aae4e0, 0x1457fefb0, 0x14148aa20
HANDLER, SETTER, CLOCK_GET = 0x1467ace30, 0x1445d8a30, 0x1445ce230
PACKET_TABLE, HANDLER_TABLE = 0x149942ce0, 0x149dc7ab0
STOP_PAIR=0x1467b5e74


def main():
    spec=importlib.util.spec_from_file_location('lobby_clock_archive',HERE/'replay-release-archive-input.py')
    archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    addresses=(ROOT,REGISTER,CTOR,TIME_CTOR,READER,TIME_READ_CORE,0x144aad7c0,HANDLER,0x145d5e440)
    hooks={a:None for a in (0x1467b5d90,0x14690a090,INSERT,STOP_PAIR,0x1487eac40,
                           0x144ab04b0,0x145d4e7b0,0x1445cda00)}
    h=archive.make_harness(extra_addresses=addresses,extra_leaves=(TIME_BASE,TIME_READ,ID,CLOCK_GET),fixtures=hooks)
    evidence=h.comparison/'bootstrap/run-f534419cd27a/export/bootstrap.json'
    clock_evidence=h.comparison/'bootstrap/run-1ffad6459713/export/bootstrap.json'
    if h.audit.sha256(evidence)!='a2c3a7104e1218d61b31e638daea50a4e67dc54ab6142abf967df52e369885dd' or h.audit.sha256(clock_evidence)!='5da074763b362b2d05d3adfac4ec200ee9f221e34c469fbd2fb1fec9878a7bbb':
        raise ValueError('Lobby/clock Ghidra evidence changed')
    functions={int(f['address'],16):f for f in json.loads(clock_evidence.read_text('utf-8'))['functions']}
    uc,x=h.uc,h.x
    def source(address,count):
        off=h.image.offset(address-h.image.pe.base);return h.raw[off:off+count]
    decoder=h.native.capstone.Cs(h.native.capstone.CS_ARCH_X86,h.native.capstone.CS_MODE_64);decoder.detail=True
    rows=functions[SETTER]['instructions'];end=SETTER;pages=set()
    for row in rows:
        address,data=int(row['address'],16),bytes.fromhex(row['bytes'])
        if address!=end or source(address,len(data))!=data:raise ValueError('Setter instruction source differs')
        for instruction in decoder.disasm(data,address):
            for op in instruction.operands:
                if op.type==h.native.X86_OP_MEM and op.mem.base==h.native.X86_REG_RIP:
                    pages.add((address+len(data)+op.mem.disp)&~4095)
        end+=len(data)
    h.ranges.append((SETTER,end));pages.update(range(SETTER&~4095,(end+4095)&~4095,4096))
    pages.update(a&~4095 for a in (PACKET_TABLE,HANDLER_TABLE,0x14b567a40))
    for page in sorted(pages):
        if not any(lo<=page<=hi for lo,hi,permissions in uc.mem_regions()):
            uc.mem_map(page,4096)
            try:uc.mem_write(page,source(page,4096))
            except ValueError:pass
    if int.from_bytes(source(PACKET_TABLE+0x28,8),'little')!=ID or int.from_bytes(source(HANDLER_TABLE+0x10,8),'little')!=HANDLER:
        raise ValueError('Current packet/handler table target differs')
    name=b'PktLobbyVersionResult\0'
    if source(0x149942d30,len(name))!=name:raise ValueError('Current packet name differs')
    tail=source(0x1467ace8c,5)
    if tail[0]!=0xe9 or 0x1467ace91+struct.unpack('<i',tail[1:])[0]!=0x145d5e440:
        raise ValueError('Current handler tail target differs')
    dispatcher,clock,manager,wrapper=[h.scratch+n for n in (0x10000,0x11000,0x12000,0x13000)]
    allocation=[h.scratch+0x18000];bindings=[];events=[]
    def fixture(machine):
        at=machine.reg_read(x.UC_X86_REG_RIP)
        a,b,c=[machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8)]
        result=0
        if at==0x14690a090:
            if a not in (8,64):raise ValueError('Unexpected first-pair allocation')
            result=allocation[0];allocation[0]+=(a+31)&~31
            machine.mem_write(result,b'\0'*a)
        elif at==INSERT:
            if a!=dispatcher+8:raise ValueError('Registration map fixture receiver differs')
            key,packet,handler=struct.unpack('<H6xQQ',bytes(machine.mem_read(c,24)))
            bindings.append((key,packet,handler))
            machine.mem_write(b+8,b'\x01')  # Explicit insertion-success output; skip duplicate logging.
        elif at==STOP_PAIR:
            machine.reg_write(x.UC_X86_REG_RIP,h.stop);machine.emu_stop();return
        elif at==0x1487eac40:
            if a!=int.from_bytes(machine.mem_read(0x14b274780,8),'little'):raise ValueError('Cookie differs')
        elif at==0x144ab04b0:result=wrapper
        elif at==0x145d4e7b0:result=manager
        elif at==0x1445cda00:
            if a!=clock:raise ValueError('Clock comparison receiver differs')
            result=1000
        elif at!=0x1467b5d90:raise ValueError('Unreviewed lobby fixture')
        events.append(hex(at))
        sp=machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,result)
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    for address in hooks:hooks[address]=fixture
    uc.mem_write(dispatcher,b'\0'*4096);h.call(ROOT,dispatcher,budget=32768)
    if len(bindings)!=1 or bindings[0][0]!=2:raise ValueError('Native registration key differs')
    key,packet,handler=bindings[0]
    if int.from_bytes(uc.mem_read(packet,8),'little')!=PACKET_TABLE or int.from_bytes(uc.mem_read(handler,8),'little')!=HANDLER_TABLE or h.call(ID,packet)!=2:
        raise ValueError('Actual constructor/ID/handler pair differs')
    ctor_bytes=bytes(uc.mem_read(packet,64)).hex()
    cases=[]
    for offset in (-180,0,540):
        for flag in (0,1,255):
            for first in (0,2000):
                server=1792600142863
                body=struct.pack('<IBQQH',0,flag,first,server,offset&65535)
                h.call(CTOR,packet)
                h.call(h.ctor,h.obj)
                uc.mem_write(h.buffer,body)
                uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,len(body)))
                uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
                if h.call(READER,packet,h.obj)&255!=1:raise ValueError('Current whole lobby reader rejected')
                if int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer!=23:raise ValueError('Reader cursor differs')
                uc.mem_write(clock,b'\0'*80);uc.mem_write(manager,b'\0'*0x400)
                uc.mem_write(wrapper+0x28,struct.pack('<I',2))  # UI branch bypass, not a real peer state claim.
                uc.mem_write(0x14b567a40,struct.pack('<Q',clock))
                try:
                    h.call(HANDLER,handler,dispatcher,packet,budget=32768)
                except Exception as error:
                    raise RuntimeError('Lobby handler failed at '+hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
                addend=struct.unpack('<q',bytes(uc.mem_read(0x14b567700,8)))[0]
                sample,baseline=struct.unpack('<qq',bytes(uc.mem_read(clock+32,16)))
                if (addend,sample,baseline)!=(offset*600000000,server*10000,server*10000):raise ValueError('Handler to clock source fields differ')
                if int.from_bytes(uc.mem_read(manager+0x340,8),'little')!=first or int.from_bytes(uc.mem_read(manager+0x34c,1),'little')!=int(first>1000):raise ValueError('First/second TimeBase fields mixed')
                if bytes(uc.mem_read(0x14b595039,1))!=bytes((bool(flag),)):raise ValueError('Bool normalization differs')
                cases.append(dict(offset_minutes=offset,raw_flag=flag,first_bits=first,server_sample=server,offset_ticks=addend,server_ticks=sample))
    truncated=[]
    for size in range(24):
        h.call(CTOR,packet);h.call(h.ctor,h.obj)
        uc.mem_write(h.buffer,body);uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,size));uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
        accepted=h.call(READER,packet,h.obj)&255
        if accepted!=int(size==23):raise ValueError('Native lobby reader prefix gate differs')
        truncated.append(dict(size=size,accepted=bool(accepted)))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence_sha256=h.audit.sha256(evidence),clock_evidence_sha256=h.audit.sha256(clock_evidence),
        registration_key=key,packet_table=hex(PACKET_TABLE),handler_table=hex(HANDLER_TABLE),packet_constructor=hex(CTOR),packet_name='PktLobbyVersionResult',
        constructor_bytes=ctor_bytes,registry_pair_execution='root entry through first registration return',cases=cases,prefix_cases=truncated,
        handler_tail_target='0x145d5e440',handler_tail_bytes=tail.hex(),
        fragments=h.fragments,leaves=h.leaves,setter_instructions=rows,network_used=False,
        limits=['Actual first registration pair, ID getter, constructors, whole reader, handler, getter and clock setter execute.',
            'Allocator, map insertion, dispatcher base initialize, maintenance/UI managers and cookie backend are fixtures.',
            'Root stops after the first pair; actual generic dispatcher, map implementation and TCP routing are not executed.',
            'Only successful result-code-zero bodies are routed; protocol failure handling and session success are not established.'])
    target=h.audit.save_snapshot(h.comparison/'lobby-clock-replay',report)
    print(json.dumps(dict(report=str(target),sha256=h.audit.sha256(target),cases=len(cases),prefix_cases=len(truncated))))


if __name__=='__main__':main()
