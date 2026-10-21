"""Current whole ID205 request/gate with explicit state, label and send fixtures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
REQUEST,GATE,CTOR=0x145db3fe0,0x14561cf70,0x14584db60
TABLE,WRITER,GETTER=0x14996d4b0,0x140bb4a10,0x145759160
FORMAT,SET_STATE,FREE=0x141433420,0x145619e00,0x141483160
SETTINGS,TRANSPORT,DTOR,LOAD=0x145979550,0x144ab1f90,0x1456b7990,0x145610de0
SEND,LABEL=0x3000e000,0x3000e100


def run():
    spec=importlib.util.spec_from_file_location('finish_request_archive',HERE/'replay-release-archive-input.py')
    archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    hooks={a:None for a in (FORMAT,SET_STATE,FREE,SETTINGS,TRANSPORT,DTOR,LOAD,SEND,LABEL)}
    h=archive.make_harness(extra_addresses=(REQUEST,GATE),
        extra_leaves=(CTOR,WRITER,GETTER,0x14584dcd0,0x145759190),fixtures=hooks)
    evidence={
        'details/run-412c8f62f9c7/details.json':'7737ae0bb8b3e80ab63899f5aadb41d896f4f940ccf367a8b4adc23504f47269',
        'details/run-a676cd5fc6e5/details.json':'03c109d07104b11e76b2328d3b7e811c5266fe5fc91a58afe79d02b8bd743f61'}
    for relative,expected in evidence.items():
        if h.audit.sha256(h.comparison/relative)!=expected:raise ValueError('Finish evidence changed')
    service_table=0x149a3faf0
    service_offset=h.image.offset(service_table-h.image.pe.base)
    if (struct.unpack_from('<Q',h.raw,service_offset+0x70)[0],
            struct.unpack_from('<Q',h.raw,service_offset+0xa8)[0])!=(REQUEST,0x145db1580):
        raise ValueError('Current service finish/load slots differ')
    off=h.image.offset(TABLE-h.image.pe.base)
    if (struct.unpack_from('<Q',h.raw,off+0x10)[0],struct.unpack_from('<Q',h.raw,off+0x28)[0])!=(WRITER,GETTER):
        raise ValueError('Finish packet slots differ')
    # Explicitly inspected leaves; do not infer empty body from a neighbour.
    leaves={r['address']:r['bytes'] for r in h.leaves}
    if leaves[hex(WRITER)]!='b001c3' or leaves[hex(GETTER)]!='b8cd000000c3':
        raise ValueError('Finish writer/getter instructions differ')
    uc,x=h.uc,h.x
    service,vtable,settings,transport,transport_table,packet=[h.scratch+n for n in (0x10000,0x11000,0x12000,0x13000,0x14000,0x15000)]
    h.call(CTOR,packet)
    if int.from_bytes(uc.mem_read(packet,8),'little')!=TABLE:raise ValueError('Finish constructor differs')
    if h.call(GETTER,packet)!=205 or h.call(WRITER,packet,h.obj)&255!=1:
        raise ValueError('Finish packet ID/writer differs')
    start_packet=packet+0x100
    h.call(0x14584dcd0,start_packet)
    if int.from_bytes(uc.mem_read(start_packet,8),'little')!=0x14996d6c8 or h.call(0x145759190,start_packet)!=204:
        raise ValueError('Start response constructor/getter differs')
    handler_offset=h.image.offset(0x149dc76d8-h.image.pe.base)
    if struct.unpack_from('<Q',h.raw,handler_offset+0x10)[0]!=0x1467cbe20:
        raise ValueError('Start handler slot differs')
    registration={0x1467b6ee3:'488d05ee076103',0x1467b6eea:'488907',
        0x1467b6f04:'e8c76d09ff',0x1467b6f0e:'4c8bc7',0x1467b6f11:'488bd0',
        0x1467b6f14:'488bce',0x1467b6f17:'e8345e0100',0x1467cbebe:'e9dd265eff'}
    for address,expected in registration.items():
        offset=h.image.offset(address-h.image.pe.base)
        if h.raw[offset:offset+len(bytes.fromhex(expected))]!=bytes.fromhex(expected):
            raise ValueError('Start registration/tail instructions differ')
    minimum=struct.unpack_from('<f',h.raw,h.image.offset(0x1489e6030-h.image.pe.base))[0]
    events=[]
    def finish(machine,value=0):
        sp=machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,value)
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    def fixture(address):
        def apply(machine):
            a,b,c,d=[machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            result=0
            if address==FORMAT:
                machine.mem_write(a,bytes(16));result=a
            elif address==LABEL:
                if a!=service:raise ValueError('Unexpected label receiver')
                machine.mem_write(b,bytes(16));result=b
                events.append(dict(action='label_fixture',target=c&0xffffffff))
            elif address==SET_STATE:
                if a!=service or b&255!=5:raise ValueError('Unexpected state setter')
                machine.mem_write(a+0x30,b'\x05')
                events.append(dict(action='state_setter_fixture',state=b&255))
            elif address==SETTINGS:result=settings
            elif address==TRANSPORT:result=transport
            elif address==SEND:
                if a!=transport or not h.scratch<=b<=h.scratch+0x40000-16:
                    raise ValueError('Unexpected send boundary')
                if int.from_bytes(machine.mem_read(b,8),'little')!=TABLE:
                    raise ValueError('Unexpected sent packet table')
                events.append(dict(action='send_boundary_fixture',packet_id=205,body_size=0))
                result=1
            elif address==LOAD:
                if a!=service or b!=41 or d!=1:raise ValueError('Unexpected relocation boundary')
                events.append(dict(action='load_fixture',target=b))
            elif address not in (FREE,DTOR):raise ValueError('Unexpected fixture')
            finish(machine,result)
        return apply
    hooks.update({a:fixture(a) for a in hooks})
    uc.mem_write(vtable+0xc8,struct.pack('<Q',LABEL))
    uc.mem_write(transport,struct.pack('<Q',transport_table))
    uc.mem_write(transport_table+0x38,struct.pack('<Q',SEND))
    cases=[]
    for status in range(8):
        for relocating in (False,True):
            for interval in (-2,0,9):
                uc.mem_write(service,bytes(0x180))
                uc.mem_write(service,struct.pack('<Q',vtable))
                uc.mem_write(service+0x30,bytes([status]))
                uc.mem_write(service+0x40,struct.pack('<II',37,41))
                uc.mem_write(service+0xc1,bytes([relocating]))
                uc.mem_write(service+0x150,struct.pack('<I',0x12345678))
                uc.mem_write(settings+0x238,struct.pack('<q',interval))
                events.clear()
                result=h.call(REQUEST,service)&255
                accepted=not relocating and status in (2,3,4)
                sent=[e for e in events if e['action']=='send_boundary_fixture']
                state=uc.mem_read(service+0x30,1)[0]
                active=int.from_bytes(uc.mem_read(service+0x158,4),'little')
                delay=struct.unpack('<f',uc.mem_read(service+0x154,4))[0]
                timer_field150=int.from_bytes(uc.mem_read(service+0x150,4),'little')
                if bool(result)!=accepted or len(sent)!=int(accepted) or state!=(5 if accepted else status):
                    raise ValueError('Native finish gate differs')
                if active!=int(accepted) or (accepted and delay!=max(float(interval),minimum)):
                    raise ValueError('Native finish timer differs')
                if timer_field150!=(0 if accepted else 0x12345678):
                    raise ValueError('Native finish timer field differs')
                if sum(e['action']=='load_fixture' for e in events)!=int(relocating):
                    raise ValueError('Native relocation branch differs')
                cases.append(dict(status=status,relocating=relocating,interval=interval,accepted=accepted,
                    state_after=state,timer_active=active,timer_field150=timer_field150,
                    delay=delay,events=events.copy()))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence=evidence,
        native_execution=True,network_used=False,packet_id=205,minimum_interval=minimum,
        request=hex(REQUEST),gate=hex(GATE),service_table=hex(service_table),
        start_binding=dict(packet_id=204,constructor='0x14584dcd0',handler='0x1467cbe20',
            receiver='0x145dae5a0',registration_bytes={hex(a):v for a,v in registration.items()}),
        fragments=h.fragments,leaves=h.leaves,cases=cases,
        limits=['Whole current request and gate execute; native constructor, empty writer and ID getter execute.',
            'Formatter, state setter, settings singleton, label resolution, load, destructor and send boundary are explicit fixtures.',
            'State setter fixture stores requested state 5; real engine setter side effects are not executed.',
            'Relocation fixture records a load request without executing a world load.',
            'ID204 constructor/getter execute; registration subset and handler tail are checked statically, not executed.',
            'Source of states 2/3/4, completion callback, ID206, actor position and world readiness are not established.',
            'No game, account or network IO.'])
    target=h.audit.save_snapshot(h.comparison/'world-finish-request-replay',report)
    return target,h.audit.sha256(target)


if __name__=='__main__':
    path,sha=run();print(json.dumps(dict(report=str(path),sha256=sha,cases=48)))
