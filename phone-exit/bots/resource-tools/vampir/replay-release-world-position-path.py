"""Bounded current callback/bridge and whole actor-position forwarding checks."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
CALLBACK,BRIDGE,MOVE=0x145d99710,0x14561f540,0x1438228b0
WORLD_SERVICE,ENABLE_SERVICE,ENABLE=0x14560c510,0x145517570,0x145512100
WORLD_CONTEXT,HAS_WORLD=0x1445d42b0,0x144321140
CLASS,FIND=0x14555ada0,0x143c16780
FORMAT,STATE,FREE,DELEGATE_DTOR,COOKIE=0x141433420,0x145619e00,0x141483160,0x141421c50,0x1487eac40
OTHER,FINISH,MOVE_COMPONENT=0x3000f100,0x3000f200,0x3000f300


def run():
    spec=importlib.util.spec_from_file_location('position_archive',HERE/'replay-release-archive-input.py')
    archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)
    hooks={a:None for a in (WORLD_SERVICE,ENABLE_SERVICE,ENABLE,WORLD_CONTEXT,HAS_WORLD,CLASS,FIND,
        FORMAT,STATE,FREE,DELEGATE_DTOR,COOKIE,OTHER,FINISH,MOVE_COMPONENT)}
    h=archive.make_harness(extra_addresses=(CALLBACK,BRIDGE,MOVE),
        extra_leaves=(0x1458212d0,0x1457846f0,0x145759170),fixtures=hooks)
    evidence={
        'details/run-6b9214e917be/details.json':'e19ef0084ed087d9c972a7e5fd47fd5d11251ffe0844243e03341dc06a99e31f',
        'details/run-a74c5869b659/details.json':'4615a07bcfe85b5213cd0ecbaeffb4f7245cd48376fe5851c6a900add93f5bda',
        'details/run-74bc593d49ac/details.json':'7635e508c5a742374aea37a9789f23dac2db586450a8cec4bad9fff8e5c19348',
        'details/run-3fff77629747/details.json':'6122ebd8e03562b24830417fbddd0c8790119db8e35ba78c1e1c11062edcb478'}
    for relative,expected in evidence.items():
        if h.audit.sha256(h.comparison/relative)!=expected:raise ValueError('Position path evidence changed')
    class_literals=[]
    for address,text in ((0x1498f9ba2,'NnWaitingForWorldPartitionStreamingActor'),
            (0x1498b29b2,'NnCharacterPC')):
        encoded=(text+'\0').encode('utf-16le')
        off=h.image.offset(address-h.image.pe.base)
        if h.raw[off:off+len(encoded)]!=encoded:raise ValueError('Class literal differs')
        class_literals.append(dict(address=hex(address),text=text,bytes=encoded.hex()))
    uc,x=h.uc,h.x
    service,table,closure,other,other_table,actor,component,component_table,target=[
        h.scratch+n for n in (0x10000,0x11000,0x12000,0x13000,0x14000,0x15000,0x16000,0x17000,0x18000)]
    nested_bindings=[]
    for ctor,expected_table,expected_reader in ((0x1458212d0,0x1499237a0,0x1458233c0),
            (0x1457846f0,0x149921fb0,0x145788d00)):
        h.call(ctor,target)
        actual_table=int.from_bytes(uc.mem_read(target,8),'little')
        off=h.image.offset(actual_table-h.image.pe.base)
        reader=struct.unpack_from('<Q',h.raw,off+0x20)[0]
        if (actual_table,reader)!=(expected_table,expected_reader):raise ValueError('Nested ID206 binding differs')
        nested_bindings.append(dict(constructor=hex(ctor),table=hex(actual_table),reader=hex(reader)))
    if h.call(0x145759170,target)!=206:raise ValueError('ID206 getter differs')
    events=[];has_world=False;move_result=0
    def finish(machine,value=0):
        sp=machine.reg_read(x.UC_X86_REG_RSP)
        machine.reg_write(x.UC_X86_REG_RAX,value)
        machine.reg_write(x.UC_X86_REG_RIP,int.from_bytes(machine.mem_read(sp,8),'little'))
        machine.reg_write(x.UC_X86_REG_RSP,sp+8)
    def fixture(address):
        def apply(machine):
            a,b,c,d=[machine.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
            result=0
            if address==WORLD_SERVICE:result=other
            elif address in (ENABLE_SERVICE,WORLD_CONTEXT):result=h.scratch+0x19000
            elif address==HAS_WORLD:result=int(has_world)
            elif address==CLASS:result=h.scratch+0x1a000
            elif address==FIND:
                # No streaming actor in this bounded branch.
                events.append(dict(action='streaming_actor_lookup_fixture',found=False))
            elif address==FORMAT:machine.mem_write(a,bytes(16));result=a
            elif address==STATE:
                if a!=service or b&255!=4:raise ValueError('Unexpected bridge state')
                machine.mem_write(a+0x30,b'\x04')
                events.append(dict(action='state_setter_fixture',state=4))
            elif address==OTHER:
                if a!=other or (b&0xffffffff,c&255)!=(37,3):raise ValueError('World callback context differs')
            elif address==ENABLE:
                if b&255!=1:raise ValueError('Enable fixture differs')
            elif address==FINISH:
                if a!=service:raise ValueError('Finish callback receiver differs')
                events.append(dict(action='finish_slot_fixture'))
            elif address==MOVE_COMPONENT:
                if a!=component:raise ValueError('Unexpected moved component')
                sp=machine.reg_read(x.UC_X86_REG_RSP)
                delta=struct.unpack('<ddd',machine.mem_read(b,24))
                rotation=bytes(machine.mem_read(c,32)).hex()
                stack_args=[int.from_bytes(machine.mem_read(sp+n,8),'little') for n in (0x28,0x30,0x38)]
                events.append(dict(action='component_move_fixture',delta=list(delta),rotation_hex=rotation,
                    sweep=d&255,hit_result=stack_args[0],move_flags=stack_args[1]&0xffffffff,
                    teleport=stack_args[2]&255))
                result=move_result
            elif address not in (FREE,DELEGATE_DTOR,COOKIE):raise ValueError('Unexpected position fixture')
            finish(machine,result)
        return apply
    hooks.update({a:fixture(a) for a in hooks})
    uc.mem_write(service,struct.pack('<Q',table))
    uc.mem_write(table+0x70,struct.pack('<Q',FINISH))
    uc.mem_write(service+0x40,struct.pack('<I',37))
    uc.mem_write(service+0x58,b'\x03')
    uc.mem_write(service+0x60,struct.pack('<ddd',1.5,-2.25,-0.0))
    uc.mem_write(closure,struct.pack('<Q',service))
    uc.mem_write(other,struct.pack('<Q',other_table))
    uc.mem_write(other_table+0x60,struct.pack('<Q',OTHER))
    uc.mem_write(0x14b3ce8c0,b'\0')
    callback_cases=[]
    for has_world in (False,True):
        for status in (1,2,3,4):
            uc.mem_write(service+0x30,bytes([status]));events.clear()
            h.call(CALLBACK,closure,budget=10000)
            state=uc.mem_read(service+0x30,1)[0]
            if state!=(4 if has_world else status):raise ValueError('Callback state differs')
            if sum(e['action']=='finish_slot_fixture' for e in events)!=int(not has_world):
                raise ValueError('Callback completion differs')
            callback_cases.append(dict(has_world=has_world,streaming_actor_found=False,
                initial_state=status,state_after=state,events=events.copy()))
    uc.mem_write(actor+0x1b8,struct.pack('<Q',component))
    uc.mem_write(component,struct.pack('<Q',component_table))
    uc.mem_write(component_table+0x548,struct.pack('<Q',MOVE_COMPONENT))
    rotation=struct.pack('<dddd',0.0,0.0,0.0,1.0)
    uc.mem_write(component+0x1d0,rotation)
    move_cases=[]
    for current,destination in (((0.0,0.0,0.0),(1.5,-2.25,-0.0)),
            ((10.0,-20.0,30.0),(-3.5,4.25,99.0)),((5.0,6.0,7.0),(5.0,6.0,7.0))):
        for sweep in (0,1):
            for teleport in (0,1,2):
                for move_result in (0,1):
                    uc.mem_write(component+0x1f0,struct.pack('<ddd',*current))
                    uc.mem_write(target,struct.pack('<ddd',*destination))
                    # Fifth Windows ABI argument belongs to the caller's stack.
                    uc.mem_write(h.stack+0x28,struct.pack('<Q',teleport))
                    events.clear()
                    result=h.call(MOVE,actor,target,sweep,0)&255
                    if len(events)!=1:raise ValueError('Expected one component move')
                    event=events[0]
                    if (event['delta']!=[b-a for a,b in zip(current,destination)]
                            or event['rotation_hex']!=rotation.hex() or event['sweep']!=sweep
                            or event['hit_result']!=0 or event['move_flags']!=0
                            or event['teleport']!=teleport or result!=move_result):
                        raise ValueError('Actor position forwarding differs')
                    move_cases.append(dict(current=list(current),target=list(destination),
                        returned=result,event=event.copy()))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),evidence=evidence,
        native_execution=True,network_used=False,callback=hex(CALLBACK),bridge=hex(BRIDGE),move=hex(MOVE),
        fragments=h.fragments,leaves=h.leaves,class_literals=class_literals,
        nested_finish_bindings=nested_bindings,finish_packet_id=206,
        callback_cases=callback_cases,move_cases=move_cases,
        limits=['Whole current callback executes; bridge executes only its no-streaming-actor branch.',
            'World/context/class lookup, state setter, enable, delegate cleanup and finish slot are explicit fixtures.',
            'Whole actor position wrapper executes with a synthetic actor/component; virtual component move is a capture fixture.',
            'Component movement is not simulated; only delta, rotation and arguments reaching its boundary are verified.',
            'ID204/206 receiver, actor spawn, streaming completion event and readiness are not executed.',
            'Class getter literal links are checked statically; getters and player actor lookup do not execute.',
            'Two nested ID206 constructors and ID getter execute; complete ID206 constructor and reader do not execute.',
            'Synthetic coordinates only; no game, account or network IO.'])
    target_path=h.audit.save_snapshot(h.comparison/'world-position-path-replay',report)
    return target_path,h.audit.sha256(target_path)


if __name__=='__main__':
    path,sha=run();print(json.dumps(dict(report=str(path),sha256=sha,callback_cases=8,move_cases=36)))
