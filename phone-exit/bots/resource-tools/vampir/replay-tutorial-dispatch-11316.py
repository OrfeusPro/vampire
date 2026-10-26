"""Current tutorial handler/gate and deep queued copy; application is a fixture."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def run():
    context_path=HERE/'knowledge/native-contexts/tutorial-dispatch-11316.json'
    context=json.loads(context_path.read_text('utf-8'))
    functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    if context['source_sha256']!=h.sha:raise ValueError('Tutorial dispatch source differs')
    uc,x=h.uc,h.x
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def num(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,fmt,*values):uc.mem_write(at,struct.pack('<'+fmt,*values))
    for at,expected in context['registration_anchors'].items():
        off=h.image.offset(int(at,16)-h.image.pe.base)
        if h.raw[off:off+len(bytes.fromhex(expected))].hex()!=expected:raise ValueError('Tutorial registration changed')
    table=int(context['handler_table'],16);off=h.image.offset(table-h.image.pe.base)
    if struct.unpack_from('<3Q',h.raw,off)!=(0x1414096c0,0x14153b9d0,functions['handler']):
        raise ValueError('Tutorial handler table differs')
    getter=0x1464af340;off=h.image.offset(getter-h.image.pe.base)
    global_at=getter+7+struct.unpack_from('<i',h.raw,off+3)[0]
    if global_at!=int(context['handler_global'],16):raise ValueError('Tutorial context getter differs')
    model,state_object,packet,records,queue=[h.scratch+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000)]
    state={}
    def allocate(size):
        if not 0<size<=64*24 or state['heap']+size+32>h.scratch+0x30000:raise ValueError('Tutorial clone allocation bound')
        pointer=state['heap']+16;state['heap']+=(size+63)&~15
        uc.mem_write(pointer-16,b'\xa1'*16+b'\x5a'*size+b'\xa2'*16)
        state['allocations'][pointer]=size;return pointer
    def state_fixture(machine):state['state_calls']+=1;h.finish(state_object)
    def packet_allocate(machine):
        if reg('RCX')!=0x30:raise ValueError('Unexpected tutorial packet allocation')
        state['clone']=allocate(48);h.finish(state['clone'])
    def reserve(machine):
        if reg('RCX')!=state['clone']+0x20 or not 0<reg('RDX')<=64 or reg('R8')!=0:
            raise ValueError('Only fresh tutorial clone array is fixture')
        count=reg('RDX');put(reg('RCX'),'Q',allocate(count*24));put(reg('RCX')+12,'I',count);h.finish()
    def empty_cleanup(machine):
        if reg('RCX') or reg('RDX'):raise ValueError('Only empty prior clone storage is fixture')
        h.finish()
    def apply_fixture(machine):
        if (reg('RCX'),reg('RDX'))!=(model,packet+16):raise ValueError('Immediate tutorial argument association differs')
        state['applied']+=1;h.finish()
    def no_growth(machine):raise ValueError('Prepared tutorial queue grew unexpectedly')
    for at,fn in ((0x14560adc0,state_fixture),(0x146908950,packet_allocate),(0x141539310,reserve),
            (0x1456b5990,empty_cleanup),(0x1464c35d0,apply_fixture),(0x14141c080,no_growth)):
        h.add_fixture(at,fn)
    cases=[]
    for via_handler in (False,True):
        for native_state in (0,5,6,7):
            for force in ((0,) if via_handler else (0,1)):
                for flag in (0,1):
                    for count in (0,1,8,64):
                        for prior in (0,1):
                            state.clear();state.update(heap=h.scratch+0x10000,allocations={},state_calls=0,applied=0)
                            uc.mem_write(model,bytes(0x400));uc.mem_write(state_object,bytes(0x80))
                            uc.mem_write(packet-16,b'\xa3'*16+bytes(48)+b'\xa4'*16)
                            uc.mem_write(queue-16,b'\xa5'*16+bytes(32)+b'\xa6'*16)
                            put(global_at,'Q',model);put(state_object+0x30,'B',native_state)
                            put(model+0x198,'QII',queue,prior,4);put(queue,'Q',0xfeed if prior else 0)
                            h.call(functions['packet_constructor'],packet)
                            put(packet+8,'HB',0x1234,0x56);put(packet+0x18,'B',flag)
                            put(packet+0x20,'QII',records if count else 0,count,count)
                            expected=[]
                            for i in range(count):
                                row=(1001+i,i,1001002+i,i%4);expected.append(row)
                                put(records+i*24,'QIIIB',0x1499290a0,*row)
                            if via_handler:
                                uc.reg_write(x.UC_X86_REG_R8,packet);h.call(functions['handler'])
                            else:
                                uc.reg_write(x.UC_X86_REG_RDX,packet);uc.reg_write(x.UC_X86_REG_R8,force)
                                h.call(functions['receiver'],model)
                            deferred=not force and native_state<6
                            if state['state_calls']!=(0 if force else 1):raise ValueError('Native state gate call differs')
                            if deferred:
                                clone=state['clone']
                                if state['applied'] or num(model+0x1a0,4)!=prior+1 or num(queue+prior*8,8)!=clone:
                                    raise ValueError('Deferred tutorial queue association differs')
                                if num(clone,8)!=0x149969ad8 or num(clone+8,2)!=0x1234 or num(clone+10,1)!=0x56 or num(clone+0x18,1)!=flag:
                                    raise ValueError('Tutorial clone metadata differs')
                                pointer,n,capacity=struct.unpack('<QII',uc.mem_read(clone+0x20,16))
                                if n!=count or capacity!=count or (count and pointer==records):raise ValueError('Tutorial clone storage aliases source')
                                def copied():return [struct.unpack('<IIIB',uc.mem_read(pointer+i*24+8,13)) for i in range(count)]
                                if copied()!=expected:raise ValueError('Native tutorial deep copy fields differ')
                                for i in range(count):
                                    if num(pointer+i*24,8)!=0x1499290a0:raise ValueError('Tutorial clone record vptr differs')
                                put(packet+0x18,'B',1-flag)
                                if count:uc.mem_write(records,b'\xff'*(count*24))
                                if copied()!=expected or num(clone+0x18,1)!=flag:raise ValueError('Queued tutorial changed with original packet')
                            elif state['applied']!=1 or state['allocations'] or num(model+0x1a0,4)!=prior:
                                raise ValueError('Immediate tutorial route differs')
                            if prior and num(queue,8)!=0xfeed:raise ValueError('Prior tutorial queue entry changed')
                            for pointer,size in state['allocations'].items():
                                if bytes(uc.mem_read(pointer-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(pointer+size,16))!=b'\xa2'*16:
                                    raise ValueError('Tutorial allocation guard changed')
                            for at,value in ((packet-16,b'\xa3'*16),(packet+48,b'\xa4'*16),(queue-16,b'\xa5'*16),(queue+32,b'\xa6'*16)):
                                if bytes(uc.mem_read(at,16))!=value:raise ValueError('Tutorial object guard changed')
                            cases.append(dict(via_handler=via_handler,native_state=native_state,force=force,flag=flag,count=count,prior=prior,deferred=deferred))
    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),
        exports=h.evidence,cases=cases,native_execution=True,network_used=False,
        limits=['Native handler/getter/receiver, ID9905 defer branch, packet ctor and whole deep-copy helpers execute.',
            'State provider, successful allocations and fresh reserve/empty cleanup are fixtures; prepared queue does not grow.',
            'Immediate application target is a fixture: no native server/local map, bootstrap, task launch or queue drain proof.',
            'Other packet IDs and allocation failure branches are not covered. Native gate value 6 is not equated with headless world finish.'])
    path=audit.save_snapshot(h.root/'code-clues/tutorial-dispatch-11316',report)
    return path,report

if __name__=='__main__':
    p,r=run();print(json.dumps(dict(report=str(p),cases=len(r['cases']))))
