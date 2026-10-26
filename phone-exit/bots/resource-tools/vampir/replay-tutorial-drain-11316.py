"""Whole current ID9905 queue consumer; application and deallocation fixtures."""
import importlib.util
import json
from pathlib import Path
import struct
HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def run():
    context_path=HERE/'knowledge/native-contexts/tutorial-drain-11316.json'
    current=json.loads(context_path.read_text('utf-8'))
    functions={k:int(v,16) for k,v in current['functions'].items()}
    h=load('native-request-harness-11316').make_harness(current['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in current['leaves'].items()})
    if current['source_sha256']!=h.sha:raise ValueError('Tutorial queue source differs')
    uc,x=h.uc,h.x
    model,state_object,queue=h.scratch+0x1000,h.scratch+0x2000,h.scratch+0x3000
    packets=[h.scratch+0x4000+i*0x100 for i in range(3)]
    records=[h.scratch+0x10000+i*0x1000 for i in range(3)]
    table=int(current['packet_table'],16);destructor=int(current['destructor'],16)
    off=h.image.offset(table-h.image.pe.base)
    if struct.unpack_from('<Q',h.raw,off)[0]!=destructor or struct.unpack_from('<Q',h.raw,off+0x28)[0]!=0x145855ec0:
        raise ValueError('Current tutorial destructor / ID binding differs')
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def num(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def put(at,fmt,*v):uc.mem_write(at,struct.pack('<'+fmt,*v))
    state={}
    def state_fixture(machine):state['state_calls']+=1;h.finish(state_object)
    def apply_fixture(machine):
        pointer=reg('RDX')-16
        if reg('RCX')!=model or pointer not in state['expected']:raise ValueError('Queue application arguments differ')
        if state['waiting_release'] is not None:raise ValueError('Queue applied next packet before release')
        if pointer!=state['expected'][len(state['applied'])]:raise ValueError('Queue application order differs')
        vector,n,capacity=struct.unpack('<QII',uc.mem_read(pointer+0x20,16))
        if n!=state['count'] or capacity!=n or num(pointer+0x18,1)!=state['flag']:raise ValueError('Queued tutorial metadata differs')
        rows=[struct.unpack('<IIIB',uc.mem_read(vector+i*24+8,13)) for i in range(n)]
        if rows!=state['values'][pointer]:raise ValueError('Queued tutorial records differ')
        state['applied'].append(pointer);state['waiting_release']=pointer;h.finish()
    def release_fixture(machine):
        pointer=reg('RCX')
        if reg('RDX')!=1 or pointer!=state['waiting_release'] or pointer in state['released']:
            raise ValueError('Queue destructor order/count differs')
        state['released'].append(pointer);state['waiting_release']=None
        # Mark released packet unusable; a second native dispatch would fail.
        uc.mem_write(pointer,bytes(48));h.finish()
    def shrink_fixture(machine):
        if (reg('RCX'),reg('RDX'))!=(model+0x198,0) or num(model+0x1a0,4)!=0:
            raise ValueError('Queue shrink before count reset')
        if state['waiting_release'] is not None or state['released']!=state['expected']:
            raise ValueError('Queue shrunk before all packets released')
        state['shrink']+=1;put(model+0x198,'QII',0,0,0);h.finish()
    for at,fn in ((0x14560adc0,state_fixture),(int(current['application'],16),apply_fixture),
            (destructor,release_fixture),(0x14141cb60,shrink_fixture)):
        h.add_fixture(at,fn)
    cases=[]
    for phase in (0,5,6,7):
        for order in ((),(None,),(0,),(0,None,1),(2,1,0)):
            for count in (0,1,8,64):
                for flag in (0,1):
                    guarded=[(model,0x400),(state_object,0x80),(queue,32),*[(p,48) for p in packets],*[(p,64*24) for p in records]]
                    for at,size in guarded:uc.mem_write(at-16,b'\xa1'*16+bytes(size)+b'\xa2'*16)
                    state.clear();state.update(expected=[packets[i] for i in order if i is not None],applied=[],released=[],
                        waiting_release=None,shrink=0,state_calls=0,count=count,flag=flag,values={})
                    put(state_object+0x30,'B',phase);put(model+0x198,'QII',queue,len(order),4)
                    for j,item in enumerate(order):put(queue+j*8,'Q',0 if item is None else packets[item])
                    for i,pointer in enumerate(packets):
                        h.call(functions['packet_constructor'],pointer);put(pointer+0x18,'B',flag)
                        put(pointer+0x20,'QII',records[i] if count else 0,count,count)
                        # Deliberately share the record keys across distinct packets.
                        values=[(1001+k,i,k,1) for k in range(count)];state['values'][pointer]=values
                        for k,row in enumerate(values):put(records[i]+k*24,'QIIIB',0x1499290a0,*row)
                    before=bytes(uc.mem_read(model,0x400))+bytes(uc.mem_read(queue,32))+b''.join(bytes(uc.mem_read(p,48)) for p in packets)
                    h.call(functions['consumer'],model,budget=100000)
                    if phase<6:
                        after=bytes(uc.mem_read(model,0x400))+bytes(uc.mem_read(queue,32))+b''.join(bytes(uc.mem_read(p,48)) for p in packets)
                        if before!=after or state['applied'] or state['released'] or state['shrink']:
                            raise ValueError('Not-ready consumer changed queue')
                        put(state_object+0x30,'B',6);h.call(functions['consumer'],model,budget=100000)
                    if state['applied']!=state['expected'] or state['released']!=state['expected'] or state['shrink']!=1:
                        raise ValueError('Native consumer did not process / release exactly once')
                    if bytes(uc.mem_read(model+0x198,16))!=bytes(16):raise ValueError('Queue header not cleared')
                    previous=(state['applied'][:],state['released'][:],state['shrink'])
                    h.call(functions['consumer'],model,budget=100000)
                    if previous!=(state['applied'],state['released'],state['shrink']):raise ValueError('Empty queue processed twice')
                    for at,size in guarded:
                        if bytes(uc.mem_read(at-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(at+size,16))!=b'\xa2'*16:
                            raise ValueError('Queue consumer guard changed')
                    cases.append(dict(initial_phase=phase,order=list(order),records=count,flag=flag,resumed=phase<6,released=len(state['released'])))
    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(context_path),
        exports=h.evidence,cases=cases,native_execution=True,network_used=False,
        limits=['Whole current consumer and all chained unwind ranges execute for ID9905; actual constructor/ID getter execute.',
            'State provider, application, deleting destructor and shrink/deallocation are fixtures; actual heap lifecycle and applied maps not executed.',
            'Other tutorial packet branches and caller lifecycle are not covered; native phase 6 is not equated to headless world finish.',
            'No game traffic, commands or live tutorial completion claim.'])
    path=audit.save_snapshot(h.root/'code-clues/tutorial-drain-11316',report)
    return path,report

if __name__=='__main__':
    p,r=run();print(json.dumps(dict(report=str(p),cases=len(r['cases']))))
