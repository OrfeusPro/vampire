"""Current whole tutorial reader; fresh bounded array storage, no game IO."""
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def run():
    path=HERE/'knowledge/native-contexts/tutorial-update-11316.json'
    context=json.loads(path.read_text('utf-8'))
    functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    if context['source_sha256']!=h.sha:raise ValueError('Tutorial context source differs')
    for table,slot,target in context['bindings']:
        at=int(table,16)+int(slot,16);off=h.image.offset(at-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,off)[0]!=int(target,16):raise ValueError('Tutorial binding changed')
    packet,archive,buffer,storage=[h.scratch+n for n in (0x30000,0x2000,0x5000,0x10000)]
    vector=packet+0x20
    def reg(key):return uc.reg_read(getattr(x,'UC_X86_REG_'+key))
    def number(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def clear(machine):
        if reg('RCX') or reg('RDX'):raise ValueError('Only empty prior tutorial storage is fixture')
        h.finish()
    def reserve(machine):
        count=reg('R8')
        if reg('RDX')!=vector or count>64:raise ValueError('Tutorial allocation budget')
        uc.mem_write(vector,struct.pack('<QII',storage if count else 0,0,count));h.finish()
    def no_growth(machine):raise ValueError('Fresh reserved tutorial vector grew unexpectedly')
    h.add_fixture(0x1456b5990,clear);h.add_fixture(0x1456ba3a0,reserve)
    h.add_fixture(0x141437ee0,no_growth);h.add_fixture(0x14141c410,no_growth)
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.tutorial_update import decode_tutorial_update
    def read(body):
        uc.mem_write(packet-16,b'\xa1'*16+bytes(64)+b'\xa2'*16)
        uc.mem_write(storage-16,b'\xa3'*16+b'\x5a'*(64*24)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        uc.mem_write(archive,bytes(64))
        h.call(functions['packet_constructor'],packet)
        if number(packet,8)!=0x149969ad8 or h.call(0x145855ec0,packet)!=9905:
            raise ValueError('Tutorial constructor / ID differs')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(functions['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(functions['reader'],packet,budget=1000000)&255)
        consumed=number(archive+0x30,8)-buffer
        if not 0<=consumed<=len(body):raise ValueError('Tutorial cursor exceeds input')
        for at,value in ((packet-16,b'\xa1'*16),(packet+64,b'\xa2'*16),
                (storage-16,b'\xa3'*16),(storage+64*24,b'\xa4'*16),
                (buffer-16,b'\xa5'*16),(buffer+len(body),b'\xa6'*16)):
            if bytes(uc.mem_read(at,len(value)))!=value:raise ValueError('Tutorial guard changed')
        return accepted,consumed
    cases=[]
    def whole(flag,count,state):
        body=struct.pack('<BH',flag,count)+b''.join(struct.pack('<IIIB',0xffffffff-i,i,1001002+i,state) for i in range(count))
        expected=decode_tutorial_update(body,source_sha256=h.sha,max_records=64,max_payload_size=835)
        if read(body)!=(True,len(body)):raise ValueError('Whole tutorial reader rejected input')
        if bool(number(packet+0x18,1))!=expected.flag:raise ValueError('Tutorial bool differs')
        pointer,n,capacity=struct.unpack('<QII',uc.mem_read(vector,16))
        if n!=count or capacity!=count:raise ValueError('Tutorial array count differs')
        for i,r in enumerate(expected.records):
            at=pointer+i*24
            if number(at,8)!=0x1499290a0 or struct.unpack('<IIIB',uc.mem_read(at+8,13))!=(r.raw08,r.raw0c,r.raw10,r.state):
                raise ValueError('Native / portable tutorial fields differ')
        cases.append(dict(flag=flag,count=count,state=state,consumed=len(body)))
        return body
    for flag in (0,1,255):
        for count in (0,1,2,8):
            for state in (0,1,2,3,4,255):whole(flag,count,state)
    body=whole(1,64,255);short=[]
    for size in range(len(body)):
        accepted,consumed=read(body[:size])
        if accepted:raise ValueError('Truncated tutorial accepted')
        short.append(dict(size=size,consumed=consumed))
    report=dict(source_sha256=h.sha,tool_sha256=load('audit-client-release').sha256(Path(__file__)),
        context_sha256=load('audit-client-release').sha256(path),exports=h.evidence,bindings=context['bindings'],
        cases=cases,short=short,native_execution=True,network_used=False,
        limits=['Whole current packet/nested constructors, ID getter, readers, array input loop and callback execute.',
            'Fresh array reserve and cleanup of empty previous storage are fixtures; reuse/growth/cleanup of populated storage not covered.',
            'Raw fields and last received message do not prove active local tutorial, handler application or safe outgoing action.'])
    audit=load('audit-client-release');target=audit.save_snapshot(h.root/'code-clues/tutorial-update-11316',report)
    return target,report

if __name__=='__main__':
    p,r=run();print(json.dumps(dict(report=str(p),cases=len(r['cases']),short=len(r['short']))))
