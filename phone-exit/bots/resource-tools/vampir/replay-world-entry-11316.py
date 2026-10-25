"""Current bounded writers/readers and Ping receiver; explicit IO boundaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
SELECT_WRITE,START_WRITE=0x1456e8280,0x1456baaf0
RESERVE,NESTED,START,PING=0x14584f3d0,0x145821fb0,0x14584f4f0,0x1456db410
RECEIVER,HANDLER,GET=0x1467cf320,0x14679c450,0x1445cd3c0


def load(name):
    s=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def verify(exports):
    relocation=ROOT/'code-clues/world-relocation-11316/67c301f00b6cbf0e3706dad823acb14144e3bfa547fd9dd401f15b1a9f37d9ae/manifest.json'
    if hashlib.sha256(relocation.read_bytes()).hexdigest()!=relocation.parent.name:
        raise ValueError('World relocation evidence differs')
    contract=json.loads(relocation.read_text('utf-8'))
    if contract['source_sha256']!=SHA or not all(f['equal'] for f in contract['functions']):
        raise ValueError('World instruction contracts differ')
    h=load('native-request-harness-11316').make_harness(exports,
        {SELECT_WRITE,START_WRITE,RESERVE,NESTED,START,PING,RECEIVER},
        leaves={GET:'488b057976f906c3'})
    uc,x=h.uc,h.x
    packet,archive,table,nested_table,opaque_table=[h.scratch+n for n in (0x10000,0x12000,0x13000,0x14000,0x15000)]
    state={};events=[];cases=[]
    def take(count):
        at=state['cursor']
        if at+count>len(state['body']):return None
        state['cursor']+=count
        return state['body'][at:at+count]
    def io(machine,size,boolean=False):
        destination=machine.reg_read(x.UC_X86_REG_RDX)
        if not h.scratch<=destination<=h.scratch+0x40000-size:raise ValueError('Read fixture bounds')
        data=take(size)
        if data is not None:machine.mem_write(destination,bytes((bool(data[0]),)) if boolean else data)
        h.finish(int(data is not None))
    slots={0x40:(4,False),0x50:(8,False),0x58:(4,False),0x60:(4,False),0x78:(1,False),0x88:(1,True)}
    for slot,(size,boolean) in slots.items():
        at=h.scratch+0x20000+slot
        h.add_fixture(at,lambda machine,size=size,boolean=boolean:io(machine,size,boolean))
        uc.mem_write(table+slot,struct.pack('<Q',at))
    def raw64(machine):io(machine,8)
    h.add_fixture(0x144aac470,raw64)
    def nested(machine):
        archive_arg=machine.reg_read(x.UC_X86_REG_RCX)
        target=machine.reg_read(x.UC_X86_REG_RDX)
        vptr=int.from_bytes(machine.mem_read(target,8),'little')
        method=int.from_bytes(machine.mem_read(vptr+0x20,8),'little')
        machine.reg_write(x.UC_X86_REG_RCX,target)
        machine.reg_write(x.UC_X86_REG_RDX,archive_arg)
        machine.reg_write(x.UC_X86_REG_RIP,method)
    h.add_fixture(0x144aad190,nested)
    def opaque(machine):
        if machine.reg_read(x.UC_X86_REG_RCX)!=packet+0x30:raise ValueError('Wrong reserve boundary')
        events.append('opaque-reserve-suffix');h.finish(0)
    h.add_fixture(h.scratch+0x21000,opaque)
    uc.mem_write(nested_table+0x20,struct.pack('<Q',NESTED))
    uc.mem_write(opaque_table+0x20,struct.pack('<Q',h.scratch+0x21000))
    def vector(machine):
        destination=machine.reg_read(x.UC_X86_REG_RDX)
        data=take(12)
        if data is not None:machine.mem_write(destination,struct.pack('<ddd',*struct.unpack('<fff',data)))
        h.finish(int(data is not None))
    h.add_fixture(0x144aacf40,vector)
    def read(at,body):
        state.update(body=body,cursor=0);events.clear()
        uc.mem_write(packet,b'\0'*0x400)
        uc.mem_write(packet+0x18,struct.pack('<Q',nested_table))
        uc.mem_write(packet+0x30,struct.pack('<Q',opaque_table))
        uc.mem_write(archive,struct.pack('<Q',table))
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        return h.call(at,packet)&255
    for values in ((0,0,0,0,0,0),(16,255,2**64-1,2**32-1,255,255),(0,1,12345,456,1,22)):
        body=struct.pack('<IBQIBB',*values)
        for size in range(20):
            read(RESERVE,body[:size])
            if bool(events)!=(size==19):raise ValueError('Reserve prefix boundary differs')
            if size==19:
                actual=(struct.unpack('<I',bytes(uc.mem_read(packet+0x10,4)))[0],
                    uc.mem_read(packet+0x14,1)[0],struct.unpack('<Q',bytes(uc.mem_read(packet+0x20,8)))[0],
                    struct.unpack('<I',bytes(uc.mem_read(packet+0x28,4)))[0],uc.mem_read(packet+0x2c,1)[0],uc.mem_read(packet+0x2d,1)[0])
                expected=(values[0],min(values[1],32),values[2],values[3],bool(values[4]),min(values[5],22))
                if actual!=expected:raise ValueError('Reserve fields differ')
            cases.append(dict(kind='reserve-prefix',size=size,reached_boundary=bool(events)))
    for code,kind,flag in ((0,0,0),(16,255,255),(0,22,1)):
        body=struct.pack('<IIfffBBQ',code,10010,1.25,-2.5,3.75,kind,flag,1234)
        for size in range(31):
            accepted=read(START,body[:size])
            if accepted!=int(size==30):raise ValueError('Start reader length gate differs')
            if accepted:
                if struct.unpack('<ddd',bytes(uc.mem_read(packet+0x18,24)))!=(1.25,-2.5,3.75):raise ValueError('Start vector differs')
                if (uc.mem_read(packet+0x30,1)[0],uc.mem_read(packet+0x31,1)[0])!=(min(kind,22),bool(flag)):
                    raise ValueError('Start enum/bool differs')
            cases.append(dict(kind='start-result',size=size,accepted=bool(accepted)))
    for code,value in ((0,0),(16,2**64-1),(2**32-1,12345)):
        body=struct.pack('<IQ',code,value)
        for size in range(13):
            accepted=read(PING,body[:size])
            if accepted!=int(size==12):raise ValueError('Ping reader length differs')
            cases.append(dict(kind='ping-result',size=size,accepted=bool(accepted)))
    output=[]
    def write(machine,fmt):
        value=machine.reg_read(x.UC_X86_REG_RDX)&((1<<(struct.calcsize(fmt)*8))-1)
        output.append(struct.pack(fmt,value));h.finish(1)
    for slot,fmt in ((0xb8,'<Q'),(0xc8,'<I')):
        at=h.scratch+0x22000+slot
        h.add_fixture(at,lambda machine,fmt=fmt:write(machine,fmt))
        uc.mem_write(table+slot,struct.pack('<Q',at))
    for a,b,c in ((0,0,0),(12345,0,67890),(2**64-1,2**32-1,2**64-1)):
        uc.mem_write(packet+0x10,struct.pack('<Q8xQ',a,c));uc.mem_write(packet+0x18,struct.pack('<I',b))
        for at,expected in ((SELECT_WRITE,struct.pack('<QIQ',a,b,c)),(START_WRITE,struct.pack('<Q',a))):
            output.clear();uc.reg_write(x.UC_X86_REG_RDX,archive)
            if h.call(at,packet)&255!=1 or b''.join(output)!=expected:raise ValueError('World request writer differs')
            cases.append(dict(kind='writer',address=hex(at),bytes=len(expected)))
    # Actual Ping receiver timing arithmetic; source data is copied by harness.
    clock=h.scratch+0x17000
    uc.mem_write(0x14b564a40,struct.pack('<Q',clock))
    for sent,now in ((1000,2000),(5000,5000),(2000,1000)):
        uc.mem_write(packet,b'\0'*0x400);uc.mem_write(packet+0x178,struct.pack('<q',sent))
        uc.mem_write(packet+0x168,struct.pack('<ii',0,6));uc.mem_write(clock+0x10,struct.pack('<q',now*10000))
        h.call(RECEIVER,packet)
        if struct.unpack('<ii',bytes(uc.mem_read(packet+0x168,8)))!=(0,0):raise ValueError('Ping receiver tracking reset differs')
        if struct.unpack('<q',bytes(uc.mem_read(packet+0x178,8)))[0]!=now-sent:raise ValueError('Ping elapsed differs')
        cases.append(dict(kind='ping-receiver',sent=sent,now=now))
    report=dict(source_sha256=SHA,exports=h.evidence,cases=cases,network_used=False,profile_activated=False,
        relocation_report=dict(path=str(relocation),sha256=relocation.parent.name),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Actual ID109/203 writers, ID202 prefix/nested, ID204 and ID17 readers and Ping receiver.',
            'Archive scalar/nested thunk/vector, output IO are bounded fixtures. Reserve stops before opaque suffix.',
            'ID110/206 nested decoders are historical bounded parsers; full current nested compatibility is not established.',
            'No world engine streaming, active state or server session established by this replay.'])
    p=load('audit-client-release').save_snapshot(ROOT/'code-clues/world-entry-11316',report)
    return dict(report=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--exports',type=Path,required=True);a=p.parse_args()
    print(json.dumps(verify(json.loads(a.exports.read_text('utf-8')))))
