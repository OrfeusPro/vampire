"""Whole current ID17 reader/handler/receiver with actual native input scalars."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def replay(context,root=ROOT):
    root=Path(root);guard=load('verify-ping-world-source-11318').verify(context,root)
    input_path=HERE/'knowledge/native-contexts/character-record-11318.json'
    input_context=json.loads(input_path.read_bytes())['native_input']
    if input_context['source_sha256']!=SHA:raise ValueError('Ping native input source differs')
    p={key:int(value,16) for key,value in context['ping'].items() if isinstance(value,str)}
    used=('constructor','buffer_constructor','u32','u64','time','raw')
    inputs={key:int(input_context['functions'][key],16) for key in used}
    functions={p['reader'],p['handler'],p['receiver'],*inputs.values()}
    exports=dict(context['exports'],**input_context['exports'])
    leaves={int(at,16):code for at,code in context['leaves'].items()}
    leaves.update({int(at,16):spec['bytes'] for at,spec in input_context['leaves'].items()})
    h=load('native-request-harness-11316').make_harness(exports,functions,leaves=leaves,root=root,
        source_sha256=SHA,copy_thunk=int(context['copy_thunk'],16))
    native=load('build-native-entry-code');whole=load('audit-launcher-shape-11318')
    for fragment in h.fragments:whole.normalize_function(native,h.image,fragment)
    uc,x=h.uc,h.x
    def data(at,size):
        off=h.image.offset(at-h.image.pe.base);return h.raw[off:off+size]
    def map_data(at,size):
        for page in range(at&~4095,(at+size+4095)&~4095,4096):
            if not any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()):
                uc.mem_map(page,4096)
                try:uc.mem_write(page,data(page,4096))
                except ValueError:pass
    table=int(input_context['table'],16);table_bytes=bytes.fromhex(input_context['table_bytes'])
    if data(table,len(table_bytes))!=table_bytes:raise ValueError('Ping input table changed')
    for slot,name in ((0x28,'time'),(0x50,'u64'),(0x58,'u32'),(0x90,'raw')):
        if struct.unpack_from('<Q',table_bytes,slot)[0]!=inputs[name]:raise ValueError('Ping input table target differs')
    map_data(table,len(table_bytes))
    packet,wrapper,clock,config,archive,buffer=[h.scratch+at for at in (0x10000,0x11000,0x12000,0x13000,0x14000,0x16000)]
    map_data(p['clock_global'],8);uc.mem_write(p['clock_global'],struct.pack('<Q',clock))
    events=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def fixture(kind):
        def run(machine):
            if kind=='wrapper':result=wrapper
            elif kind=='config':result=config
            elif kind=='recovery':
                if reg('RCX')!=wrapper:raise ValueError('Ping recovery wrapper differs')
                events.append('recovery');result=0
            elif kind=='read-error':events.append('read-error');result=0
            else:raise ValueError('Unknown Ping boundary')
            h.finish(result)
        return run
    h.add_fixture(p['wrapper_getter'],fixture('wrapper'))
    h.add_fixture(p['config_getter'],fixture('config'))
    h.add_fixture(p['recovery'],fixture('recovery'))
    # These callbacks report failed native reads. They do not return bytes or
    # change the cursor; the actual native scalar/raw path controls acceptance.
    error_callbacks=(0x1445e06f0,0x1445e0720)
    for at in error_callbacks:h.add_fixture(at,fixture('read-error'))
    def read(body):
        uc.mem_write(packet,b'\xa5'*0x20);h.call(p['constructor'],packet)
        if int.from_bytes(uc.mem_read(packet,8),'little')!=p['packet_table'] or h.call(p['getter'],packet)!=17:
            raise ValueError('Ping native constructor/getter differs')
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        uc.mem_write(archive-16,b'\xa5'*16+b'\x55'*0x40+b'\xa6'*16)
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(inputs['constructor'],archive)
        if (int.from_bytes(uc.mem_read(archive,8),'little')!=table
                or int.from_bytes(uc.mem_read(archive+0x20,8),'little')!=buffer
                or int.from_bytes(uc.mem_read(archive+0x30,8),'little')!=buffer):
            raise ValueError('Ping native archive construction differs')
        events.clear();uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=h.call(p['reader'],packet)&255
        consumed=int.from_bytes(uc.mem_read(archive+0x30,8),'little')-buffer
        if not 0<=consumed<=len(body):raise ValueError('Ping native reader cursor bound')
        if bytes(uc.mem_read(buffer-16,len(body)+32))!=b'\xa5'*16+body+b'\xa6'*16:
            raise ValueError('Ping reader changed input/guards')
        return accepted,consumed
    cases=[]
    for code in (0,16,0xffffffff):
        for value in (0,2**64-1):
            for flags in (0,512,1024):
                for outstanding in (0,6):
                    if read(struct.pack('<IQ',code,value))!=(1,12):raise ValueError('Ping whole reader consumption differs')
                    if struct.unpack('<I',uc.mem_read(packet+0x10,4))[0]!=code or struct.unpack('<Q',uc.mem_read(packet+0x18,8))[0]!=value:
                        raise ValueError('Ping reader fields differ')
                    uc.mem_write(wrapper,bytes(0x200));uc.mem_write(wrapper+0x16c,struct.pack('<I',outstanding))
                    uc.mem_write(wrapper+0x178,struct.pack('<q',10000));uc.mem_write(clock+0x10,struct.pack('<q',100250000))
                    uc.mem_write(config+8,struct.pack('<I',flags));events.clear()
                    uc.reg_write(x.UC_X86_REG_RDX,0);uc.reg_write(x.UC_X86_REG_R8,packet)
                    h.call(p['handler'],0,budget=3000)
                    index,counter=struct.unpack('<II',uc.mem_read(wrapper+0x168,8))
                    elapsed=struct.unpack('<q',uc.mem_read(wrapper+0x178,8))[0]
                    average=struct.unpack('<f',uc.mem_read(wrapper+0x170,4))[0]
                    recovery=events.count('recovery')
                    if (counter,index,elapsed,average,recovery)!=(0,0,25,25.0,int(bool(flags&1024))):
                        raise ValueError('Ping whole handler/receiver state differs')
                    cases.append(dict(result_bits=code,value_bits=value,flags=flags,outstanding_before=outstanding,
                        outstanding_after=counter,tracking_index_after=index,elapsed=elapsed,recovery_calls=recovery))
    short=[]
    for size in range(12):
        accepted,consumed=read(bytes(size))
        if accepted:raise ValueError('Short Ping native input accepted')
        short.append(dict(size=size,consumed=consumed))
    deps=('replay-ping-result-11318.py','verify-ping-world-source-11318.py','native-request-harness-11316.py',
          'build-native-entry-code.py','build-object-zero-init-code.py','extract-native-enums.py','audit-launcher-shape-11318.py',
          'knowledge-index.py','knowledge/native-contexts/ping-world-11318.json','knowledge/native-contexts/character-record-11318.json')
    return dict(schema=1,source_sha256=SHA,method='bounded_native',native_execution=True,cases=cases,short=short,
        evidence=h.evidence,source_guard=guard,registration=context['ping']['registration'],
        dependencies={name:digest(HERE/name) for name in deps},tool_sha256=digest(Path(__file__)),
        network_used=False,profile_activated=False,
        limits=['Whole native constructor/ID getter/input archive u32/time/u64/raw/reader/handler/receiver execute.',
                'Singleton/config getters, one clock slot, recovery and scalar-error logging are explicit fixtures; memcpy is bounded.',
                'Packet/result bits are not claimed to gate receiver acceptance; all tested nonzero result codes still reset it.',
                'Registration is a source-checked static window, not whole factory execution. Recovery internals and resync unknown.',
                'No real network, scheduling, reconnect, automatic profile activation or durable session claim.'])


def verify(exports):
    context=json.loads((HERE/'knowledge/native-contexts/ping-world-11318.json').read_bytes())
    if exports!=context['exports']:raise ValueError('Ping replay supplied exports differ')
    report=replay(context)
    path=load('audit-client-release').save_snapshot(ROOT/'code-clues/ping-result-11318',report)
    return dict(report=str(path),sha256=digest(path),cases=len(report['cases']),short=len(report['short']))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--context',type=Path,default=HERE/'knowledge/native-contexts/ping-world-11318.json')
    a=p.parse_args();print(json.dumps(verify(json.loads(a.context.read_bytes())['exports'])))
