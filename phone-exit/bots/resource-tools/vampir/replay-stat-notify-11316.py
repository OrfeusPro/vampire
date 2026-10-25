"""Whole stat notify reader/callback/input on one memory; bounded storage fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
ROOT=Path('F:/PhoneExit Resources/Vampir')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    context=json.loads((HERE/'knowledge/native-contexts/stat-notify-11316.json').read_text('utf-8'))
    functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    packet,archive,buffer,storage,model=[h.scratch+n for n in (0x1000,0x2000,0x5000,0x10000,0x18000)]
    cases=[]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def number(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def resize(machine):
        target,count=reg('RDX'),reg('R8')
        if target!=packet+0x18 or count>256:raise ValueError('Stat storage fixture bounds')
        uc.mem_write(target,struct.pack('<QII',storage if count else 0,0,count))
        uc.mem_write(storage,b'\x5a'*(32*256));h.finish()
    h.add_fixture(0x1456ba3e0,resize)
    def clear(machine):
        if reg('RCX')!=0 or reg('RDX')!=0:raise ValueError('Only empty previous stat storage is fixture')
        h.finish()
    h.add_fixture(0x1456b59f0,clear)
    h.add_fixture(0x1456b66c0,lambda machine:h.finish())
    model_fixtures=load('stat-model-fixtures')
    init_model,model_values,writes,types=model_fixtures.install(h,model,functions['model_setter'])
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.stat_change import decode_stat_change,decode_character_level_up
    samples=[[],[(4,123,0)],[(3,1,12),(4,-1,1500),(5,0,2000),(9,2**63-1,25),(10,-2**63,100)],[(4,i,i+10) for i in range(8)],[(134,123,-101)],[(i,987,-134055 if i==134 else i*123) for i in range(207)]]
    def attempt(body):
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x80)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(functions['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(functions[reader_name],packet,budget=300000)&255)
        if bytes(uc.mem_read(packet-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(packet+0x80,16))!=b'\xa2'*16:
            raise ValueError('Stat packet guards changed')
        if bytes(uc.mem_read(buffer-16,len(body)+32))!=b'\xa5'*16+body+b'\xa6'*16:
            raise ValueError('Stat input bytes changed')
        return accepted
    for reader_name,flags,decoder in (('reader',(0,255),decode_stat_change),('level_reader',(None,),decode_character_level_up)):
        for records in samples:
            for flag in flags:
                body=struct.pack('<QH',2**64-1,len(records))+b''.join(struct.pack('<iqq',*r) for r in records)+(b'' if flag is None else struct.pack('<BH',flag,0xffff))
                sizes=range(len(body)+1) if len(records)<207 else sorted({0,1,9,10,11,len(body)//2,len(body)-1,len(body)})
                for size in sizes:
                    accepted=attempt(body[:size])
                    if accepted!=(size==len(body)):raise ValueError('Whole stat prefix gate differs')
                    try:portable=decoder(body[:size],source_sha256=context['source_sha256'])
                    except ValueError:portable=None
                    if bool(portable)!=accepted:raise ValueError('Portable stat prefix gate differs')
                    if accepted:
                        actual=[]
                        count=number(packet+0x20,4);pointer=number(packet+0x18,8)
                        if count!=len(records):raise ValueError('Stat callback count differs')
                        for index in range(count):
                            at=pointer+32*index
                            if number(at,8)!=0x14991f558:raise ValueError('Stat copied record table differs')
                            actual.append((struct.unpack('<i',bytes(uc.mem_read(at+8,4)))[0],
                                struct.unpack('<q',bytes(uc.mem_read(at+0x10,8)))[0],
                                struct.unpack('<q',bytes(uc.mem_read(at+0x18,8)))[0]))
                        if actual!=records or portable.entity_key!=number(packet+0x10,8):raise ValueError('Stat identity or fields differ')
                        if flag is not None and (bool(number(packet+0x28,1))!=portable.flag or number(packet+0x2a,2)!=portable.reason):raise ValueError('Stat tail differs')
                        if [(r.stat_type,r.signed_second) for r in portable.values]!=[(r[0],r[2]) for r in actual]:raise ValueError('Stat portable values differ')
                        writes.clear();init_model();uc.reg_write(x.UC_X86_REG_RDX,packet+0x18);h.call(functions['apply'],model)
                        if writes!=[(r[0],model_fixtures.model_value(r[0],r[2])) for r in records]:raise ValueError('Whole stat apply order differs')
                        expected=dict.fromkeys(types,0xfeed)
                        expected.update((r[0],model_fixtures.model_value(r[0],r[2])%(2**64)) for r in records)
                        if model_values()!=expected:
                            raise ValueError('Actual native model values differ, including collisions and repeated keys')
                    cases.append(dict(records=len(records),flag=flag,size=size,accepted=accepted))
                if not attempt(body+b'\xff'):raise ValueError('Native stat trailing-byte behavior changed')
                try:decoder(body+b'\xff',source_sha256=context['source_sha256'])
                except ValueError:pass
                else:raise ValueError('Portable exact-size policy weakened')
    report=dict(source_sha256=context['source_sha256'],exports=h.evidence,cases=cases,network_used=False,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Actual outer reader, vector, record ctor/callback/reader, input/archive, apply and existing-key model setter run on one memory.',
            'Array allocation/reset, temporary record cleanup, memcpy and ownership wrapper are bounded fixtures.',
            'Model map uses preallocated existing keys with collisions; insertion, listeners and ownership services are not replayed.',
            'Zero previous storage; 207-record cases use eight selected prefixes, smaller cases test every prefix.',
            'No entity lookup, UI units or live notification integration proved.',
            'Portable trailing-byte rejection is stricter than native reader behavior.'])
    path=load('audit-client-release').save_snapshot(ROOT/'code-clues/stat-notify-11316',report)
    return dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
