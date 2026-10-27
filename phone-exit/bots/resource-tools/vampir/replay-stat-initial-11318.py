"""Current initial PktStat array/record/application with bounded model storage."""
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
    context=json.loads((HERE/'knowledge/native-contexts/stat-initial-11318.json').read_text('utf-8'))
    functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('stat-support-11318').make_harness(context)
    uc,x=h.uc,h.x
    vector,archive,buffer,storage,model=[h.scratch+n for n in (0x1000,0x2000,0x5000,0x10000,0x18000)]
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def number(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def resize(machine):
        if reg('RDX')!=vector or reg('R8')>256:raise ValueError('Initial stat allocation budget')
        count=reg('R8');uc.mem_write(vector,struct.pack('<QII',storage if count else 0,0,count))
        uc.mem_write(storage,b'\x5a'*(24*256));h.finish()
    h.add_fixture(int(context['fixtures']['0x1456ba3a0'],16),resize)
    def clear(machine):
        if reg('RCX')!=0 or reg('RDX')!=0:raise ValueError('Only empty prior initial storage is fixture')
        h.finish()
    h.add_fixture(int(context['fixtures']['0x1456b5990'],16),clear)
    h.add_fixture(int(context['fixtures']['0x1456b66c0'],16),lambda machine:h.finish())
    model_fixtures=load('stat-support-11318')
    init_model,model_values,writes,types=model_fixtures.install(h,model,functions['model_setter'])
    # Level-related external identity service is a fixture with a different model;
    # the native UI/engine side-effect branch is deliberately not executed.
    service,other=h.scratch+0x1b000,h.scratch+0x1c000
    uc.mem_write(service+0x38,struct.pack('<QQ',other,0));uc.mem_write(other+8,struct.pack('<Q',2))
    h.add_fixture(int(context['fixtures']['0x145594e00'],16),lambda machine:h.finish(service))
    links=[context['character_stat_link']]
    for row in links[0]:
        at=int(row['address'],16);raw=bytes.fromhex(row['bytes']);off=h.image.offset(at-h.image.pe.base)
        if h.raw[off:off+len(raw)]!=raw:raise ValueError('Character stat call-site source differs')
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.character_select_result import SelectionRecord
    initial_stat_values=load('stat-support-11318').initial_stat_values
    cases=[]
    for records in ([],[(4,0)],[(3,12),(4,1500),(5,2000),(9,25),(10,100)],[(4,i) for i in range(8)],[(134,-101)],[(i,-134055 if i==134 else i*123) for i in range(207)]):
        body=struct.pack('<H',len(records))+b''.join(struct.pack('<iq',*row) for row in records)
        sizes=range(len(body)+1) if len(records)<207 else sorted({0,1,2,3,len(body)//2,len(body)-2,len(body)-1,len(body)})
        for size in sizes:
            uc.mem_write(vector-16,b'\xa1'*16+bytes(16)+b'\xa2'*16)
            uc.mem_write(buffer-16,b'\xa3'*16+body[:size]+b'\xa4'*16)
            uc.mem_write(archive,bytes(0x40))
            uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,size);uc.reg_write(x.UC_X86_REG_R9,1)
            uc.mem_write(h.scratch+0x38028,bytes(8));h.call(functions['input_constructor'],archive)
            uc.reg_write(x.UC_X86_REG_RDX,vector)
            accepted=bool(h.call(functions['reader'],archive,budget=300000)&255)
            if accepted!=(size==len(body)):raise ValueError('Initial stat reader prefix gate differs')
            if bytes(uc.mem_read(vector-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(vector+16,16))!=b'\xa2'*16:
                raise ValueError('Initial stat vector guards changed')
            if accepted:
                if number(vector+8,4)!=len(records):raise ValueError('Initial stat count differs')
                actual=[];pairs=[]
                for i in range(len(records)):
                    at=number(vector,8)+i*24
                    if number(at,8)!=int(context['bindings']['0x149921c20'],16):raise ValueError('Initial PktStat table differs')
                    stat=struct.unpack('<i',bytes(uc.mem_read(at+8,4)))[0]
                    bits=number(at+16,8);actual.append((stat,bits if bits<2**63 else bits-2**64))
                    pairs.append(SelectionRecord(((8,stat%(2**32)),(16,bits))))
                if actual!=records or initial_stat_values(tuple(pairs),source_sha256=context['source_sha256'])!=tuple(records):
                    raise ValueError('Initial stat native fields differ from portable projection')
                init_model();uc.reg_write(x.UC_X86_REG_RDX,vector);h.call(functions['apply'],model)
                expected=dict.fromkeys(types,0xfeed);expected.update((stat,model_fixtures.model_value(stat,value)%(2**64)) for stat,value in records)
                if writes!=[(stat,model_fixtures.model_value(stat,value)) for stat,value in records] or model_values()!=expected:raise ValueError('Initial native model values differ')
            cases.append(dict(records=len(records),size=size,accepted=accepted))
    payload=dict(source_sha256=context['source_sha256'],exports=h.evidence,cases=cases,
        character_stat_link=links[0],network_used=False,profile_activated=False,runtime_decoder_admitted=False,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ('native-request-harness-11316.py','build-native-entry-code.py')},
        portable_decoder_sha256=hashlib.sha256((HERE.parents[1]/'vampir-shared/vampir_core/stat_change_11318.py').read_bytes()).hexdigest(),
        context_sha256=hashlib.sha256((HERE/'knowledge/native-contexts/stat-initial-11318.json').read_bytes()).hexdigest(),
        fixture_tool_sha256=hashlib.sha256((HERE/'stat-support-11318.py').read_bytes()).hexdigest(),
        limits=['Actual initial array wrapper, vector, ctor/callback/record, input, apply and existing-key map setter.',
            'Array storage/reset, cleanup, memcpy, ownership wrapper and external identity service are fixtures.',
            'Main character +1c8 call-site is checked statically; the full character reader is not replayed here.',
            '207-record cases use eight selected prefixes; smaller cases test every prefix. No insertion or UI/engine effects.'])
    path=load('audit-client-release').save_snapshot(ROOT/'code-clues/stat-initial-11318',payload)
    return dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
