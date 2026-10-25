"""Whole current NPC effect/optional-vector reader, synthetic bounded input only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    context_path=HERE/'knowledge/native-contexts/npc-effect-11316.json'
    context=json.loads(context_path.read_text('utf-8'))
    functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    if h.sha!=context['source_sha256']:raise ValueError('Effect context source differs')
    uc,x=h.uc,h.x
    record,archive,buffer=[h.scratch+n for n in (0x1000,0x2000,0x5000)]
    def number(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    # Name table and nested vptr links are checked against the immutable PE.
    for table,expected in [(0x149921b58,functions['reader']),(0x14991fc10,functions['optional']),
                           (0x1499203c8,functions['vector'])]:
        off=h.image.offset(table+0x20-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,off)[0]!=expected:raise ValueError('Effect reader binding differs')
    literal=b'PktEffectData\0'
    off=h.image.offset(0x149921b58-h.image.pe.base)
    if literal not in h.raw[off:off+256]:raise ValueError('Effect record literal binding differs')
    scalar_formats=[(8,'Q'),(0x10,'I'),(0x14,'I'),(0x18,'H'),(0x1a,'H'),(0x1c,'H'),
                    (0x20,'Q'),(0x28,'Q'),(0x30,'Q'),(0x38,'I')]
    cases=[]
    def attempt(body):
        uc.mem_write(record-16,b'\xa1'*16+bytes(0x70)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        h.call(functions['constructor'],record)
        if [number(record+n,8) for n in (0,0x40,0x50)]!=[0x149921b58,0x14991fc10,0x1499203c8]:
            raise ValueError('Effect native constructor differs')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(functions['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(functions['reader'],record)&255)
        for target,size,before,after in [(record,0x70,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4')]:
            if bytes(uc.mem_read(target-16,16))!=before*16 or bytes(uc.mem_read(target+size,16))!=after*16:
                raise ValueError('Effect record/archive guard changed')
        if bytes(uc.mem_read(buffer-16,len(body)+32))!=b'\xa5'*16+body+b'\xa6'*16:
            raise ValueError('Effect input modified')
        consumed=number(archive+0x30,8)-buffer
        if not 0<=consumed<=len(body):raise ValueError('Effect input read out of bounds')
        return accepted,consumed
    for scalar_case in ('zero','max','mixed'):
        values=[]
        for i,(_,fmt) in enumerate(scalar_formats):
            maximum=(1<<(8*struct.calcsize(fmt)))-1
            values.append(0 if scalar_case=='zero' else maximum if scalar_case=='max' else (maximum//3+i)&maximum)
        prefix=b''.join(struct.pack('<'+fmt,value) for (_,fmt),value in zip(scalar_formats,values))
        for present in (0,1,2,255):
            for bits in ((0,0,0),(0x80000000,0x3f800000,0xc2f68000),(0x7f800000,0xff800000,0x7fc12345)) if present else ((0,0,0),):
                for tail in (0,1,2,255):
                    body=prefix+bytes([present])+(struct.pack('<III',*bits) if present else b'')+bytes([tail])
                    for size in range(len(body)+1):
                        accepted,consumed=attempt(body[:size])
                        if accepted!=(size==len(body)):raise ValueError('Effect native prefix acceptance differs')
                        if accepted:
                            if consumed!=len(body):raise ValueError('Effect consumed size differs')
                            for (offset,fmt),expected in zip(scalar_formats,values):
                                if number(record+offset,struct.calcsize(fmt))!=expected:raise ValueError('Effect scalar differs')
                            # bool input normalizes any nonzero byte; vector retains raw float bits.
                            if number(record+0x48,1)!=bool(present) or number(record+0x68,1)!=bool(tail):
                                raise ValueError('Effect bool normalization differs')
                            actual=struct.unpack('<III',bytes(uc.mem_read(record+0x58,12)))
                            if actual!=(bits if present else (0,0,0)):raise ValueError('Effect optional vector differs')
                        cases.append(dict(scalar=scalar_case,present=present,bits=bits,tail=tail,size=size,accepted=accepted))
                    accepted,consumed=attempt(body+b'\xff')
                    if not accepted or consumed!=len(body):raise ValueError('Effect native trailing behavior differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,cases=cases,network_used=False,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),
        limits=['Whole effect constructor/reader, optional wrapper, vector constructor/reader and input/archive execute on one memory.',
                'Only memcpy allocation-free boundary is a fixture. Archive conversion flag is disabled.',
                'No NPC outer record, array callbacks, actor, effect gameplay meaning, visibility or live packet is proven.',
                'Float32 NaN/inf bits are accepted by native; no position semantics or safe map use inferred.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/npc-effect-11316',report)
    return dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
