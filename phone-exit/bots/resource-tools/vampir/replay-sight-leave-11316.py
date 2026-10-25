"""Whole source-bound sight leave reader/callbacks on one native memory."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    context_path=HERE/'knowledge/native-contexts/sight-leave-11316.json'
    context=json.loads(context_path.read_text('utf-8'));f={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(f.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    packet,archive,buffer,keys,visible=[h.scratch+n for n in (0x1000,0x2000,0x5000,0x10000,0x12000)]
    def require(ok,message):
        if not ok:raise ValueError(message)
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def number(at,width):return int.from_bytes(uc.mem_read(at,width),'little')
    def allocate(machine,target,storage,stride):
        count=reg('RDX');require(reg('RCX')==target and count<=64,'Sight storage bound/receiver')
        uc.mem_write(target,struct.pack('<QII',storage if count else 0,0,count));h.finish()
    h.add_fixture(0x14141cb60,lambda machine:allocate(machine,packet+0x10,keys,8))
    h.add_fixture(0x141437f60,lambda machine:allocate(machine,packet+0x20,visible,32))
    def clear(machine):
        require(reg('RCX')==0 and reg('RDX')==0,'Only empty previous sight storage supported');h.finish()
    h.add_fixture(0x1456b59f0,clear)
    def no_growth(machine):raise ValueError('Reserved sight storage exceeded')
    for at in (0x14141c080,0x141437520):h.add_fixture(at,no_growth)
    for table,offset,expected in [(0x1499225b8,0x20,(f['reader'],0x1456cf160)),
        (0x149924c90,0,(0x141b0aa50,0x1456d2030,f['keys_callback'])),
        (0x149924d50,0,(0x141b0aa50,f['visible_resize'],f['visible_callback'])),
        (0x149922570,0x20,(f['visible_reader'],))]:
        off=h.image.offset(table+offset-h.image.pe.base)
        require(struct.unpack_from('<'+'Q'*len(expected),h.raw,off)==expected,'Sight table binding differs')
    require(h.call(0x1456cf160)==302,'Sight packet ID differs')
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.sight_leave_event import decode_sight_leave_notify
    def attempt(body):
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x38)+b'\xa2'*16)
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        for at,stride in [(keys,8),(visible,32)]:uc.mem_write(at-16,b'\xa7'*16+b'\x5a'*(64*stride)+b'\xa8'*16)
        h.call(0x1456c0360,packet);require(number(packet,8)==0x1499225b8,'Sight constructor differs')
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(f['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(f['reader'],packet,budget=300000)&255)
        consumed=number(archive+0x30,8)-buffer;require(0<=consumed<=len(body),'Sight cursor outside input')
        for at,size,before,after in [(packet,0x38,b'\xa1',b'\xa2'),(archive,0x40,b'\xa3',b'\xa4'),
            (keys,64*8,b'\xa7',b'\xa8'),(visible,64*32,b'\xa7',b'\xa8')]:
            require(bytes(uc.mem_read(at-16,16))==before*16 and bytes(uc.mem_read(at+size,16))==after*16,'Sight frame/storage guards changed')
        require(bytes(uc.mem_read(buffer-16,len(body)+32))==b'\xa5'*16+body+b'\xa6'*16,'Sight input changed')
        if accepted:
            decoded=decode_sight_leave_notify(body[:consumed],source_sha256=h.sha)
            require(number(packet+0x18,4)==len(decoded.actor_keys) and number(packet+0x28,4)==len(decoded.quest_visible),'Sight array counts differ')
            require(tuple(number(keys+i*8,8) for i in range(len(decoded.actor_keys)))==decoded.actor_keys,'Sight keys differ')
            for i,record in enumerate(decoded.quest_visible):
                require(number(visible+i*32,8)==0x149922570,'Sight copied record table differs')
                require(struct.unpack('<QQQ',bytes(uc.mem_read(visible+i*32+8,24)))==record,'Sight visible fields differ')
            require(number(packet+0x30,1)==decoded.reason,'Sight reason clamp differs')
        return accepted,consumed
    cases=[]
    key_sets=[[],[0],[2**64-1],[1,1,2**63,2**64-1],list(range(64))]
    record_sets=[[],[(0,0,0)],[(2**64-1,2**63,1),(1,2,3),(1,4,5)]]
    for ks in key_sets:
        for rs in record_sets:
            for reason in (0,1,31,32,33,255):
                body=struct.pack('<H',len(ks))+b''.join(struct.pack('<Q',v) for v in ks)+struct.pack('<H',len(rs))+b''.join(struct.pack('<QQQ',*r) for r in rs)+bytes([reason])
                sizes=range(len(body)+1) if len(ks)<64 else sorted({0,1,2,len(ks)*8+2,len(body)//2,len(body)-1,len(body)})
                for size in sizes:
                    accepted,consumed=attempt(body[:size]);require(accepted==(size==len(body)),'Sight native prefix gate differs')
                    try:decoded=decode_sight_leave_notify(body[:size],source_sha256=h.sha)
                    except ValueError:decoded=None
                    require((decoded is not None)==accepted,'Sight portable prefix gate differs')
                    cases.append(dict(keys=len(ks),records=len(rs),reason=reason,size=size,accepted=accepted,consumed=consumed))
                accepted,consumed=attempt(body+b'\xff');require(accepted and consumed==len(body),'Sight native trailing behavior differs')
                try:decode_sight_leave_notify(body+b'\xff',source_sha256=h.sha)
                except ValueError:pass
                else:raise ValueError('Sight portable exact-size policy differs')
    report=dict(source_sha256=h.sha,exports=h.evidence,cases=cases,network_used=False,
        context_sha256=hashlib.sha256(context_path.read_bytes()).hexdigest(),tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Whole reader, native callbacks, visible record constructor/reader, generic vector and input execute together.',
            'Only empty previous storage with preallocated bounded arrays; allocation/growth and reuse are not proved.',
            'First array is raw actor keys; quest-visible triples remain separate, without field-name interpretation.',
            'No handler, actor deletion, world or live visibility claim. Portable exact-size policy is stricter than native.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/sight-leave-11316',report)
    return dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
