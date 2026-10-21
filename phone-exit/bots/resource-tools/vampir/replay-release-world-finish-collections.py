"""Whole current ID206 with actual collection callbacks; bounded storage only."""
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent


def load():
    spec=importlib.util.spec_from_file_location('finish_empty',HERE/'replay-release-world-finish-reader.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def make_harness():
    base=load()
    h=base.make_harness(extra_addresses=(0x1456b8c90,0x145822fd0,0x14573e510,
        0x14578b5e0,0x14578aee0,0x1457a9240,0x145793520,0x145787460,
        0x1456b8330,0x1457a6e30,0x145790980,0x1457a3800),
        extra_leaves=(0x145821190,0x1457a45a0))
    evidence='details/run-51479638a879/details.json'
    sha='eddff675aa0f11c8f581f901a76f5f00bf83b109f092b303c79aa2a6775c567a'
    if h.audit.sha256(h.comparison/evidence)!=sha:raise ValueError('Collection evidence changed')
    h.finish_evidence[evidence]=sha
    # Leaf extraction accepts only mov/lea/xor followed by ret/jmp, from pinned EXE bytes.
    bindings={0x149923b40:0x1457a9240,0x149923a78:0x145793520,
        0x1499239f8:0x145787460,0x149921b30:0x1456b8330,
        0x1499239d0:0x1456b8330,0x149923990:0x1457a6e30,0x1499222e8:0x145822fd0}
    for table,reader in bindings.items():
        off=h.image.offset(table-h.image.pe.base)
        if struct.unpack_from('<Q',h.raw,off+0x20)[0]!=reader:raise ValueError('Collection vtable changed')
        h.map_finish_page(table&~4095)
    uc,x=h.uc,h.x
    for address,stride in ((0x1456bb670,0x18),(0x14578c440,0x70),
            (0x14578c2c0,0x78),(0x1456bb650,4)):
        def resize(machine,stride=stride):
            container=machine.reg_read(x.UC_X86_REG_RDX)
            count=machine.reg_read(x.UC_X86_REG_R8)&65535
            if count>256 or bytes(machine.mem_read(container,16))!=bytes(16):
                raise ValueError('Collection storage requires fresh bounded container')
            pointer=h.allocate(count*stride) if count else 0
            machine.mem_write(container,struct.pack('<QII',pointer,0,count))
            h.finish()
        h.fixtures[address]=resize
    for address in (0x1456b7990,0x145791cb0,0x1457a4b00):
        h.map_finish_page(address&~4095)
        def cleanup(machine):
            pointer=machine.reg_read(x.UC_X86_REG_RCX)
            if not h.scratch<=pointer<h.scratch+0x40000:raise ValueError('Temporary cleanup storage bound')
            h.finish()
        h.fixtures[address]=cleanup
    h.collection_bindings=bindings
    return h


def body_bytes(*,counts=(1,1,1,1),present=255):
    base=load().body_bytes(heading=45)
    # Minimal appearance, including its empty extension count, ends at byte 53.
    prefix=base[:53]
    b8,c8,e8,u32=counts
    out=bytearray(prefix)
    out.extend(struct.pack('<H',b8))
    for i in range(b8):out.extend(struct.pack('<IQ',0x80000000+i,0xfedcba9876543210-i))
    out.extend(struct.pack('<H',c8))
    for i in range(c8):
        flag=present if i%2==0 else 0
        out.extend(struct.pack('<QIIHHHQQQIB',7+i,0xffffffff,123+i,65535,2,3,8,9,10,11,flag))
        if flag:out.extend(struct.pack('<III',0x80000000,0x3fc00000,0xc0100000))
        out.append(255 if i%2==0 else 0)
    out.extend(struct.pack('<QH',0xfedcba9876543210,e8))
    for i in range(e8):
        flag=present if i%2==0 else 0
        out.extend(struct.pack('<BIQQB',255,101+i,12,13,flag))
        if flag:out.extend(struct.pack('<fffB',-0.0,1.5,-2.25,45))
    out.extend(struct.pack('<HH',65535,u32))
    for i in range(u32):out.extend(struct.pack('<I',0xffffffff-i))
    out.extend(struct.pack('<QBB',7,255,255))
    return bytes(out)


def compare(h,body):
    base=load();value=base.decode_world_move_finish_result(body,max_payload_size=4096,max_collection_items=1024)
    accepted,consumed=h.read_finish(body)
    if (accepted,consumed)!=(1,len(body)):raise ValueError('Collection whole-reader acceptance differs')
    packet=h.finish_packet;uc=h.uc
    def n(p,size):return int.from_bytes(uc.mem_read(p,size),'little')
    counts={}
    for off,stride,fields in ((0xb8,0x18,((8,4),(16,8))),
            (0xc8,0x70,((8,8),(16,4),(20,4),(24,2),(26,2),(28,2),(32,8),(40,8),
                (48,8),(56,4),(72,1),(88,4),(92,4),(96,4),(104,1))),
            (0xe8,0x78,((8,1),(12,4),(16,8),(24,8),(40,1))),
            (0x100,4,())):
        pointer,count,capacity=struct.unpack('<QII',uc.mem_read(packet+off,16))
        expected=value.data.at(off)
        if not count==capacity==len(expected):raise ValueError('Collection length differs')
        counts[hex(off)]=count
        for i,item in enumerate(expected):
            p=pointer+i*stride
            if off==0x100:
                if n(p,4)!=item:raise ValueError('u32 item differs')
                continue
            for field,width in fields:
                if n(p+field,width)!=item.at(field):raise ValueError('Collection field differs: '+hex(off)+'/'+hex(field))
            if off==0xe8 and item.at(0x28):
                spatial=item.at(0x30)
                if bytes(uc.mem_read(p+0x38,24))!=struct.pack('<ddd',*spatial.at(8).finite_values()):
                    raise ValueError('Nested spatial vector differs')
                if n(p+0x58,1)!=n(packet+0x50,1):raise ValueError('Nested native heading differs')
    if bytes(uc.mem_read(packet+0x30,24))!=struct.pack('<ddd',*value.data.at(0x30).finite_values()):
        raise ValueError('Main vector displaced')
    if (n(packet+0xf8,2),n(packet+0x110,8),n(packet+0x118,1),n(packet+0x119,1))!=(65535,7,100,1):
        raise ValueError('Tail displaced')
    return dict(body_hex=body.hex(),counts=counts,consumed=consumed,fields_match=True)


def run():
    h=make_harness();cases=[]
    for counts in ((1,0,0,0),(0,1,0,0),(0,0,1,0),(0,0,0,1),(1,1,1,1),
            (2,2,2,2),(8,8,8,8),(205,0,1,0)):
        for present in (0,1,255):cases.append(compare(h,body_bytes(counts=counts,present=present)))
    short=[];body=body_bytes(counts=(2,2,2,2))
    for size in range(len(body)):
        accepted,consumed=h.read_finish(body[:size])
        if accepted or consumed>size:raise ValueError('Short collection body accepted or overconsumed')
        short.append(dict(size=size,consumed=consumed))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),
        evidence=h.finish_evidence,fragments=h.fragments,leaves=h.leaves,
        math_provenance_sha256=h.audit.sha256(h.finish_math_path),math_ranges=h.finish_math['ranges'],
        crt=dict(path=str(h.crt_path),sha256=h.audit.sha256(h.crt_path)),math_imports=h.math_imports,
        collection_bindings={hex(k):hex(v) for k,v in h.collection_bindings.items()},
        cases=cases,short=short,native_execution=True,network_used=False,
        limits=['Whole current ID206 reader, collection callbacks and nested readers execute.',
            'Fresh bounded storage and temporary cleanup are fixtures; allocator growth/reuse are not tested.',
            'Raw optional float bits and converted finite vectors are compared; heading canonicalization is native.',
            'Synthetic bodies include reference collection counts, not private live payloads.',
            'No handler, world readiness, live position or game IO.'])
    path=h.audit.save_snapshot(h.comparison/'world-finish-collections-replay',report)
    return path,h.audit.sha256(path),len(cases),len(short)


if __name__=='__main__':
    path,sha,cases,short=run()
    print(json.dumps(dict(report=str(path),sha256=sha,cases=cases,short=short)))
