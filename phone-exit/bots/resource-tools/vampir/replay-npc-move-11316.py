"""Whole NPC move notify/data readers on one memory; bounded array storage."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify():
    context=json.loads((HERE/'knowledge/native-contexts/npc-move-11316.json').read_text('utf-8'))
    functions={k:int(v,16) for k,v in context['functions'].items()}
    h=load('native-request-harness-11316').make_harness(context['exports'],set(functions.values()),
        leaves={int(k,16):v for k,v in context['leaves'].items()})
    uc,x=h.uc,h.x
    packet,archive,buffer,storage=[h.scratch+n for n in (0x1000,0x2000,0x5000,0x10000)]
    target=None
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def number(at,size):return int.from_bytes(uc.mem_read(at,size),'little')
    def resize(machine):
        count=reg('R8')
        if reg('RDX')!=target or count>128:raise ValueError('NPC storage fixture bounds')
        uc.mem_write(target,struct.pack('<QII',storage if count else 0,0,count))
        uc.mem_write(storage-16,b'\xa7'*16+b'\x5a'*(16*128)+b'\xa8'*16);h.finish()
    def clear(machine):
        if reg('RCX')!=0 or reg('RDX')!=0:raise ValueError('Only empty previous NPC storage is fixture')
        h.finish()
    h.add_fixture(0x1456ba460,resize)
    h.add_fixture(0x1456b59c0,clear)
    h.add_fixture(0x1456b66c0,lambda machine:h.finish())
    sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
    from vampir_core.npc_move_event import decode_npc_move_notify,decode_npc_move_data
    # Table links are checked against the same immutable PE, not role names.
    for table,offset,expected in ((0x149922080,0x20,(functions['reader'],)),
            (0x149924cc0,0,(0x141b0aa50,0x1456ba460,functions['callback'])),
            (0x149920910,0x20,(functions['record'],))):
        off=h.image.offset(table+offset-h.image.pe.base)
        if struct.unpack_from('<'+'Q'*len(expected),h.raw,off)!=expected:raise ValueError('NPC table binding differs')
    getter=h.image.offset(0x1456cf0f0-h.image.pe.base)
    if h.raw[getter:getter+6]!=b'\xb8\x45\x01\x00\x00\xc3':raise ValueError('NPC packet ID getter differs')
    cases=[]
    samples=[[],[(0x3f800000,0xc2f68000)],[(0,0x80000000),(0x7f800000,0xff800000),(0x7fc12345,0x3f800000)],[(i,0x3f800000+i) for i in range(64)]]
    def attempt(body,reader):
        uc.mem_write(packet-16,b'\xa1'*16+bytes(0x80)+b'\xa2'*16)
        if reader=='reader':
            h.call(0x1456c0230,packet)
            if number(packet,8)!=0x149922080 or h.call(0x1456cf0f0,packet)!=325:raise ValueError('NPC native constructor/getter differs')
        uc.mem_write(archive-16,b'\xa3'*16+bytes(0x40)+b'\xa4'*16)
        uc.mem_write(buffer-16,b'\xa5'*16+body+b'\xa6'*16)
        uc.reg_write(x.UC_X86_REG_RDX,buffer);uc.reg_write(x.UC_X86_REG_R8,len(body));uc.reg_write(x.UC_X86_REG_R9,1)
        uc.mem_write(h.scratch+0x38028,bytes(8));h.call(functions['input_constructor'],archive)
        uc.reg_write(x.UC_X86_REG_RDX,archive)
        accepted=bool(h.call(functions[reader],packet,budget=300000)&255)
        if bytes(uc.mem_read(packet-16,16))!=b'\xa1'*16 or bytes(uc.mem_read(packet+0x80,16))!=b'\xa2'*16:raise ValueError('NPC packet guards changed')
        if bytes(uc.mem_read(buffer-16,len(body)+32))!=b'\xa5'*16+body+b'\xa6'*16:raise ValueError('NPC input changed')
        if number(archive+0x30,8)-buffer>len(body):raise ValueError('NPC read exceeded input')
        return accepted
    for reader,decoder in (('reader',decode_npc_move_notify),('data_reader',decode_npc_move_data)):
        target=packet+(0x28 if reader=='reader' else 8)
        headings=[(key,bits) for key in (0,1,2**63,2**64-1) for bits in (0,0x80000000,0x3f800000,0xc2f68000,0x7f800000,0x7fc12345)] if reader=='reader' else [(None,None)]
        for records in samples:
            for key,bits in headings:
                prefix=struct.pack('<QII',key,bits,0x43800000) if key is not None else b''
                body=prefix+struct.pack('<H',len(records))+b''.join(struct.pack('<II',*r) for r in records)
                sizes=range(len(body)+1) if len(records)<64 else sorted({0,1,len(prefix),len(prefix)+1,len(prefix)+2,len(body)//2,len(body)-1,len(body)})
                for size in sizes:
                    accepted=attempt(body[:size],reader)
                    if accepted!=(size==len(body)):raise ValueError('NPC native prefix gate differs')
                    try:portable=decoder(body[:size],source_sha256=h.sha)
                    except ValueError:portable=None
                    if (portable is not None)!=accepted:raise ValueError('NPC portable prefix gate differs')
                    if accepted:
                        count=number(target+8,4);pointer=number(target,8)
                        actual=[]
                        if count!=len(records):raise ValueError('NPC native count differs')
                        for i in range(count):
                            at=pointer+16*i
                            if number(at,8)!=0x149920910:raise ValueError('NPC copied table differs')
                            actual.append(struct.unpack('<II',bytes(uc.mem_read(at+8,8))))
                        if actual!=records:raise ValueError('NPC record bits differ')
                        values=portable.records if reader=='reader' else portable
                        if [pair.bits for pair in values]!=records:raise ValueError('NPC portable records differ')
                        if reader=='reader':
                            if portable.entity_key!=number(packet+0x10,8) or portable.entity_key!=key:raise ValueError('NPC key differs')
                            actual_xy=struct.unpack('<dd',bytes(uc.mem_read(packet+0x18,16)))
                            expected_xy=struct.unpack('<ff',body[8:16])
                            for a,b in zip(actual_xy,expected_xy):
                                if math.isnan(b):
                                    if not math.isnan(a):raise ValueError('NPC NaN differs')
                                elif struct.pack('<d',a)!=struct.pack('<d',b):raise ValueError('NPC widened float differs')
                            if portable.xy.bits!=(bits,0x43800000):raise ValueError('NPC portable XY bits differ')
                        if bytes(uc.mem_read(storage-16,16))!=b'\xa7'*16 or bytes(uc.mem_read(storage+16*128,16))!=b'\xa8'*16:raise ValueError('NPC storage guards changed')
                    cases.append(dict(reader=reader,records=len(records),key=key,bits=bits,size=size,accepted=accepted))
                if not attempt(body+b'\xff',reader):raise ValueError('Native NPC trailing behavior changed')
                try:decoder(body+b'\xff',source_sha256=h.sha)
                except ValueError:pass
                else:raise ValueError('Portable NPC exact-size policy weakened')
    report=dict(source_sha256=h.sha,exports=h.evidence,cases=cases,network_used=False,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limits=['Whole outer and nested readers, generic array, callback, record leaf constructor, record reader and archive execute on one memory.',
            'Zero previous storage; array allocation and empty temporary destruction are fixtures. No growth, reuse or engine application.',
            'Smaller arrays test every prefix; 64 records use selected boundaries. No live NPC packet or actor/world/map semantics proved.',
            'Wire float bits retained, nonfinite values require explicit rejection before use; trailing-byte rejection is stricter than native.'])
    path=load('audit-client-release').save_snapshot(h.root/'code-clues/npc-move-11316',report)
    return dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(cases))


if __name__=='__main__':print(json.dumps(verify()))
