"""Current whole ID206 reader with native heading math and bounded storage."""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
from vampir_core.world_move_finish_result import decode_world_move_finish_result


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def make_harness(*,extra_addresses=(),extra_leaves=()):
    base=load('finish_release_list',HERE/'replay-release-character-list.py')
    addresses=(0x14584db80,0x1458503f0,0x1458233c0,0x144aae290,0x144aad640,
        0x1456b6290,0x14150b140,0x14150d410,*extra_addresses)
    h=base.make_harness(extra_addresses=addresses,
        extra_leaves=(0x1458212d0,0x1457846f0,0x145759170,*extra_leaves),max_appearance=4)
    evidence={
        'details/run-a74c5869b659/details.json':'4615a07bcfe85b5213cd0ecbaeffb4f7245cd48376fe5851c6a900add93f5bda',
        'details/run-7b00263d9ea5/details.json':'a26a06673aa07711ee50369ba26d041ba842100e4d73d8650e764507c9e74a15',
        'details/run-6770206293df/details.json':'57e40960e63a98b055597bb81e0852d56ce006fface292766546c6abfb1562e6'}
    for relative,expected in evidence.items():
        if h.audit.sha256(h.comparison/relative)!=expected:raise ValueError('ID206 reader evidence changed')
    math_path=h.comparison/'math/run-538e7d34a845/provenance.json'
    if h.audit.sha256(math_path)!='0d82836493f153423f9d8ac800f5b1b262412445528ccf792d2dd30843a37339':
        raise ValueError('Current math discovery changed')
    math_report=json.loads(math_path.read_text('utf-8'))
    if math_report['source_sha256']!=h.sha:raise ValueError('Math source differs')
    for name,sha in math_report['files'].items():
        if h.audit.sha256(math_path.parent/name)!=sha:raise ValueError('Math material changed')
    uc,x=h.uc,h.x
    def map_page(page):
        if any(lo<=page<=hi for lo,hi,_ in uc.mem_regions()):return
        uc.mem_map(page,4096)
        try:off=h.image.offset(page-h.image.pe.base)
        except ValueError:return
        uc.mem_write(page,h.raw[off:off+4096])
    cs=h.env.capstone.Cs(h.env.capstone.CS_ARCH_X86,h.env.capstone.CS_MODE_64);cs.detail=True
    for r in math_report['ranges']:
        start,end=r['start'],r['end'];raw=h.raw[r['file_offset']:r['file_offset']+end-start]
        if hashlib.sha256(raw).hexdigest()!=r['sha256']:raise ValueError('Math range bytes changed')
        h.ranges.append((start,end))
        for page in range(start&~4095,(end+4095)&~4095,4096):map_page(page)
        for instruction in cs.disasm(raw,start):
            for operand in instruction.operands:
                if operand.type==h.env.capstone.x86.X86_OP_MEM and operand.mem.base==h.env.capstone.x86.X86_REG_RIP:
                    map_page((instruction.address+instruction.size+operand.mem.disp)&~4095)
    crt_path=Path(os.environ['SystemRoot'])/'System32/ucrtbase.dll'
    crt=ctypes.CDLL(str(crt_path));math_imports={}
    for address,name in ((0x1487f7afd,'fmod'),(0x1487f7af7,'atan2')):
        off=h.image.offset(address-h.image.pe.base)
        if h.raw[off:off+2]!=b'\xff\x25':raise ValueError('Math import thunk changed')
        slot=address+6+struct.unpack_from('<i',h.raw,off+2)[0]
        imported=h.imports.import_at(h.raw,h.image,slot)
        if (imported['dll'].lower(),imported['name'])!=('api-ms-win-crt-math-l1-1-0.dll',name):
            raise ValueError('Unverified CRT math import')
        function=getattr(crt,name);function.argtypes=(ctypes.c_double,ctypes.c_double);function.restype=ctypes.c_double
        def fixture(machine,fn=function):
            values=[struct.unpack('<d',(machine.reg_read(reg)&(2**64-1)).to_bytes(8,'little'))[0]
                for reg in (x.UC_X86_REG_XMM0,x.UC_X86_REG_XMM1)]
            value=fn(*values)
            machine.reg_write(x.UC_X86_REG_XMM0,int.from_bytes(struct.pack('<d',value),'little'))
            h.finish()
        map_page(address&~4095);h.fixtures[address]=fixture;math_imports[name]=imported
    # Fresh packet cleanup only. Empty arrays do not require allocation fixtures.
    cleanup=(0x1456b6c60,0x1456bdee0,0x1456bdbf0)
    for address in cleanup:
        def fixture(machine):
            if machine.reg_read(x.UC_X86_REG_RDX)&0xffffffff:
                raise ValueError('Only fresh ID206 cleanup is supported')
            h.finish()
        map_page(address&~4095);h.fixtures[address]=fixture
    empty_resize=(0x1456bb670,0x14578c440,0x14578c2c0,0x1456bb650)
    for address in empty_resize:
        def fixture(machine):
            if machine.reg_read(x.UC_X86_REG_R8)&65535:
                raise ValueError('Nonempty ID206 resize outside initial profile')
            container=machine.reg_read(x.UC_X86_REG_RDX)
            if bytes(machine.mem_read(container,16))!=bytes(16):
                raise ValueError('Only fresh empty ID206 containers are supported')
            h.finish()
        map_page(address&~4095);h.fixtures[address]=fixture
    packet=h.scratch+0x10000
    off=h.image.offset(0x14996d500-h.image.pe.base)
    if struct.unpack_from('<QQ',h.raw,off+0x20)!=(0x1458503f0,0x145759170):
        raise ValueError('Current ID206 reader/getter binding differs')
    if h.call(0x145759170,packet)!=206:raise ValueError('Current packet getter differs')
    def read(body):
        if len(body)>4096:raise ValueError('ID206 synthetic body bound')
        h.string_heap[0]=h.scratch+0x20000
        uc.mem_write(packet,bytes(0x200));h.call(0x14584db80,packet)
        uc.mem_write(h.buffer,bytes(4096))
        if body:uc.mem_write(h.buffer,body)
        h.call(h.ctor,h.obj)
        uc.mem_write(h.obj+0x20,struct.pack('<QI',h.buffer,len(body)))
        uc.mem_write(h.obj+0x30,struct.pack('<Q',h.buffer))
        try:accepted=h.call(0x1458503f0,packet,h.obj,budget=100000)&255
        except h.env.unicorn.UcError as error:
            raise ValueError('ID206 memory fault at '+hex(uc.reg_read(x.UC_X86_REG_RIP))) from error
        consumed=int.from_bytes(uc.mem_read(h.obj+0x30,8),'little')-h.buffer
        return accepted,consumed
    h.read_finish=read;h.finish_packet=packet;h.finish_evidence=evidence;h.map_finish_page=map_page
    h.finish_math_path=math_path;h.finish_math=math_report;h.crt_path=crt_path;h.math_imports=math_imports
    return h


def body_bytes(*,code=0,kind=0,text='',heading=0):
    encoded=text.encode('utf-8')
    appearance=bytes([255])+bytes(range(9))+struct.pack('<H',len(encoded))+encoded+bytes([255,255])+bytes(2)
    return (struct.pack('<IQIIBBfffBBB',code,0x123456789abcdef,0xffffffff,0x89abcdef,255,kind,
        1.5,-2.25,-0.0,heading,kind,255)+appearance+bytes(4)+struct.pack('<QHHH',
        0xfedcba9876543210,0,65535,0)+struct.pack('<QBB',7,kind,255))


def run():
    h=make_harness();uc=h.uc;packet=h.finish_packet
    cases=[]
    for text in ('','ASCII','Ж界🙂'):
        for code in (0,16,0xffffffff):
            for kind in (0,255):
                body=body_bytes(code=code,kind=kind,text=text,heading=45)
                accepted,consumed=h.read_finish(body)
                value=decode_world_move_finish_result(body,max_payload_size=4096,max_collection_items=4)
                if (accepted,consumed)!=(1,len(body)):raise ValueError('Whole ID206 acceptance differs')
                fields={}
                for off,size in ((0x10,4),(0x18,8),(0x20,4),(0x24,4),(0x28,1),(0x29,1),
                        (0x70,1),(0x71,1),(0xe0,8),(0xf8,2),(0x110,8),(0x118,1),(0x119,1)):
                    actual=int.from_bytes(uc.mem_read(packet+off,size),'little')
                    expected=value.result_code if off==0x10 else value.data.at(off)
                    if actual!=expected:raise ValueError('ID206 scalar differs')
                    fields[hex(off)]=actual
                vector=bytes(uc.mem_read(packet+0x30,24)).hex()
                if vector!=struct.pack('<ddd',*value.data.at(0x30).finite_values()).hex():
                    raise ValueError('ID206 vector differs')
                ptr,count,cap=struct.unpack('<QII',uc.mem_read(packet+0x90,16))
                native_text=bytes(uc.mem_read(ptr,(count-1)*2)).decode('utf-16le') if count else ''
                if native_text!=text:raise ValueError('ID206 appearance text differs')
                cases.append(dict(body_hex=body.hex(),fields=fields,vector_hex=vector,text_matches=True))
    short=[];body=body_bytes()
    for size in range(len(body)):
        accepted,consumed=h.read_finish(body[:size])
        if accepted or consumed>size:raise ValueError('Short ID206 accepted or overconsumed')
        short.append(dict(size=size,consumed=consumed))
    heading=[]
    for value in range(256):
        accepted,consumed=h.read_finish(body_bytes(heading=value))
        if (accepted,consumed)!=(1,len(body)):raise ValueError('Heading ID206 failed')
        heading.append(dict(wire=value,native=uc.mem_read(packet+0x50,1)[0]))
    report=dict(source_sha256=h.sha,tool_sha256=h.audit.sha256(Path(__file__)),
        packet_id=206,evidence=h.finish_evidence,math_provenance_sha256=h.audit.sha256(h.finish_math_path),
        math_ranges=h.finish_math['ranges'],crt=dict(path=str(h.crt_path),sha256=h.audit.sha256(h.crt_path)),
        math_imports=h.math_imports,fragments=h.fragments,leaves=h.leaves,
        cases=cases,short=short,heading=heading,native_execution=True,network_used=False,
        limits=['Whole current ID206 constructor/reader, vector/heading/appearance/time and scalar readers execute.',
            'Current native math ranges execute; imported fmod/atan2 use the recorded local ucrtbase DLL.',
            'Packet/input storage, fresh empty container cleanup/resize and FString allocation are bounded fixtures.',
            'Initial profile has empty arrays; nonempty collection callbacks are not yet covered.',
            'No handler, world state, position application, account or network IO.'])
    path=h.audit.save_snapshot(h.comparison/'world-finish-reader-replay',report)
    return path,h.audit.sha256(path)


if __name__=='__main__':
    path,sha=run();print(json.dumps(dict(report=str(path),sha256=sha,cases=18,heading=256)))
