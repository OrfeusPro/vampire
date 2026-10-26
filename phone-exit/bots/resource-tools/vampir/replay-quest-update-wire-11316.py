"""Current whole QuestUpdate output/input with real archive IO; no game socket."""
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
from vampir_core.quest_update import QuestUpdate,encode_quest_update,decode_quest_update
from vampir_core.world_move_start import SOURCE_SHA256 as HISTORICAL_SOURCE


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    path=HERE/'knowledge/native-contexts/quest-update-wire-11316.json'
    context=json.loads(path.read_text('utf-8'));functions={k:int(v,16) for k,v in context['functions'].items()}
    def make():
        return load('native-request-harness-11316').make_harness(context['exports'],set(functions.values()),
            leaves={int(k,16):v for k,v in context['leaves'].items()})
    h=make();uc,x,base=h.uc,h.x,h.scratch
    packet,output,buffer,input_archive,input_buffer=[base+n for n in (0x1000,0x2000,0x3000,0x4000,0x5000)]
    out_table,in_table,packet_table=[int(context[key],16) for key in ('output_table','input_table','packet_table')]
    off=h.image.offset(out_table-h.image.pe.base)
    if hashlib.sha256(h.raw[off:off+0xf8]).hexdigest()!=context['output_table_sha256']:raise ValueError('Output table differs')
    bindings=[(out_table,slot,target) for slot,target in ((0x48,functions['output_u64']),(0xa8,functions['output_float']),
        (0xb8,functions['output_u64']),(0xe8,functions['output_u8']),(0x88,functions['output_raw']))]
    bindings+=[(in_table,slot,target) for slot,target in ((0x40,functions['input_float']),(0x50,functions['input_u64']),
        (0x80,0x144aac240),(0x90,functions['input_raw']))]
    bindings+=[(packet_table,0x10,functions['writer']),(packet_table,0x20,functions['reader']),(packet_table,0x28,0x145834490)]
    for table,slot,target in bindings:
        if struct.unpack_from('<Q',h.raw,h.image.offset(table+slot-h.image.pe.base))[0]!=target:
            raise ValueError('Quest update typed binding differs')
    def growth(machine):raise ValueError('Output growth excluded from bounded replay')
    h.add_fixture(int(context['output_growth'],16),growth)
    def reg(name):return uc.reg_read(getattr(x,'UC_X86_REG_'+name))
    def number(at,size=8):return int.from_bytes(uc.mem_read(at,size),'little')
    def construct():
        uc.mem_write(packet-16,b'\xa1'*16+b'\xa5'*64+b'\xa2'*16)
        if h.call(0x145828b00,packet)!=packet or number(packet)!=packet_table or h.call(0x145834490,packet)!=1810:
            raise ValueError('Actual QuestUpdate constructor/ID differs')
        if bytes(uc.mem_read(packet+0x10,24))!=b'\xa5'*24 or bytes(uc.mem_read(packet+0x28,17))!=bytes(17):
            raise ValueError('QuestUpdate constructor defaults differ')
    def output_reset():
        uc.mem_write(output-16,b'\xb1'*16+b'\xcc'*64+b'\xb2'*16)
        uc.reg_write(x.UC_X86_REG_RDX,1)
        if h.call(functions['output_constructor'],output)!=output or number(output)!=out_table:
            raise ValueError('Native output constructor differs')
        uc.mem_write(output+0x18,struct.pack('<QQQ',buffer,buffer,buffer+128))
        uc.mem_write(output+0x30,struct.pack('<III',128,0,0))
        uc.mem_write(buffer-16,b'\xc1'*16+b'\x5a'*128+b'\xc2'*16)
    def input_read(body):
        uc.mem_write(input_archive-16,b'\xd1'*16+bytes(64)+b'\xd2'*16)
        h.call(functions['input_constructor'],input_archive)
        if number(input_archive)!=in_table:raise ValueError('Native input constructor differs')
        uc.mem_write(input_archive+0x20,struct.pack('<QI',input_buffer,len(body)))
        uc.mem_write(input_archive+0x30,struct.pack('<Q',input_buffer))
        uc.mem_write(input_buffer-16,b'\xe1'*16+body+b'\xe2'*16)
        uc.reg_write(x.UC_X86_REG_RDX,input_archive)
        accepted=bool(h.call(functions['reader'],packet)&255)
        consumed=number(input_archive+0x30)-input_buffer
        if not 0<=consumed<=len(body):raise ValueError('Quest mirror cursor exceeded body')
        for at,expected in ((input_archive-16,b'\xd1'*16),(input_archive+64,b'\xd2'*16),
                (input_buffer-16,b'\xe1'*16),(input_buffer+len(body),b'\xe2'*16),
                (packet-16,b'\xa1'*16),(packet+64,b'\xa2'*16)):
            if bytes(uc.mem_read(at,16))!=expected:raise ValueError('Quest input guard changed')
        return accepted,consumed
    cases=[]
    vectors=((0.,0.,0.),(1.,-2.5,3.25),(-0.,1.1754943508222875e-38,3.4028234663852886e38),(90049.,151840.,-44.))
    values=[QuestUpdate(vector,key,key^0xffffffffffffffff,flag) for vector in vectors
        for key in (0,1,110120,0x8000000000000000,0xffffffffffffffff) for flag in (0,1,2,255)]
    values.append(QuestUpdate((90049.,151840.,-44.),0,110120,0))
    for value in values:
        construct();output_reset()
        native_fields=struct.pack('<dddQQB',*value.vector,value.raw28,value.raw30,value.raw38)
        uc.mem_write(packet+0x10,native_fields);before=bytes(uc.mem_read(packet-16,96))
        uc.reg_write(x.UC_X86_REG_RDX,output)
        if h.call(functions['writer'],packet)&255!=1:raise ValueError('Whole current writer failed')
        expected=struct.pack('<fffQQB',*value.vector,value.raw28,value.raw30,value.raw38)
        if struct.unpack('<II',uc.mem_read(output+0x34,8))!=(29,29):raise ValueError('Output counters differ')
        if bytes(uc.mem_read(buffer-16,160))!=b'\xc1'*16+expected+b'\x5a'*99+b'\xc2'*16:
            raise ValueError('Native packet bytes or output guard differ')
        if bytes(uc.mem_read(packet-16,96))!=before:raise ValueError('Packet mutated by writer')
        if bytes(uc.mem_read(output-16,16))!=b'\xb1'*16 or bytes(uc.mem_read(output+64,16))!=b'\xb2'*16:
            raise ValueError('Output archive guard changed')
        for source in (HISTORICAL_SOURCE,h.sha):
            if encode_quest_update(value,source_sha256=source)!=expected:raise ValueError('Portable writer differs')
        portable=decode_quest_update(expected,source_sha256=h.sha)
        construct()
        if input_read(expected)!=(True,29):raise ValueError('Whole current mirror failed')
        wanted=struct.pack('<dddQQB',*portable.vector,portable.raw28,portable.raw30,portable.raw38)
        if bytes(uc.mem_read(packet+0x10,41))!=wanted:raise ValueError('Mirror object differs')
        cases.append(dict(body_hex=expected.hex()))
    short=[]
    for size in range(29):
        construct();accepted,consumed=input_read(bytes(size))
        if accepted:raise ValueError('Quest mirror accepted short prefix')
        short.append(dict(size=size,consumed=consumed))
    # Separate harness: only failure cases replace raw IO with a bounded fixture.
    failing=make();widths=[];fail_at=[0]
    def raw_failure(machine):
        width=failing.uc.reg_read(failing.x.UC_X86_REG_R8)
        if width not in (1,4,8):raise ValueError('Raw output width differs')
        accepted=len(widths)!=fail_at[0];widths.append(width);failing.finish(int(accepted))
    failing.add_fixture(functions['output_raw'],raw_failure)
    failures=[]
    for index in range(6):
        fail_at[0]=index;widths.clear()
        failing.uc.mem_write(packet,bytes(64));failing.call(0x145828b00,packet)
        failing.uc.mem_write(output,struct.pack('<Q',out_table));failing.uc.reg_write(failing.x.UC_X86_REG_RDX,output)
        if failing.call(functions['writer'],packet)&255 or widths!=[4,4,4,8,8,1][:index+1]:
            raise ValueError('Current writer did not stop on raw failure')
        failures.append(dict(index=index,widths=widths.copy()))
    audit=load('audit-client-release')
    report=dict(source_sha256=h.sha,tool_sha256=audit.sha256(Path(__file__)),context_sha256=audit.sha256(path),
        native_execution=True,network_used=False,exports=h.evidence,cases=cases,short_prefixes=short,writer_failures=failures,
        limits=['Whole packet constructor/getter/writer/mirror, vector/scalar helpers, actual input/output constructors and raw archive IO execute.',
            'Preallocated 128-byte output; growth rejected; memcpy is bounded fixture. Endian swap paths excluded.',
            'Failure cases use a separate explicit raw IO fixture; no network, HUD, active task or server result.',
            'Portable codec admits only the two reviewed full source hashes; action permission remains separate.'])
    return audit.save_snapshot(h.root/'code-clues/quest-update-wire-11316',report),report


if __name__=='__main__':
    path,report=run();print(json.dumps(dict(report=str(path),cases=len(report['cases']),short=len(report['short_prefixes']))))
