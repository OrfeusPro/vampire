"""Native ID110 scalar/text profiles, complementing nonempty container cases."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('select_fields_base',HERE/'replay-character-select-maps.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
native=base.native
PLAYER=((8,8),(16,8),(24,1),(48,4),(52,1),(56,4),(72,4),(76,1),
    (0x1e8,1),(0x1f0,8),(0x208,8),(0x210,8),(0x218,1),(0x230,8),(0x248,1),(0x260,1),(0x268,8),(0x270,8))
BLOCK=((8,8),(32,4),(0x38,8),(0x40,1),(0x50,8),(0x58,1))
ROOT=((0x2b0,8),(0x320,8),(0x348,1),(0x349,1))


def profile_body(text,code):
    data=bytearray(base.base.base.basic_body((1.5,-2.25,3.75),45,code))
    for offset in (4,12,79,89,97,108,122,130,141,149,171,180,189):struct.pack_into('<Q',data,offset,2**64-1-offset)
    for offset in (23,28,32,159):struct.pack_into('<I',data,offset,0xffffffff-offset)
    for offset in (20,27,36,37,49,50,78,105,118,121,138,179,188,201,202):data[offset]=255
    data[38:47]=bytes((0,1,2,127,128,129,253,254,255))
    struct.pack_into('<HHHH',data,163,0,65535,32768,1234)
    encoded=text.encode('utf-8')
    for offset in (199,197,157,47,21):data[offset:offset+2]=struct.pack('<H',len(encoded))+encoded
    return bytes(data)


class Emulator(base.Emulator):
    def read_fields(self,data):
        result=self.read_maps(data);packet=self.scratch+0x1000;player=packet+0x18;block=packet+0x2b8
        def raw(address,fields):return {hex(o):int.from_bytes(self.uc.mem_read(address+o,n),'little') for o,n in fields}
        def text(address):
            pointer,count,capacity=struct.unpack('<QII',bytes(self.uc.mem_read(address,16)))
            if not 0<=count<=capacity<=512:raise ValueError('Text profile output bound')
            return bytes(self.uc.mem_read(pointer,(count-1)*2)).decode('utf-16-le') if count else ''
        result['player_fields']=raw(player,PLAYER)
        result['appearance_fields']=raw(player+0x50,tuple((i,1) for i in range(8,18))+((0x28,1),(0x29,1)))
        result['block_fields']=raw(block,BLOCK);result['root_fields']=raw(packet,ROOT)
        result['four_u16']=[int.from_bytes(self.uc.mem_read(block+0x30+i*2,2),'little') for i in range(4)]
        result['outer290_flag']=int.from_bytes(self.uc.mem_read(packet+0x298,1),'little')
        result['texts']=[text(address) for address in (player+0x20,player+0x68,block+0x10,packet+0x328,packet+0x338)]
        return result


def build():
    em=Emulator();cases=[]
    for text,code in (('',0),('Profile',0x26),('Ж界🙂',0xffffffff)):
        data=profile_body(text,code);case=em.read_fields(data)
        if (case['returned'],case['consumed'],case['result_code'],case['texts'])!=(1,len(data),code,[text]*5):
            raise ValueError('Scalar/text native profile mismatch')
        cases.append(case)
    data=profile_body('Ж界🙂',0)
    cuts={0,1,2,3,len(data)-1};delta=0
    for offset in (21,47,157,197,199):
        start=offset+delta;length=len('Ж界🙂'.encode('utf-8'))
        cuts.update((start,start+1,start+2,start+3,start+2+length-1,start+2+length))
        delta+=length
    truncated=[em.read_fields(data[:n]) for n in sorted(cuts)]
    if any(c['returned'] for c in truncated):raise ValueError('Short text profile accepted')
    return dict(schema_version=1,source=em.bindings['source'],sha256=em.bindings['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency_sha256=hashlib.sha256((HERE/'replay-character-select-maps.py').read_bytes()).hexdigest(),
        cases=cases,truncated=truncated,native_execution=True,network_ready=False,
        limitations=['Actual whole native reader with nonzero scalar fields and empty/ASCII/BMP/emoji strings; containers stay empty/absent.',
            'Bounded allocation/cleanup and IO fixtures inherited from the map replay. No handler or live session.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/character-select-fields-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases']),truncated=len(report['truncated']))))
