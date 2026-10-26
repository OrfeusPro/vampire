"""Synthetic mixed SightEnter bodies; never a live packet capture."""
import importlib.util
from pathlib import Path
import struct


def bodies():
    path=Path(__file__).resolve().parents[2]/'test_vampir_sight_character_other_11316.py'
    spec=importlib.util.spec_from_file_location('character_fixture',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    def array(items):return struct.pack('<H',len(items))+b''.join(items)
    def text(value):
        data=value.encode('utf-8');return struct.pack('<H',len(data))+data
    def npc(key,rich):
        if not rich:return struct.pack('<Q',key)+bytes(103)
        count=2;label='Тест日本😀';maximum=2**64-1
        effects=[]
        for i in range(count):
            present=i%2
            effects.append(struct.pack('<QIIHHHQQQIB',i+1,0xffffffff,3,4,5,0xffff,7,8,9,10,present)
                +(struct.pack('<III',0x80000000,0x3f800000,0x7fc12345) if present else b'')+b'\xff')
        appearance=b'\xff'+bytes(range(1,10))+text(label)+b'\xff\xfe'+array([struct.pack('<IBH',1,45,65535),struct.pack('<IBH',0xffffffff,2,32768)])
        entries=array([struct.pack('<BBIIIQ',1,255,2,3,4,5),struct.pack('<BBIIIQ',17,1,6,7,8,9),struct.pack('<BBIIIQ',1,2,10,11,12,13)])
        return (struct.pack('<QIIIIBQQQBIQH',key,123,0x80000000,0x3f800000,0xc2f68000,255,4,5,6,255,7,8,count)
            +b''.join(effects)+b'\xff\xff\xff'+struct.pack('<QQ',21,22)+b'\xff'+appearance+b'\xff'+entries
            +array([struct.pack('<IQ',4,maximum),struct.pack('<IQ',5,100)])+struct.pack('<QQI',9,10,11)
            +array([struct.pack('<II',0x80000000,0x3f800000),struct.pack('<II',0x7fc12345,0xff800000)])
            +struct.pack('<Q',12)+b'\xff\xff'+struct.pack('<Q',maximum)+text(label)+struct.pack('<Q',14)
            +b'\xff'+struct.pack('<QQ',15,16)+b'\xff'+struct.pack('<II',0x80000000,13))
    def gadget(key,rich):
        if not rich:return struct.pack('<Q',key)+bytes(44)
        return (struct.pack('<QIIIIII BBBQIB',key,1,2,3,0x7fc12345,0x80000000,0x3f800000,255,255,255,2**63,0xffffffff,255)
            +array([struct.pack('<Q',key),bytes(8),struct.pack('<Q',key)])+b'\xff\xff'+struct.pack('<Q',key)+text('Владелец 🦇')+struct.pack('<QB',key,255))
    def mixed(count,rich,projectiles=True):
        keys=[42,2**64-1][:count]
        return (array([m.character_body(rich,key) for key in keys])+array([npc(key,rich) for key in keys])
            +array([struct.pack('<Q',key)+bytes(41)+b'\xff' for key in keys])+array([gadget(key,rich) for key in keys])
            +(b'\xff'+array([struct.pack('<H',65535)+bytes(63) for _ in keys]) if projectiles else b'\0')
            +array([struct.pack('<Q',key)+bytes(57)+b'\xff' for key in keys])+b'\xff')
    return [bytes(12),bytes(8)+b'\xff'+bytes(5),mixed(1,False,False),mixed(2,False),mixed(2,True),mixed(1,True)]
