"""Whole CharacterOther plus one cursor/budget over nested and successive records."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_character_other import SOURCE_SHA256,decode_character_other
from vampir_core.current_record_reader import CurrentRecordReader

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def character_body(rich=False,key=2**64-1):
    def text(value):
        data=value.encode('utf-8');return struct.pack('<H',len(data))+data
    count=1 if rich else 0
    appearance=b'\xff'+bytes(range(1,10))+text('Внешность 🦇' if rich else '')+b'\xff\xfe'+struct.pack('<H',count)
    if rich:appearance+=struct.pack('<IBH',0xffffffff,255,65535)
    stats=struct.pack('<H',2 if rich else 0)+(struct.pack('<IQIQ',4,2**64-1,5,2**63) if rich else b'')
    effect=struct.pack('<QIIHHHQQQIBIII B',1,2,3,4,5,6,7,8,9,10,1,0x7fc12345,0,0x80000000,255) if rich else b''
    action=struct.pack('<BIQQBIII B',255,17,2**64-1,2**63,255,0x7fc12345,0x80000000,0x3f800000,254) if rich else b''
    guild=struct.pack('<Q',key)+text('Гильдия' if rich else '')+struct.pack('<I4HQBQB',19,0,32767,32768,65535,2**63,255,key,255)
    party=(b'\xff'+struct.pack('<Q',7)+text('Группа')+b'\xff\xff\xff'+text('Опции')+b'\xff\0\xff\xff'+struct.pack('<I',9)) if rich else b'\0'
    map_data=(b'\xff\2\0'+struct.pack('<BBIIIQ',5,255,1,2,3,4)+struct.pack('<BBIIIQ',5,2,10,11,12,13)) if rich else b'\0'
    return (struct.pack('<QQI',key,2**63,0xffffffff)+text('Игрок 🦇' if rich else '')+struct.pack('<IIBI',12,13,255,14)+appearance
        +struct.pack('<HIII B',65535,0x7fc12345,0x80000000,0x3f800000,255)+stats+struct.pack('<QH',23,count)+effect
        +b'\xff'+struct.pack('<H',count)+action+guild+party+map_data+b'\xff\xff\0\xff')


class CharacterOtherTests(unittest.TestCase):
    def test_whole_native_reader_all_nested_records(self):
        self.assertEqual(load('replay-sight-character-other-11316').verify()['cases'],1797)

    def test_aggregate_budget_precision_actor_action_and_successive_records(self):
        body=character_body(True);value=decode_character_other(body,source_sha256=SOURCE_SHA256,max_collection_items=7)
        self.assertEqual(value.at(8),2**64-1);self.assertEqual(value.at(0x10),2**63);self.assertEqual(value.at(0x20),'Игрок 🦇')
        self.assertEqual(value.at(0x40).at(8),2);self.assertEqual(value.at(0xc8)[0].at(0x10),2**64-1)
        self.assertEqual(value.at(0xa0).raw_byte,255);self.assertEqual(value.at(0x88).bits,(0x7fc12345,0x80000000,0x3f800000))
        action=value.at(0xf8)[0];self.assertEqual(action.at(8),5);self.assertEqual(action.at(0xc),17)
        self.assertEqual(action.at(0x10),2**64-1);self.assertEqual(action.at(0x18),2**63)
        self.assertEqual(action.at(0x20).at(0x20).raw_byte,254)
        self.assertEqual(value.at(0x108).at(0x10),'Гильдия');self.assertEqual(value.at(0x168).at(0x10),'Группа')
        self.assertEqual(len(value.at(0x1c8)),1);self.assertEqual(value.at(0x1c8)[0][1].at(0x20),13)
        with self.assertRaises(BufferError):decode_character_other(body,source_sha256=SOURCE_SHA256,max_collection_items=6)
        reader=CurrentRecordReader(body+body,source_sha256=SOURCE_SHA256,max_collection_items=14)
        self.assertEqual(reader.character_other(),value);self.assertEqual(reader.remaining,7);self.assertEqual(reader.position,len(body))
        self.assertEqual(reader.character_other(),value);reader.finish();self.assertEqual(reader.remaining,0)
        short=CurrentRecordReader(body+body,source_sha256=SOURCE_SHA256,max_collection_items=13);short.character_other()
        with self.assertRaises(BufferError):short.character_other()
        other=decode_character_other(character_body(False,42),source_sha256=SOURCE_SHA256,max_collection_items=0)
        self.assertEqual(other.at(8),42);self.assertEqual(value.at(8),2**64-1);self.assertEqual(other.at(0xf8),());self.assertIsNone(other.at(0x168))

    def test_source_size_mutability_text_and_scope_guards(self):
        body=character_body()
        for bad in (b'',body[:-1],body+b'\0'):
            with self.assertRaises(ValueError):decode_character_other(bad,source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_character_other(body,source_sha256='old')
        with self.assertRaises(TypeError):decode_character_other(bytearray(body),source_sha256=SOURCE_SHA256)
        with self.assertRaises(BufferError):decode_character_other(bytes(65537),source_sha256=SOURCE_SHA256)
        for limit in (-1,True,4097):
            with self.assertRaises(ValueError):decode_character_other(body,source_sha256=SOURCE_SHA256,max_collection_items=limit)
        for invalid in (b'\0',b'\xc0\x80',b'\xed\xa0\x80',b'\xef\xbf\xbe'):
            broken=body[:20]+struct.pack('<H',len(invalid))+invalid+body[22:]
            with self.assertRaises(ValueError):decode_character_other(broken,source_sha256=SOURCE_SHA256)
        context=json.loads((HERE/'knowledge/native-contexts/sight-character-other-11316.json').read_text('utf-8'))
        functions={int(v,16) for v in context['functions'].values()};harness=load('update-native-harness')
        context['budget_scope']='arbitrary'
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)
        context['budget_scope']='sight-character-other';functions.remove(0x145788180);functions.add(0x1457938b0)
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)


if __name__=='__main__':unittest.main()
