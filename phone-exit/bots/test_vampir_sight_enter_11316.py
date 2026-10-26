"""Composed mixed SightEnter boundaries/budget; no whole native or live claim."""
from pathlib import Path
import importlib.util
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_enter_event import SOURCE_SHA256,decode_sight_enter
from vampir_core.current_record_reader import CurrentRecordReader
from test_vampir_sight_character_other_11316 import character_body


def mixed_body(key=2**64-1):
    def array(*items):return struct.pack('<H',len(items))+b''.join(items)
    npc=struct.pack('<Q',key)+bytes(103)
    ground=struct.pack('<Q',key)+bytes(41)+b'\xff'
    tether=struct.pack('<Q',key)+bytes(57)+b'\xff'
    name='Владелец 🦇'.encode('utf-8')
    gadget=struct.pack('<Q',key)+bytes(40)+array(struct.pack('<Q',key),bytes(8),struct.pack('<Q',key))
    gadget+=b'\xff\xff'+struct.pack('<QH',key,len(name))+name+struct.pack('<QB',key,255)
    projectile=struct.pack('<H',65535)+bytes(63)
    return (array(character_body(True,key))+array(npc)+array(ground)+array(gadget)
        +b'\xff'+array(projectile,projectile)+array(tether)+b'\xff')


class SightEnterCompositionTests(unittest.TestCase):
    def test_source_outer_order_descriptors_and_callback_types(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-sight-enter-11316.py'
        spec=importlib.util.spec_from_file_location('sight_enter_contract',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _,rows=module.run()
        self.assertEqual([row['offset'] for row in rows],['0x10','0x20','0x30','0x40','0x70'])

    def test_mixed_boundaries_raw_values_duplicates_and_single_aggregate_budget(self):
        body=mixed_body();reader=CurrentRecordReader(body,source_sha256=SOURCE_SHA256,max_collection_items=17)
        value=reader.sight_enter();reader.finish();self.assertEqual(reader.remaining,0)
        self.assertEqual(tuple(k for k,_ in value.fields),(0x10,0x20,0x30,0x40,0x50,0x70,0x80))
        for offset in (0x10,0x30,0x40,0x70):self.assertEqual(value.at(offset)[0].at(8),2**64-1)
        self.assertEqual(value.at(0x20)[0].at(8).at(8),2**64-1)
        self.assertEqual(value.at(0x40)[0].at(0x78),(2**64-1,0,2**64-1))
        self.assertEqual(value.at(0x40)[0].at(0x88).at(0x18),'Владелец 🦇')
        self.assertEqual(value.at(0x50)[0],value.at(0x50)[1])
        self.assertEqual(value.at(0x50)[0].at(8).at(8),65535)
        self.assertEqual(value.at(0x30)[0].at(0x70),3);self.assertIs(value.at(0x70)[0].at(0x8c),True)
        self.assertEqual(value.at(0x80),32)
        for limit in (0,7,10,16):
            with self.assertRaises(BufferError):decode_sight_enter(body,source_sha256=SOURCE_SHA256,max_collection_items=limit)
        other=decode_sight_enter(mixed_body(42),source_sha256=SOURCE_SHA256)
        self.assertEqual(other.at(0x10)[0].at(8),42);self.assertEqual(value.at(0x10)[0].at(8),2**64-1)

    def test_absent_empty_optional_tail_and_all_truncated_prefixes(self):
        absent=decode_sight_enter(bytes(12),source_sha256=SOURCE_SHA256,max_collection_items=0)
        self.assertIsNone(absent.at(0x50))
        present=decode_sight_enter(bytes(8)+b'\xff'+bytes(5),source_sha256=SOURCE_SHA256,max_collection_items=0)
        self.assertEqual(present.at(0x50),())
        for raw in range(256):
            self.assertEqual(decode_sight_enter(bytes(11)+bytes([raw]),source_sha256=SOURCE_SHA256).at(0x80),min(raw,32))
        body=mixed_body()
        for size in range(len(body)):
            with self.subTest(prefix=size):
                with self.assertRaises(ValueError):decode_sight_enter(body[:size],source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_sight_enter(body+b'\0',source_sha256=SOURCE_SHA256)

    def test_guards_every_outer_count_and_shared_gadget_budget(self):
        for offset in (0,2,4,6,9):
            bad=bytearray(12);struct.pack_into('<H',bad,offset,65535)
            with self.assertRaises(BufferError):decode_sight_enter(bytes(bad),source_sha256=SOURCE_SHA256)
        with self.assertRaises(BufferError):decode_sight_enter(bytes(8)+b'\1\xff\xff',source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_sight_enter(bytes(12),source_sha256='old')
        with self.assertRaises(TypeError):decode_sight_enter(bytearray(12),source_sha256=SOURCE_SHA256)
        with self.assertRaises(BufferError):decode_sight_enter(bytes(65537),source_sha256=SOURCE_SHA256)
        for limit in (-1,True,4097):
            with self.assertRaises(ValueError):decode_sight_enter(bytes(12),source_sha256=SOURCE_SHA256,max_collection_items=limit)
        # Two packets on one cursor cannot reset the aggregate budget.
        body=mixed_body();reader=CurrentRecordReader(body+body,source_sha256=SOURCE_SHA256,max_collection_items=33)
        reader.sight_enter()
        with self.assertRaises(BufferError):reader.sight_enter()


if __name__=='__main__':unittest.main()
