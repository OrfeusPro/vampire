"""Whole Gadget and explicit source/count/text guards; no game connection."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_gadget_record import SOURCE_SHA256,decode_gadget

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class SightGadgetTests(unittest.TestCase):
    def test_whole_native_reader_keys_optional_owner_strings_and_math(self):
        self.assertEqual(load('replay-sight-gadget-11316').verify()['cases'],1891)

    def test_limits_raw_values_optional_owner_and_text_policy(self):
        prefix=struct.pack('<QIIIIII BBBQIBH',2**64-1,1,2,3,0x7fc12345,0x80000000,0x3f800000,255,255,255,2**63,0xffffffff,255,3)
        keys=struct.pack('<QQQ',2**64-1,0,2**64-1);name='Владелец 🦇'.encode('utf-8')
        body=prefix+keys+b'\xff\xff'+struct.pack('<QH',2**63,len(name))+name+struct.pack('<QB',2**64-1,255)
        value=decode_gadget(body,source_sha256=SOURCE_SHA256,max_collection_items=3)
        self.assertEqual(value.at(8),2**64-1);self.assertEqual(value.at(0x68),2**63)
        self.assertEqual(value.at(0x20).bits,(0x7fc12345,0x80000000,0x3f800000))
        with self.assertRaises(ValueError):value.at(0x20).finite_values()
        self.assertEqual(value.at(0x38).raw_byte,255);self.assertIs(value.at(0x60),True)
        self.assertEqual(value.at(0x61),5);self.assertEqual(value.at(0x74),3);self.assertEqual(value.at(0xc8),255)
        self.assertEqual(value.at(0x78),(2**64-1,0,2**64-1));owner=value.at(0x88)
        self.assertEqual(owner.at(8),9);self.assertEqual(owner.at(0x10),2**63);self.assertEqual(owner.at(0x18),'Владелец 🦇')
        self.assertEqual(owner.at(0x28),2**64-1)
        empty=decode_gadget(bytes(52),source_sha256=SOURCE_SHA256,max_collection_items=0)
        self.assertEqual(empty.at(0x78),());self.assertIsNone(empty.at(0x88))
        with self.assertRaises(BufferError):decode_gadget(body,source_sha256=SOURCE_SHA256,max_collection_items=2)
        for limit in (-1,True,4097):
            with self.assertRaises(ValueError):decode_gadget(bytes(52),source_sha256=SOURCE_SHA256,max_collection_items=limit)
        for bad in (b'',body[:-1],body+b'\0'):
            with self.assertRaises(ValueError):decode_gadget(bad,source_sha256=SOURCE_SHA256)
        with self.assertRaises(TypeError):decode_gadget(bytearray(body),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_gadget(body,source_sha256='old')
        with self.assertRaises(BufferError):decode_gadget(bytes(65537),source_sha256=SOURCE_SHA256)
        for invalid in (b'\0',b'\xc0\x80',b'\xed\xa0\x80',b'\xef\xbf\xbe',b'\xef\xbf\xbf'):
            bad=bytes(50)+b'\1\0'+bytes(8)+struct.pack('<H',len(invalid))+invalid+bytes(9)
            with self.assertRaises(ValueError):decode_gadget(bad,source_sha256=SOURCE_SHA256)
        label=b'x'*65465;maximum=bytes(50)+b'\1\0'+bytes(8)+struct.pack('<H',len(label))+label+bytes(9)
        self.assertEqual(len(maximum),65536);self.assertEqual(len(decode_gadget(maximum,source_sha256=SOURCE_SHA256).at(0x88).at(0x18)),65465)

    def test_harness_scope_rejects_other_function_sets(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-gadget-11316.json').read_text('utf-8'))
        functions={int(v,16) for v in context['functions'].values()};harness=load('update-native-harness')
        context['budget_scope']='arbitrary'
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)
        context['budget_scope']='sight-gadget-record';functions.remove(0x1457938b0);functions.add(0x1456c5390)
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)


if __name__=='__main__':unittest.main()
