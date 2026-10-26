"""Whole optional projectile array; synthetic records and bounded native storage."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_projectile_records import SOURCE_SHA256,decode_optional_projectile_circles,decode_projectile_circle_data

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class SightProjectileTests(unittest.TestCase):
    def test_whole_optional_native_reader_callback_records_cleanup(self):
        self.assertEqual(load('replay-sight-projectiles-11316').verify()['cases'],1734)

    def test_presence_limits_repeated_records_precision_and_source(self):
        decode=lambda body,limit=1024:decode_optional_projectile_circles(body,source_sha256=SOURCE_SHA256,max_collection_items=limit)
        self.assertIsNone(decode(b'\0'));self.assertEqual(decode(b'\xff\0\0'),())
        body=struct.pack('<HIIIQIIIHBQIIIII',65535,1,2,3,2**64-1,0x7fc12345,0x80000000,0x3f800000,65535,255,2**63,0xffffffff,0x7fc12345,0,1,2)
        value=decode(b'\1\2\0'+body*2,2);self.assertEqual(len(value),2);self.assertEqual(value[0],value[1])
        record=value[0].at(8);self.assertEqual(record.at(0x18),2**64-1);self.assertEqual(record.at(0x68),2**63)
        self.assertEqual(record.at(0x40).raw_byte,255);self.assertEqual(record.at(0x74),0x7fc12345)
        with self.assertRaises(ValueError):record.at(0x20).finite_values()
        with self.assertRaises(BufferError):decode(b'\1\2\0'+body*2,1)
        for limit in (-1,True,4097):
            with self.assertRaises(ValueError):decode(b'\0',limit)
        with self.assertRaises(BufferError):decode(b'\1'+bytes(65536))
        for bad in (b'',b'\0\0',b'\1',b'\1\0',b'\1\1\0'+body[:-1],b'\1\0\0\0'):
            with self.assertRaises(ValueError):decode(bad)
        with self.assertRaises(TypeError):decode(bytearray(1))
        with self.assertRaises(ValueError):decode_optional_projectile_circles(b'\0',source_sha256='old')
        for bad in (body[:-1],body+b'\0'):
            with self.assertRaises(ValueError):decode_projectile_circle_data(bad,source_sha256=SOURCE_SHA256)
        with self.assertRaises(TypeError):decode_projectile_circle_data(bytearray(body),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_projectile_circle_data(body,source_sha256='old')

    def test_expanded_harness_scope_cannot_select_other_functions(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-projectiles-11316.json').read_text('utf-8'))
        functions={int(v,16) for v in context['functions'].values()};harness=load('update-native-harness')
        context['budget_scope']='arbitrary'
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)
        context['budget_scope']='sight-projectile-array';functions.remove(0x1456c2f60);functions.add(0x1456c5390)
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)


if __name__=='__main__':unittest.main()
