"""Whole current social records used by CharacterOther; offline synthetic input."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_social_records import SOURCE_SHA256,decode_guild_tiny_info,decode_party_tag

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class SightSocialTests(unittest.TestCase):
    def test_whole_native_records_constructors_utf8_and_nested_readers(self):
        self.assertEqual(load('replay-sight-social-11316').verify()['cases'],9590)

    def test_unicode_precision_enum_bool_size_and_text_guards(self):
        def string(value):
            data=value.encode('utf-8');return struct.pack('<H',len(data))+data
        guild=struct.pack('<Q',2**64-1)+string('Гильдия 🦇')+struct.pack('<I4HQBQB',0xffffffff,0,32767,32768,65535,2**63,255,2**64-1,255)
        value=decode_guild_tiny_info(guild,source_sha256=SOURCE_SHA256)
        self.assertEqual(value.at(8),2**64-1);self.assertEqual(value.at(0x10),'Гильдия 🦇')
        self.assertEqual([v for _,v in value.at(0x28).fields],[0,32767,32768,65535])
        self.assertEqual(value.at(0x38),2**63);self.assertEqual(value.at(0x50),2**64-1)
        self.assertEqual(value.at(0x40),6);self.assertIs(value.at(0x58),True)
        party=bytes(8)+string('Party')+b'\xff\xff\xff'+string('Опции')+b'\xff\0\xff\xff'+bytes(4)
        value=decode_party_tag(party,source_sha256=SOURCE_SHA256);options=value.at(0x20)
        self.assertEqual([options.at(k) for k in (8,9,10)],[3,102,8]);self.assertEqual(options.at(0x10),'Опции')
        self.assertIs(options.at(0x20),True);self.assertIs(options.at(0x21),False)
        self.assertIs(value.at(0x48),True);self.assertEqual(value.at(0x49),3)
        for decoder,body in ((decode_guild_tiny_info,guild),(decode_party_tag,party)):
            for bad in (b'',body[:-1],body+b'\0'):
                with self.assertRaises(ValueError):decoder(bad,source_sha256=SOURCE_SHA256)
            with self.assertRaises(BufferError):decoder(bytes(65537),source_sha256=SOURCE_SHA256)
            with self.assertRaises(TypeError):decoder(bytearray(body),source_sha256=SOURCE_SHA256)
            with self.assertRaises(ValueError):decoder(body,source_sha256='old')
        for invalid in (b'\0',b'\xc0\x80',b'\xed\xa0\x80',b'\xef\xbf\xbe',b'\xef\xbf\xbf'):
            with self.assertRaises(ValueError):decode_guild_tiny_info(bytes(8)+struct.pack('<H',len(invalid))+invalid+bytes(30),source_sha256=SOURCE_SHA256)
        maximum=bytes(8)+string('x'*65496)+bytes(30)
        self.assertEqual(len(maximum),65536);self.assertEqual(len(decode_guild_tiny_info(maximum,source_sha256=SOURCE_SHA256).at(0x10)),65496)

    def test_expanded_harness_scope_rejects_other_functions(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-social-11316.json').read_text('utf-8'))
        functions={int(v,16) for v in context['functions'].values()};harness=load('update-native-harness')
        context['budget_scope']='arbitrary'
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)
        context['budget_scope']='sight-social-records';functions.remove(0x14579c6b0);functions.add(0x145788180)
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)


if __name__=='__main__':unittest.main()
