"""Whole current NPC create, synthetic records only; no auth/game commands."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.npc_create_event import SOURCE_SHA256,decode_npc_create_notify


class NpcCreateTests(unittest.TestCase):
    def test_whole_native_create_and_portable_nested_records(self):
        folder=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('npc_create_replay_test',folder/'replay-npc-create-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result=module.verify(json.loads((folder/'knowledge/native-contexts/npc-create-11316.json').read_text('utf-8')))
        self.assertEqual(len(result['cases']),323)
        self.assertEqual(len(result['truncated']),454)
        self.assertFalse(result['network_used'])

    def test_empty_record_raw_bits_limits_and_source(self):
        result=decode_npc_create_notify(bytes(112),source_sha256=SOURCE_SHA256,max_collection_items=0)
        self.assertFalse(result.flag);self.assertEqual(result.npc.at(8),0)
        self.assertIsNone(result.npc.at(0x118));self.assertEqual(result.npc.at(0x178),())
        self.assertEqual(result.data.at(0x1a8),())
        raw=bytearray(112);struct.pack_into('<Q',raw,1,2**64-1)
        struct.pack_into('<III',raw,13,0x80000000,0x7fc12345,0x7f800000);raw[25]=255
        result=decode_npc_create_notify(bytes(raw),source_sha256=SOURCE_SHA256)
        self.assertEqual(result.npc.at(8),2**64-1)
        self.assertEqual(result.npc.at(0x18).bits,(0x80000000,0x7fc12345,0x7f800000))
        self.assertEqual(result.npc.at(0x30).raw_byte,255)
        with self.assertRaises(ValueError):result.npc.at(0x18).finite_values()
        for size in range(112):
            with self.assertRaises(ValueError):decode_npc_create_notify(bytes(size),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_npc_create_notify(bytes(113),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_npc_create_notify(bytes(112),source_sha256='old')
        with self.assertRaises(TypeError):decode_npc_create_notify(bytearray(112),source_sha256=SOURCE_SHA256)
        with self.assertRaises(BufferError):decode_npc_create_notify(bytes(65537),source_sha256=SOURCE_SHA256)
        for count in (-1,4097,True):
            with self.assertRaises(ValueError):decode_npc_create_notify(bytes(112),source_sha256=SOURCE_SHA256,max_collection_items=count)
        raw=bytearray(112);struct.pack_into('<H',raw,63,4097)
        with self.assertRaises(BufferError):decode_npc_create_notify(bytes(raw),source_sha256=SOURCE_SHA256)


if __name__=='__main__':unittest.main()
