"""Current whole NPC movement readers; synthetic input, no game connection."""
import importlib.util
import math
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.npc_move_event import SOURCE_SHA256,decode_npc_move_notify,decode_npc_move_data


class NpcMoveTests(unittest.TestCase):
    def test_whole_native_notify_and_data_records(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-npc-move-11316.py'
        spec=importlib.util.spec_from_file_location('npc_move_replay_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.verify()['cases'],2375)

    def test_limits_identity_exact_size_and_source_guard(self):
        body=struct.pack('<QIIHII',2**64-1,0x80000000,0x3f800000,1,0x7fc12345,0xff800000)
        result=decode_npc_move_notify(body,source_sha256=SOURCE_SHA256)
        self.assertEqual(result.entity_key,2**64-1)
        self.assertEqual(math.copysign(1,result.xy.finite_values()[0]),-1)
        self.assertEqual(result.records[0].bits,(0x7fc12345,0xff800000))
        with self.assertRaises(ValueError):result.records[0].finite_values()
        self.assertEqual(decode_npc_move_data(body[16:],source_sha256=SOURCE_SHA256),result.records)
        with self.assertRaises(BufferError):decode_npc_move_notify(body,source_sha256=SOURCE_SHA256,max_records=0)
        with self.assertRaises(BufferError):decode_npc_move_notify(bytes(65537),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_npc_move_notify(body,source_sha256='old-source')
        with self.assertRaises(ValueError):decode_npc_move_notify(body+b'\0',source_sha256=SOURCE_SHA256)
        with self.assertRaises(TypeError):decode_npc_move_notify(bytearray(body),source_sha256=SOURCE_SHA256)


if __name__=='__main__':unittest.main()
