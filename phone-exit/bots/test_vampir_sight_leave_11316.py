"""Whole current sight leave, bounded native/portable inputs only."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_leave_event import SOURCE_SHA256,decode_sight_leave_notify


class SightLeaveTests(unittest.TestCase):
    def test_whole_native_reader_and_callbacks(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-sight-leave-11316.py'
        spec=importlib.util.spec_from_file_location('sight_leave_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.verify()['cases'],3726)

    def test_limits_source_and_separate_arrays(self):
        body=struct.pack('<HQHQQQB',1,2**64-1,1,7,8,9,255)
        result=decode_sight_leave_notify(body,source_sha256=SOURCE_SHA256,max_collection_items=2)
        self.assertEqual(result.actor_keys,(2**64-1,));self.assertEqual(result.quest_visible,((7,8,9),));self.assertEqual(result.reason,32)
        with self.assertRaises(BufferError):decode_sight_leave_notify(body,source_sha256=SOURCE_SHA256,max_collection_items=1)
        for limit in (-1,True,4097):
            with self.assertRaises(ValueError):decode_sight_leave_notify(body,source_sha256=SOURCE_SHA256,max_collection_items=limit)
        with self.assertRaises(ValueError):decode_sight_leave_notify(body,source_sha256='old')
        with self.assertRaises(ValueError):decode_sight_leave_notify(body+b'\0',source_sha256=SOURCE_SHA256)
        with self.assertRaises(TypeError):decode_sight_leave_notify(bytearray(body),source_sha256=SOURCE_SHA256)
        with self.assertRaises(BufferError):decode_sight_leave_notify(bytes(65537),source_sha256=SOURCE_SHA256)


if __name__=='__main__':unittest.main()
