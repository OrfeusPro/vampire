"""Whole current stat reader and portable policy; no authentication or game commands."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.stat_change import SOURCE_SHA256,decode_stat_change


class StatNotifyTests(unittest.TestCase):
    def test_same_memory_native_reader_records_and_application(self):
        spec=importlib.util.spec_from_file_location('stat_notify_native_test',HERE/'resource-tools/vampir/replay-stat-notify-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.verify()['cases'],1119)

    def test_record_and_byte_limits_wrong_source_and_exact_size(self):
        body=struct.pack('<QHiQQBH',2**64-1,1,4,2**64-1,2**63,255,65535)
        change=decode_stat_change(body,source_sha256=SOURCE_SHA256)
        self.assertEqual(change.entity_key,2**64-1)
        self.assertEqual(change.values[0].first_bits,2**64-1)
        self.assertEqual(change.values[0].signed_second,-2**63)
        self.assertTrue(change.flag)
        with self.assertRaises(BufferError):decode_stat_change(body,source_sha256=SOURCE_SHA256,max_records=0)
        with self.assertRaises(BufferError):decode_stat_change(bytes(65537),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):decode_stat_change(body,source_sha256='unverified')
        with self.assertRaises(ValueError):decode_stat_change(body+b'\0',source_sha256=SOURCE_SHA256)
        with self.assertRaises(TypeError):decode_stat_change(bytearray(body),source_sha256=SOURCE_SHA256)


if __name__=='__main__':unittest.main()
