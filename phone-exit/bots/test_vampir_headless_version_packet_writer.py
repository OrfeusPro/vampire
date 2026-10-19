"""Compare native Version serialization with the shared portable body codec."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.version_packet import VersionPayload, SOURCE_SHA256


class VersionPacketWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-version-packet-writer.py'
        spec=importlib.util.spec_from_file_location('version_writer_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/version-packet-writer-replay.json').read_text('utf-8'))

    def test_source_and_native_report_are_reproducible(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(self.report['sha256'],SOURCE_SHA256)
        self.assertFalse(self.report['network_ready'])
        self.assertEqual(len(self.report['cases']),14)

    def test_portable_bytes_match_every_native_case(self):
        for c in self.report['cases']:
            model=VersionPayload(tuple(c['strings']),tuple(c['integers']))
            self.assertEqual(model.encode(max_payload_size=8192),bytes.fromhex(c['payload_hex']))
            self.assertEqual(c['returned'],1)
        empty=VersionPayload(('',)*10,(0,0,0))
        self.assertEqual(empty.encode(max_payload_size=32),bytes(32))

    def test_local_bounds_reject_ambiguous_and_mutable_inputs(self):
        for strings in ([],['']*10,('',)*9,('',)*11,(1,)+('',)*9):
            with self.assertRaises(ValueError):VersionPayload(strings,(0,0,0))
        for values in ([0,0,0],(0,0),(0,0,0,0),(True,0,0),(-1,0,0),(1<<32,0,0)):
            with self.assertRaises(ValueError):VersionPayload(('',)*10,values)
        for text in ('a\0b','\ud800','\udfff','\ufffe','\uffff','é'*32768):
            with self.assertRaises(ValueError):VersionPayload((text,)+('',)*9,(0,0,0))
        model=VersionPayload(('secret-fixture',)+('',)*9,(0,207,2))
        self.assertNotIn('secret-fixture',repr(model))
        with self.assertRaises(BufferError):model.encode(max_payload_size=32)
        for size in (True,0,31,-1,1<<24,'1024'):
            with self.assertRaises(ValueError):model.encode(max_payload_size=size)
        maximum=VersionPayload(('a'*65535,)+('',)*9,(0,0,0)).encode(max_payload_size=65567)
        self.assertEqual(maximum[:2],b'\xff\xff')
        self.assertEqual(len(maximum),65567)


if __name__=='__main__':
    unittest.main()
