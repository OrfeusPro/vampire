"""Native ID206 minimum body, exact scalar layout and bounded short reads."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).parent


class WorldMoveFinishReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-move-finish-reader.py'
        spec=importlib.util.spec_from_file_location('finish_reader_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-move-finish-reader-replay.json').read_text('utf-8'))

    def test_whole_native_reader_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),18)
        self.assertFalse(self.report['network_ready'])

    def test_scalar_fields_vector_signed_zero_and_normalization(self):
        for case in self.report['cases']:
            data=bytes.fromhex(case['payload_hex']);fields=case['fields']
            self.assertEqual(case['consumed'],len(data))
            self.assertEqual(len(data),81+len(case['text'].encode('utf-8')))
            self.assertEqual(fields['0x10'],struct.unpack_from('<I',data)[0])
            self.assertEqual(fields['0x18'],0x123456789abcdef)
            self.assertEqual(fields['0x20'],0xffffffff)
            self.assertEqual(fields['0x24'],0x89abcdef)
            self.assertEqual(fields['0xe0'],0xfedcba9876543210)
            self.assertEqual(fields['0xf8'],65535)
            self.assertEqual(fields['0x110'],7)
            self.assertEqual([fields[k] for k in ('0x28','0x71','0x119')],[1,255,1])
            self.assertIn((fields['0x29'],fields['0x70'],fields['0x118']),((0,0,0),(22,5,100)))
            self.assertEqual(case['vector_hex'],struct.pack('<ddd',1.5,-2.25,-0.).hex())

    def test_every_short_prefix_fails_without_overconsumption(self):
        self.assertEqual([c['size'] for c in self.report['short']],list(range(81)))
        for case in self.report['short']:
            self.assertEqual(case['returned'],0)
            self.assertLessEqual(case['consumed'],case['size'])


if __name__=='__main__':unittest.main()
