"""Whole native ID110 nonempty arrays, normalization and short bodies."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


class CharacterSelectCollectionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'replay-character-select-collections.py'
        spec=importlib.util.spec_from_file_location('select_collections_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.saved=json.loads((cls.tool.native.ROOT/'code-clues/character-select-collections-replay.json').read_text('utf-8'))

    def test_whole_native_reader_reproduces(self):
        self.assertEqual(self.tool.build(),self.saved)
        self.assertFalse(self.saved['network_ready'])
        self.assertEqual(len(self.saved['cases']),34)
        for name,digest in self.saved['dependency_sha256'].items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)

    def test_each_array_and_the_combination_reach_the_native_destination(self):
        for field in self.tool.LAYOUT:
            isolated=[c for c in self.saved['cases'] if c['collections'][hex(field)] and
                sum(bool(v) for v in c['collections'].values())==1]
            self.assertEqual(len(isolated),3)
            for case,count in zip(isolated,(1,2,8)):
                self.assertEqual((case['returned'],case['consumed']),(1,len(bytes.fromhex(case['payload_hex']))))
                self.assertEqual(len(case['collections'][hex(field)]),count)
        combined=self.saved['cases'][-1]
        self.assertTrue(all(len(rows)==2 for rows in combined['collections'].values()))
        self.assertEqual(combined['collections']['0x80'][1],[0xffffffff,45,65535])
        self.assertEqual(combined['collections']['0x1d8'][1],[91,2**64-1])
        self.assertEqual(combined['collections']['0x250'][1],[255,7,255])
        nested=combined['collections']['0x1f8'][1]
        self.assertEqual(nested[10],1)
        self.assertEqual(nested[11:14],list(struct.unpack('<III',struct.pack('<fff',1.5,-2.25,-0.))))
        self.assertEqual(nested[14],1)

    def test_every_short_prefix_of_combined_body_is_rejected(self):
        body=bytes.fromhex(self.saved['cases'][-1]['payload_hex'])
        self.assertEqual(len(self.saved['truncated']),len(body))
        for length,case in enumerate(self.saved['truncated']):
            self.assertEqual(case['payload_hex'],body[:length].hex())
            self.assertEqual(case['returned'],0)
            self.assertLessEqual(case['consumed'],length)


if __name__=='__main__':unittest.main()
