"""Actual extension readers compared against the portable whole-list decoder."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_list import decode_character_list,SOURCE_SHA256


class CharacterExtensionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-character-list-extensions.py'
        spec=importlib.util.spec_from_file_location('extensions_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/character-list-extensions-replay.json').read_text('utf-8'))

    def test_native_report_reproduces(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(self.report['sha256'],SOURCE_SHA256)
        self.assertFalse(self.report['network_ready'])

    def test_portable_whole_list_and_extensions_match(self):
        for case in self.report['cases']:
            body=bytes.fromhex(case['payload_hex'])
            model=decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=64)
            self.assertEqual(len(model.records),len(case['records']))
            self.assertEqual(case['consumed'],len(body))
            for record,expected in zip(model.records,case['records']):
                self.assertEqual(record.appearance_items,tuple(tuple(v) for v in expected['appearance_items']))
                self.assertEqual(record.optional_items,None if expected['optional_items'] is None
                    else tuple(tuple(v) for v in expected['optional_items']))
                for field in ('strings','u32','u16','u64','appearance','appearance_flags'):
                    self.assertEqual(getattr(record,field),tuple(expected[field]))
        for case in self.report['truncated']:
            self.assertEqual(case['returned'],0)
            with self.assertRaises(ValueError):
                decode_character_list(bytes.fromhex(case['payload_hex']),max_payload_size=4096,max_characters=4,max_extension_items=64)

    def test_aggregate_count_budget(self):
        body=self.tool.list_bytes(((1,2,3),)*2,count=4)
        with self.assertRaises(BufferError):
            decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=7)
        self.assertEqual(len(decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=8).records),4)
        for value in (True,-1,65536,None):
            with self.assertRaises(ValueError):
                decode_character_list(body,max_payload_size=4096,max_characters=4,max_extension_items=value)
        optional=self.tool.optional_bytes(((1,1,2,3,4,5),(1,2,3,4,5,6)))
        duplicate_body=self.tool.list_bytes(((1,2,3),),optional)
        with self.assertRaises(BufferError):
            decode_character_list(duplicate_body,max_payload_size=4096,max_characters=4,max_extension_items=2)
        decoded=decode_character_list(duplicate_body,max_payload_size=4096,max_characters=4,max_extension_items=3)
        self.assertEqual(decoded.records[0].optional_items,((1,2,3,4,5,6),))


if __name__=='__main__':unittest.main()
