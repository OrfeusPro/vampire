"""Native state registry lookup without assuming real state2 contents."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent


class SelectionStateLookupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-selection-state-lookup.py'
        spec=importlib.util.spec_from_file_location('lookup_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/selection-state-lookup-replay.json').read_text('utf-8'))

    def test_source_and_native_report_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertEqual(len(self.report['cases']),13)
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['actual_state2_label_verified'])
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for row in self.report['leaves']:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(raw[row['file_offset']:row['file_offset']+len(data)],data)
            self.assertEqual(hashlib.sha256(data).hexdigest(),row['sha256'])

    def test_exact_key_match_chain_and_inline_record_address(self):
        for case in self.report['cases']:
            f=case['fixture']
            hit=bool(f['keys']) and len(f['keys'])!=f['free_count'] and not f['empty_bucket'] and f['query'] in f['keys']
            self.assertEqual(case['descriptor_key'],f['query'])
            self.assertEqual(case['selected_key'],f['query'] if hit else None)
            self.assertEqual(case['pointer_offset'],f['keys'].index(f['query'])*0x150+8 if hit else None)
            self.assertEqual(case['label'],'registry-label-fixture' if hit else '')
            self.assertEqual(case['label_reads'],[f['query']] if hit else [])

    def test_collision_miss_does_not_fall_back_to_first_record(self):
        cases={c['fixture']['name']:c for c in self.report['cases']}
        self.assertEqual(cases['collision-hit']['pointer_offset'],0x2a8)
        self.assertIsNone(cases['collision-miss']['pointer_offset'])
        self.assertEqual(cases['all-free']['label'],'')
        self.assertEqual(cases['key-4294967295']['selected_key'],0xffffffff)


if __name__=='__main__':unittest.main()
