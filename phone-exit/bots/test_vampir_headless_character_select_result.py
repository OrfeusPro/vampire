"""Native ID110 minimum-profile and player apply evidence; no live session."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class CharacterSelectResultTests(unittest.TestCase):
    def test_actual_minimum_reader_reproduces_all_wire_headings(self):
        tool=module('select_result_test','replay-character-select-result.py')
        saved=json.loads((tool.native.ROOT/'code-clues/character-select-result-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(),saved)
        self.assertFalse(saved['network_ready'])
        self.assertEqual(len(saved['cases']),256)
        self.assertEqual(len(saved['vector_cases']),12)
        self.assertGreater(len(saved['math_trace']),0)
        for heading,c in enumerate(saved['cases']):
            self.assertEqual(bytes.fromhex(c['payload_hex'])[saved['heading_wire_offset']],heading)
            self.assertEqual((c['returned'],c['consumed']),(1,203))
            self.assertEqual(c['vector188_hex'],struct.pack('<ddd',1.5,-2.25,3.75).hex())
        # Native canonicalization includes signed-byte wrap and truncation.
        self.assertEqual([saved['cases'][i]['heading_byte'] for i in (0,1,90,91,128,180,255)],
            [0,0,90,167,52,180,0])

    def test_actual_apply_preserves_raw_vector_and_derives_angles(self):
        tool=module('select_apply_test','replay-character-select-apply.py')
        saved=json.loads((tool.native.ROOT/'code-clues/character-select-apply-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(),saved)
        self.assertEqual(len(saved['cases']),22)
        for c in saved['cases']:
            self.assertEqual(c['copied_vector_hex'],struct.pack('<ddd',*c['raw_vector_input']).hex())
            self.assertEqual((c['raw8'],c['raw10']),(0x123456789abcdef,207))
            self.assertEqual(c['derived249'],int(c['raw_flag']==2))
            self.assertEqual(c['rotation'][2],0.)
            self.assertTrue(all(math.isfinite(v) for v in c['rotation']))

    def test_math_discovery_is_bound_to_tools_client_and_artifacts(self):
        tool=module('select_math_provenance_test','run-ghidra-math.py')
        latest=json.loads((tool.native.ROOT/'ghidra/latest-math.json').read_text('utf-8'))
        out=Path(latest['output']);data=(out/'provenance.json').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),latest['provenance_sha256'])
        report=json.loads(data);raw=Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),report['source_sha256'])
        self.assertEqual(report['tools'],json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8')))
        for key,filename in (('script_sha256','ExportVampirMath.java'),('runner_sha256','run-ghidra-math.py')):
            self.assertEqual(hashlib.sha256((HERE/filename).read_bytes()).hexdigest(),report[key])
        self.assertLessEqual(sum(r['end']-r['start'] for r in report['ranges']),2*65536)
        for r in report['ranges']:
            self.assertEqual(hashlib.sha256(raw[r['file_offset']:r['file_offset']+r['end']-r['start']]).hexdigest(),r['sha256'])
        for name,digest in report['files'].items():
            self.assertEqual(hashlib.sha256((out/name).read_bytes()).hexdigest(),digest)


if __name__=='__main__':unittest.main()
