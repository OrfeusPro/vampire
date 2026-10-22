"""Exact ID 9904 framing and whole native reader parity; no network."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.tutorial_result import decode_tutorial_result
from vampir_core.world_move_start import SOURCE_SHA256


class TutorialResultTests(unittest.TestCase):
    def test_source_and_exact_length(self):
        body = struct.pack('<IIIIBBB', 0, 1001, 2, 1001002, 1, 0, 0)
        for size in range(len(body)):
            with self.assertRaises(ValueError):
                decode_tutorial_result(body[:size], source_sha256=SOURCE_SHA256)
        for invalid in (body + b'\0', bytearray(body)):
            with self.assertRaises(ValueError):
                decode_tutorial_result(invalid, source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):
            decode_tutorial_result(body, source_sha256='old')

    def test_raw_fields_clamp_and_flags(self):
        result = decode_tutorial_result(struct.pack('<IIIIBBB', 4223, 1001, 2, 0xffffffff, 255, 255, 0),
                                        source_sha256=SOURCE_SHA256)
        self.assertEqual(result.code, 4223)
        self.assertEqual((result.record.raw08, result.record.raw0c, result.record.raw10, result.record.state),
                         (1001, 2, 0xffffffff, 3))
        self.assertTrue(result.raw30)
        self.assertFalse(result.raw31)
        self.assertNotIn('4294967295', repr(result))

    def test_whole_native_result_reader(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-tutorial-result.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 216)
        self.assertEqual([case['size'] for case in report['short']], list(range(19)))
        self.assertEqual(len(report['handler_cases']), 45)
        for case in report['handler_cases']:
            self.assertEqual('clear_wait_mode' in case['events'], bool(case['waiting']))
            self.assertEqual('apply_fixture' in case['events'], case['code'] == 0)
            self.assertEqual('special_fixture' in case['events'], case['code'] == 4223)


if __name__ == '__main__':
    unittest.main()
