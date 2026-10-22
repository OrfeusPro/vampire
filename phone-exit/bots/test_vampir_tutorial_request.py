"""Native parity and input guards for the isolated ID 9903 body; no network."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.tutorial_request import encode_tutorial_request
from vampir_core.world_move_start import SOURCE_SHA256


class TutorialRequestTests(unittest.TestCase):
    def test_explicit_fields_and_release_guard(self):
        self.assertEqual(encode_tutorial_request(1001, 2, 0, source_sha256=SOURCE_SHA256),
                         bytes.fromhex('e90300000200000000'))
        for args in ((-1, 2, 0), (1 << 32, 2, 0), (1001, -1, 0),
                     (1001, 1 << 32, 0), (1001, 2, -1), (1001, 2, 256),
                     (True, 2, 0), (1001, False, 0), (1001, 2, False)):
            with self.assertRaises(ValueError):
                encode_tutorial_request(*args, source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):
            encode_tutorial_request(1001, 2, 0, source_sha256='old')

    def test_whole_native_writer_and_failures(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-tutorial-request.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 64)
        self.assertEqual([len(bytes.fromhex(c['prefix_hex'])) for c in report['failures']], [0, 4, 8])
        for case in report['cases']:
            self.assertEqual(len(bytes.fromhex(case['body_hex'])), 9)
            self.assertEqual(bytes.fromhex(case['body_hex'])[-1], case['raw18'])


if __name__ == '__main__':
    unittest.main()
