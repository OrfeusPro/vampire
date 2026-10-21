"""Regression vectors from the actual new-release Ping producer, without network IO."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleasePingProducerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        tool = cls.root / 'phone-exit/bots/resource-tools/vampir/replay-release-ping-producer.py'
        result = subprocess.run([sys.executable, '-X', 'utf8', str(tool)], cwd=cls.root,
            capture_output=True, text=True, encoding='utf-8', check=True)
        receipt = json.loads(result.stdout)
        cls.report = json.loads(Path(receipt['report']).read_text('utf-8'))

    def test_source_and_native_payload(self):
        self.assertEqual(self.report['source_sha256'], '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(self.report['packet_id'], 16)
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['cases']), 36)
        for case in self.report['cases']:
            if case['name'] in ('first', 'fractional'):
                self.assertEqual(case['sent'], [[5001, 5001]])
            elif case['name'] == 'delta-send':
                self.assertEqual(case['sent'], [[15001, 5001]])

    def test_interval_and_readiness_boundaries(self):
        names = {'boundary', 'delta-boundary', 'clock-before-last', 'mode-two', 'context-special', 'wrapper-special'}
        cases = [case for case in self.report['cases'] if case['name'] in names]
        self.assertEqual(len(cases), 18)
        for case in cases:
            self.assertEqual(case['sent'], [])
            self.assertFalse(case['recovery'])

    def test_outstanding_limit_and_override(self):
        for index in (0, 1, 3):
            cases = {case['name']: case for case in self.report['cases'] if case['index'] == index}
            self.assertEqual(cases['five-outstanding']['state'], [5001, index, 6])
            self.assertEqual(cases['six-outstanding']['sent'], [])
            self.assertTrue(cases['six-outstanding']['recovery'])
            self.assertEqual(cases['six-outstanding']['state'], [0, index, 0])
            self.assertEqual(cases['override-six']['sent'], [[5001, 5001]])
            self.assertFalse(cases['override-six']['recovery'])
            self.assertEqual(cases['override-six']['state'], [5001, index, 7])


if __name__ == '__main__':
    unittest.main()
