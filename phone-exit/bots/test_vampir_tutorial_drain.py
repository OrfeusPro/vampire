"""Native queue drain resumes at readiness, preserves order and releases once; no network."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent


class TutorialDrainTests(unittest.TestCase):
    def test_native_queue_readiness_order_and_cleanup(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-tutorial-apply.py'), '--drain'],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['drains']), 64)
        for row in report['drains']:
            self.assertEqual(row['resumed'], row['initial_phase'] < 6)
            self.assertEqual(row['released'], sum(item is not None for item in row['order']))


if __name__ == '__main__':
    unittest.main()
