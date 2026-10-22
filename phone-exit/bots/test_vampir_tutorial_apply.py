"""Native pending removal, separate server/local records and deferred clones; no network."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent


class TutorialApplyTests(unittest.TestCase):
    def test_native_removal_application_and_deferral(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-tutorial-apply.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['removals']), 12)
        self.assertEqual(len(report['applied']), 384)
        self.assertEqual(len(report['phases']), 32)
        for row in report['removals']:
            self.assertNotIn(row['key'], row['remaining'])
            self.assertEqual(len(row['remaining']), 2)
        for row in report['phases']:
            self.assertEqual(row['deferred'], not row['bypass'] and row['phase'] < 6)


if __name__ == '__main__':
    unittest.main()
