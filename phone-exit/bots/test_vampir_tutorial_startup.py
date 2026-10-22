"""Fresh snapshot to first native local transition with explicit table/storage fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent


class TutorialStartupTests(unittest.TestCase):
    def test_native_snapshot_bootstrap_and_early_gate(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-tutorial-startup.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 192)
        for row in report['cases']:
            active = row['count'] > 0 and row['row_found'] and row['state'] == 1
            self.assertEqual(row['launched'], [row['selector'] + 1] if active else [])


if __name__ == '__main__':
    unittest.main()
