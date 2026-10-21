import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseSessionSetterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        tool = root / 'phone-exit/bots/resource-tools/vampir/replay-release-session-setter.py'
        run = subprocess.run([sys.executable, '-X', 'utf8', str(tool)], cwd=root,
            capture_output=True, text=True, encoding='utf-8', check=True)
        cls.report = json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_native_setter_destination_is_session_field(self):
        report = self.report
        self.assertEqual(report['source_sha256'], '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(report['destination_inner_offset'], 0x1d8)
        self.assertEqual(report['destination_data_offset'], 0x1b0)
        self.assertEqual(set(report['key_literals']), {'I_NMSessionID', 'I_TID'})
        self.assertFalse(report['network_used'])

    def test_equal_values_skip_assignment_and_changes_are_applied(self):
        self.assertEqual(len(self.report['cases']), 8)
        for case in self.report['cases']:
            changed = case['old'] != case['new']
            self.assertEqual(case['changed'], changed)
            self.assertEqual(case['events'].count('assignment_fixture'), int(changed))


if __name__ == '__main__': unittest.main()
