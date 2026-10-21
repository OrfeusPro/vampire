import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseCountrySetterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        tool = root / 'phone-exit/bots/resource-tools/vampir/replay-release-country-setter.py'
        run = subprocess.run([sys.executable,'-X','utf8',str(tool)],cwd=root,
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=60)
        cls.report = json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_current_native_setter_uses_country_slot_with_notification_disabled(self):
        self.assertEqual(self.report['source_sha256'],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(self.report['destination_settings_offset'],0x3f0)
        self.assertEqual(self.report['sentinel']['text'],'A1')
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['cases']),14)

    def test_A1_preserves_only_a_nonempty_previous_country(self):
        cases = [c for c in self.report['cases'] if c['new']=='A1']
        self.assertEqual(len(cases),5)
        for case in cases:
            self.assertEqual(case['ignored'],bool(case['old']))
            self.assertEqual(case['events'].count('assignment_fixture'),int(not bool(case['old'])))

    def test_other_values_are_assigned_even_when_equal_or_empty(self):
        for case in self.report['cases']:
            self.assertFalse(case['notification'])
            if case['new']=='A1': continue
            self.assertFalse(case['ignored'])
            self.assertEqual(case['events'].count('assignment_fixture'),1)
            self.assertEqual(case['events'].count('input_cleanup_fixture'),int(case['new'] is not None))


if __name__ == '__main__': unittest.main()
