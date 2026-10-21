import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseCommonContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        tool = root / 'phone-exit/bots/resource-tools/vampir/replay-release-common-context.py'
        completed = subprocess.run([sys.executable, '-X', 'utf8', str(tool)], cwd=root,
            capture_output=True, text=True, encoding='utf-8', check=True, timeout=60)
        cls.report = json.loads(Path(json.loads(completed.stdout)['report']).read_text('utf-8'))

    def test_current_source_executes_whole_updates_without_network(self):
        self.assertEqual(self.report['source_sha256'],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['cases']), 31)
        self.assertEqual({c['function'] for c in self.report['cases']}, {'0x14455bc40', '0x14455c950'})

    def test_missing_service_and_lazy_initialization(self):
        for case in self.report['cases']:
            if case['mode'] == 'missing':
                self.assertFalse(case['changed'])
                self.assertEqual(case['events'], ['service', 'lazy_service'])
            elif case['mode'] == 'lazy':
                self.assertTrue(case['changed'])
                self.assertIn('lazy_service', case['events'])

    def test_equivalent_empty_strings_and_independent_field_updates(self):
        for function, count in (('0x14455bc40', 4), ('0x14455c950', 3)):
            cases = [c for c in self.report['cases'] if c['function'] == function]
            self.assertEqual(len([c for c in cases if c['single_field'] is not None]), count)
            for case in cases:
                if case['single_field'] is not None:
                    self.assertTrue(case['changed'])
                elif case['mode'] == 'present':
                    self.assertEqual(case['changed'], (case['old'] or '') != (case['new'] or ''))


if __name__ == '__main__': unittest.main()
