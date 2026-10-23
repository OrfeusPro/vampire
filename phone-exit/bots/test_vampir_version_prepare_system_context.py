import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load, HERE

ROOT = Path('F:/PhoneExit Resources/Vampir')


class VersionPrepareSystemTests(unittest.TestCase):
    def context(self):
        return json.loads((HERE / 'knowledge/native-contexts/version-prepare-system-11316.json').read_text('utf-8'))

    def test_whole_prepare_runs_actual_system_helpers_and_nm_getter(self):
        report = load('verify-version-prepare-context').verify(self.context(), ROOT)
        self.assertEqual(len(report['cases']), 64)
        self.assertTrue(report['native_system_used'])
        self.assertTrue(report['native_nm_used'])
        for case in report['cases']:
            self.assertTrue(case['guards'])
            self.assertEqual(case['native_nm_calls'], 2)
            self.assertEqual(case['native_system_calls'], dict(formatter=1, first=1, second=1,
                trim=3, trim_start=3, trim_end=3, windows=1))
            self.assertEqual(case['strings'][2], '|' if case['empty'] else 'GenuineIntel|Fixture CPU')
            self.assertEqual(case['strings'][3], 'nm-cache-Ж🙂')
        self.assertFalse(report['network_used'])
        self.assertFalse(report['profile_activated'])

    def test_changed_actual_callee_and_shared_constructor_are_rejected(self):
        tool = load('verify-version-prepare-context')
        context = self.context()
        context['native_system']['cpu']['call_sites']['0x14144d1b9'] = '0x0'
        with self.assertRaisesRegex(ValueError, 'system call sites differ'): tool.verify(context, ROOT)
        context = self.context(); context['native_system']['cpu']['fixtures']['ascii'] = '0x0'
        with self.assertRaisesRegex(ValueError, 'shared string bindings differ'): tool.verify(context, ROOT)

    def test_wrong_helper_or_export_cannot_replace_verified_material(self):
        tool = load('verify-version-prepare-context')
        context = self.context(); context['native_system']['windows']['function'] = '0x14144d1a0'
        with self.assertRaisesRegex(ValueError, 'system helper links differ'): tool.verify(context, ROOT)
        context = self.context(); context['native_system']['cpu']['exports']['run-222e27fb93bc'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'): tool.verify(context, ROOT)


if __name__ == '__main__':
    unittest.main()
