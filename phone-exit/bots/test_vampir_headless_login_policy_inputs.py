import importlib.util
import json
from pathlib import Path
import unittest


class LoginPolicyInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-login-policy-inputs.py'
        spec = importlib.util.spec_from_file_location('test_login_policy_inputs', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/login-policy-inputs-replay.json').read_text('utf-8'))

    def test_source_bound_reproduction_and_actual_leaf_instructions(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 43)
        leaves = {leaf['address']: leaf for leaf in self.report['leaves']}
        self.assertEqual(leaves[0x145cb95e0]['bytes'], '807908030f94c0c3')
        self.assertEqual(leaves[0x144ff8cd0]['bytes'], '0fb64139c3')
        self.assertNotEqual(leaves[0x145564550]['instructions'][0]['rip_references'],
            leaves[0x145cb2f60]['instructions'][0]['rip_references'])

    def test_gates_raw_bytes_metadata_and_separate_auth_object(self):
        for case in self.report['cases']:
            f, p = case['fixture'], case['packet']
            entries = [e['address'] for e in case['events'] if e['action'] == 'native_policy_entry']
            self.assertIn(0x145564550, entries)
            self.assertEqual(0x145cb95e0 in entries, f['sdk_enabled'])
            flag_active = f['sdk_enabled'] and f['manager_present'] and f['manager68_present']
            self.assertEqual(0x144ff8cd0 in entries, flag_active)
            self.assertEqual(p['bytes']['0x124'], f['policy_byte'])
            self.assertEqual(p['bytes']['0x130'], int(f['sdk_enabled'] and f['mode_byte'] == 3))
            self.assertEqual(p['bytes']['0x131'], f['manager68_byte'] if flag_active else 0)
            active = f['sdk_enabled'] and f['manager_present'] and f['auth_present']
            self.assertEqual(p['strings']['0xa0'], f['sdk_token'] if active else '')
            self.assertEqual(p['strings']['0x30'], f['netmarble_id'] if active else '')
            self.assertEqual(p['strings']['0xd8'], 'collector-fixture' if
                f['sdk_enabled'] and f['manager_present'] and f['manager48_present'] else '')

    def test_constructor_sets_mode_zero_but_preserves_policy_byte(self):
        cases = [case for case in self.report['cases'] if 'constructor_poison' in case['fixture']]
        self.assertEqual(len(cases), 3)
        for case in cases:
            self.assertEqual(case['after_constructors'], dict(policy_byte=case['fixture']['constructor_poison'], mode_byte=0))

    def test_state_index_binds_constructor_sources_and_numeric_input(self):
        path = Path(__file__).parent / 'resource-tools/vampir/build-login-policy-state-index.py'
        spec = importlib.util.spec_from_file_location('test_login_state_index', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.base.native.ROOT / 'code-clues/login-policy-state-index.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        refs = {(r['instruction']['address'], r['target']) for r in report['references']}
        self.assertIn((0x14555612a, '0x14b573398'), refs)
        self.assertIn((0x146425acb, '0x14b520cb8'), refs)
        self.assertIn((0x1467a991b, '0x14b520cb8'), refs)
        rows = {r['address']: r for f in report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x145dc79c6]['operands'], '0x145ca7240')


if __name__ == '__main__': unittest.main()
