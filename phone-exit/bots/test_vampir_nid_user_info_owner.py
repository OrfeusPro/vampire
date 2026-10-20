import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class NidUserInfoOwnerTests(unittest.TestCase):
    def test_native_owner_zeroing_and_getters_reproduce(self):
        tool = load('nid_owner_test', 'replay-nid-user-info-owner.py')
        saved = json.loads((tool.native.ROOT / 'code-clues/nid-user-info-owner-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual([c['fill'] for c in saved['cases']], [0, 0x55, 0xff])
        for case in saved['cases']:
            self.assertTrue(case['user_info_empty'])
            self.assertEqual(case['descriptor_count'], 37)
            self.assertEqual(case['allocation_sizes'], [0x278, 0x18, 0x10, 0x18])
            self.assertEqual(case['owner_pointer_offset'], '0x28')
            self.assertEqual(case['inner_field_offset'], '0x28')

    def test_diagnostic_names_identify_common_log_data_and_push_consumer(self):
        tool = load('nid_owner_names_test', 'replay-nid-user-info-owner.py')
        saved = json.loads((tool.native.ROOT / 'code-clues/nid-user-info-owner-replay.json').read_text('utf-8'))
        names = {r['address']: r['text'] for r in saved['diagnostic_names']}
        self.assertIn('FCommonLogData::ToMap', names['0x1494e6f10'])
        self.assertIn('FCommonLogData::ToJsonObject', names['0x1494e7330'])
        self.assertIn('FPushImpl::OnChangedUserData', names['0x1494ee190'])

    def test_constructor_callers_reproduce_without_claiming_population(self):
        tool = load('nid_owner_callers_test', 'build-nid-user-info-construct-callers.py')
        saved = json.loads((tool.base.native.ROOT / 'code-clues/nid-user-info-construct-callers.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['calls']), 10)
        self.assertEqual(saved['failed_roots'], [])
        owner_calls = [r for r in saved['calls'] if r['target'] == '0x14450f5d0']
        self.assertEqual([r['root'] for r in owner_calls], ['0x14450f420'])


if __name__ == '__main__': unittest.main()
