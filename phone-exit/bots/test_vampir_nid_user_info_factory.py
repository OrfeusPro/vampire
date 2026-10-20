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


class NidUserInfoFactoryTests(unittest.TestCase):
    def test_full_factory_preserves_empty_common_data_and_shared_self(self):
        tool = load('nid_factory_test', 'replay-nid-user-info-factory.py')
        saved = json.loads((tool.native.ROOT / 'code-clues/nid-user-info-factory-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual([r['fill'] for r in saved['cases']], [0, 0x55, 0xff])
        for case in saved['cases']:
            self.assertTrue(case['shared_self_linked'])
            self.assertTrue(case['user_info_empty'])
            self.assertTrue(case['native_host_callsite'])
            self.assertEqual(case['bridge_owner_offset'], '0x310')
            self.assertEqual(case['descriptor_count'], 37)
            self.assertEqual(case['control_counters'], [1, 2])
            self.assertEqual(case['allocation_sizes'], [0xf0, 0x278, 0x18, 0x10, 0x18, 0x18])

    def test_factory_caller_is_verified_without_claiming_field_population(self):
        tool = load('nid_factory_callers_test', 'build-nid-user-info-factory-callers.py')
        saved = json.loads((tool.base.native.ROOT / 'code-clues/nid-user-info-factory-callers.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(saved['failed_roots'], [])
        self.assertEqual([(r['target'], r['root']) for r in saved['calls']],
                         [('0x14450f420', '0x144510fd0')])


if __name__ == '__main__':
    unittest.main()
