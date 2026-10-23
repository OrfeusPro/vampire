"""Native ordinary preset allocation boundary, constructor and defaults copy."""
import importlib.util
from pathlib import Path
import struct
import unittest


class PresetObjectTests(unittest.TestCase):
    def test_whole_ordinary_construction_and_property_lists(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-preset-object.py'
        spec = importlib.util.spec_from_file_location('preset_object_test', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        _, report = module.run()
        self.assertEqual(len(report['cases']), 18)
        vector = bytes(36) + struct.pack('<7fB', *([0.5] * 7), 0)
        for case in report['cases']:
            self.assertEqual(bytes.fromhex(case['default_bytes']), vector)
            self.assertEqual(case['completed_flags'], 0xb)
            self.assertTrue(case['guards_unchanged'])
            expected_count = {'empty': 0, 'all': 17, 'alternate': 9}[case['link_mode']]
            self.assertEqual(len(case['copied_fields']), expected_count)
            changed = case['modified_template'] and case['link_mode'] != 'empty'
            self.assertEqual(bytes.fromhex(case['output_bytes']) != vector, changed)
        self.assertEqual(report['vtable_comparison_window'], 0x2b0)
        self.assertEqual([r['offset'] for r in report['vtable_overrides']], [0])


if __name__ == '__main__': unittest.main()
