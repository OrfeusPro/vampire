import importlib.util
import json
from pathlib import Path
import unittest


class EnumFormTests(unittest.TestCase):
    def test_real_ctor_vtable_setter_prefix_and_lookup_use_descriptor_form(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-version-enum-form.py'
        spec = importlib.util.spec_from_file_location('enum_form_native_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = tool.build()
        self.assertEqual(report, json.loads((tool.native.ROOT / 'code-clues/version-enum-form-replay.json').read_text('utf-8')))
        self.assertEqual(report['vtable_slot']['table'], '0x1489e4b80')
        self.assertEqual(report['vtable_slot']['offset'], '0x2f8')
        self.assertEqual(report['descriptor']['enum_form_byte'], 2)
        self.assertEqual(len(report['cases']), 4)
        source = [case for case in report['cases'] if case['source_descriptor_case']]
        self.assertEqual(len(source), 1)
        self.assertEqual((source[0]['object_form'], source[0]['selector'], source[0]['output']), (2, 3, 'Windows'))
        self.assertEqual(report['cases'][1]['output'], 'ENnOsType::Windows')


if __name__ == '__main__': unittest.main()
