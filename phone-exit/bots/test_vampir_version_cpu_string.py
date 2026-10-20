import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.version_cpu import VersionCpuInput
from vampir_core.version_packet import VersionPayload
from vampir_core.windows_version import WindowsVersion
from vampir_core.version_inputs import bind_windows_version_inputs


class VersionCpuStringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('cpu_string_native_test',
            HERE / 'resource-tools/vampir/replay-version-cpu-string.py')
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/version-cpu-string-replay.json').read_text('utf-8'))

    def test_full_native_initializer_trim_move_and_formatter_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 9)
        for case in self.report['cases']:
            self.assertGreater(case['space_calls'], 0)
            self.assertEqual(len(case['format_calls']), 1)
            self.assertEqual(case['format_calls'][0]['format'], '%s|%s')
        self.assertEqual(self.report['cases'][3]['output'], 'GenuineIntel|')
        self.assertEqual(self.report['cases'][5]['output'], 'GenuineIntel|Unknown')
        self.assertEqual(self.report['cases'][6]['output'], 'GenuineIntel|Fixture|CPU|Brand')

    def test_portable_format_matches_native_outputs(self):
        for case in self.report['cases']:
            fixture = case['fixture']
            vendor, brand = (fixture['vendor'], fixture['brand'] if fixture['max_extended'] >= 0x80000004 else '') if fixture['enabled'] else ('previous', 'previous-brand')
            self.assertEqual(VersionCpuInput(vendor, brand).text(), case['output'])
        self.assertEqual(VersionCpuInput('', '').text(), '|')
        self.assertEqual(VersionCpuInput(' Vendor ', ' Internal  spaces ').text(), 'Vendor|Internal  spaces')

    def test_invalid_fields_are_rejected_and_hardware_repr_is_hidden(self):
        for vendor, brand in (('a' * 13, ''), ('ok', 'b' * 49), ('x\0', ''),
                ('ok', '\u00a0brand'), ('ok', '\x1bbrand'), ('ok', '\x7f'), (b'vendor', 'brand')):
            with self.assertRaises(ValueError): VersionCpuInput(vendor, brand)
        self.assertEqual(repr(VersionCpuInput('GenuineIntel', 'private-brand')), 'VersionCpuInput()')

    def test_verified_inputs_bind_only_two_fields_without_overwriting_other_context(self):
        original = VersionPayload(('app-version-fixture', '', '', 'device-fixture', 'endpoint-fixture',
            '', '', '', '', 'compiled-tag-fixture'), (0, 207, 1))
        result = bind_windows_version_inputs(original, cpu=VersionCpuInput('GenuineIntel', ' Fixture CPU '),
            windows_version=WindowsVersion(10, 0, 26200, 1, 256))
        self.assertEqual(result.strings[1:3], ('Windows_10.0.26200.1.256.64bit', 'GenuineIntel|Fixture CPU'))
        for index in (0, 3, 4, 5, 6, 7, 8, 9): self.assertEqual(result.strings[index], original.strings[index])
        self.assertEqual(result.integers, original.integers)
        self.assertEqual(original.strings[1:3], ('', ''))
        empty = bind_windows_version_inputs(original, cpu=VersionCpuInput('', ''), windows_version=None)
        self.assertEqual(empty.strings[1:3], ('Windows_', '|'))
        with self.assertRaises(ValueError):
            bind_windows_version_inputs(result, cpu=VersionCpuInput('AuthenticAMD', 'other'),
                windows_version=WindowsVersion(10, 0, 26200, 1, 256))


if __name__ == '__main__': unittest.main()
