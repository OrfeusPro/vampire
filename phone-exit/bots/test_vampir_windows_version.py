import ctypes
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.windows_version import WindowsVersion, observe_windows_version


class WindowsVersionTests(unittest.TestCase):
    def test_runtime_format_matches_native_scenarios(self):
        path = Path('F:/PhoneExit Resources/Vampir/code-clues/version-windows-suffix-replay.json')
        report = json.loads(path.read_text('utf-8'))
        for case in report['cases']:
            fixture = case['fixture']
            if fixture.get('cached') or not fixture.get('version_ok', True): continue
            self.assertEqual(WindowsVersion(*fixture['version']).suffix(), case['output'])
        self.assertEqual(WindowsVersion(10, 0, 26200, 1, 256).suffix(), '10.0.26200.1.256.64bit')

    def test_wrong_fields_are_rejected(self):
        for values in ((True, 0, 1, 1, 0), (-1, 0, 1, 1, 0), (10, 0, 0x100000000, 1, 0),
                (10, 0, 1, 256, 0), (10, 0, 1, 1, 65536), (10, 0, 1, 1, '256')):
            with self.assertRaises(ValueError): WindowsVersion(*values)

    def test_api_structure_offsets_distinguish_suite_mask_and_service_pack(self):
        def query(pointer):
            value = pointer._obj
            self.assertEqual(ctypes.sizeof(value), 0x11c)
            self.assertEqual(value.size, 0x11c)
            fields = type(value)
            self.assertEqual(fields.service_pack_major.offset, 0x114)
            self.assertEqual(fields.suite_mask.offset, 0x118)
            self.assertEqual(fields.product_type.offset, 0x11a)
            value.major, value.minor, value.build = 10, 0, 26200
            value.service_pack_major, value.suite_mask, value.product_type = 9, 256, 1
            return 1
        kernel = Mock(GetVersionExW=Mock(side_effect=query))
        with patch('vampir_core.windows_version.sys.platform', 'win32'), \
                patch.object(ctypes, 'WinDLL', return_value=kernel, create=True) as factory:
            version = observe_windows_version()
        self.assertEqual(version.suffix(), '10.0.26200.1.256.64bit')
        factory.assert_called_once_with('kernel32', use_last_error=True)

    def test_api_failure_and_unsupported_platform(self):
        with patch('vampir_core.windows_version.sys.platform', 'win32'), \
                patch.object(ctypes, 'WinDLL', return_value=Mock(GetVersionExW=Mock(return_value=0)), create=True):
            self.assertIsNone(observe_windows_version())
        with patch('vampir_core.windows_version.sys.platform', 'linux'):
            with self.assertRaises(RuntimeError): observe_windows_version()


class WindowsSuffixNativeTests(unittest.TestCase):
    def test_complete_native_getter_reproduces_init_failure_cache_and_printf(self):
        path = HERE / 'resource-tools/vampir/replay-version-windows-suffix.py'
        spec = importlib.util.spec_from_file_location('suffix_native_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = tool.build()
        expected = json.loads((tool.native.ROOT / 'code-clues/version-windows-suffix-replay.json').read_text('utf-8'))
        self.assertEqual(report, expected)
        self.assertEqual(len(report['cases']), 7)
        self.assertEqual(report['cases'][4]['output'], '-1.-2147483648.2147483647.255.65535.64bit')
        self.assertEqual(report['cases'][5]['output'], '')
        self.assertEqual(report['cases'][6]['events'], [])


if __name__ == '__main__': unittest.main()
