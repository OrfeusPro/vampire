import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent / 'resource-tools/vampir'


class SdkOverrides11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('sdk_overrides_11316_test', HERE / 'replay-sdk-overrides-11316.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_native_settings_initializers_override_and_market_paths(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 106)
        self.assertEqual(len(report['leaves']), 3)
        self.assertEqual(report['copy_import']['name'], 'memcpy')
        for case in report['cases']:
            with self.subTest(environment=case['environment'], nmenv=case['nmenv'],
                              sdk_present=case['sdk_present'], sdk_handle=case['sdk_handle']):
                epic = (case['nmenv'] in ('epicgames', 'EPICGAMES')
                        and case['sdk_present'] and case['sdk_handle'])
                expected = dict(market='epicgames' if epic else 'nmp', game_code='thered',
                                client_id='18e6xn1vuR1lGrvR', build_code=0, raw_c8=0,
                                sdk_zone=2 if case['environment'] in ('real', 'REAL', 'Real', 'rEaL') else 1)
                self.assertEqual(case['actual'], expected)
                self.assertTrue(case['canaries_unchanged'])
                self.assertEqual(len(case['events']), int(case['sdk_present'] and case['sdk_handle']))

    def test_changed_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data + b'changed' if path.name == 'details.json' else data
        with patch.object(Path, 'read_bytes', read):
            with self.assertRaisesRegex(ValueError, 'export SHA changed'):
                self.tool().replay()

    def test_changed_source_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data + b'changed' if path.suffix == '.exe' else data
        with patch.object(Path, 'read_bytes', read):
            with self.assertRaisesRegex(ValueError, 'source SHA changed'):
                self.tool().replay()

    def test_unreviewed_comparator_contract_is_rejected(self):
        tool = self.tool()
        tool.LEAVES[0x14145f1e0] = (0x47, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'leaf changed'):
            tool.replay()


if __name__ == '__main__':
    unittest.main()
