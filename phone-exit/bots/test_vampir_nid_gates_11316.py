import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class NidGates11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('nid_gates_test', HERE/'replay-nid-gates-11316.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_availability_boundaries_and_account_precedence(self):
        report = self.tool().replay()
        self.assertFalse(report['network_ready'])
        self.assertEqual(len(report['gate_cases']), 112)
        self.assertEqual(len(report['account_cases']), 512)
        for case in report['gate_cases']:
            expected = '0x1450e3d89' if not case['url_lookup_success'] else (
                '0x1450e3edd' if case['client_id_count'] <= 1 else '0x1450e4058')
            self.assertEqual(case['stop'], expected)
            self.assertTrue(case['canaries_unchanged'])
        for case in report['account_cases']:
            keys = [key for key, value in case['pairs']]
            if case['nid_token_count'] > 1:
                self.assertEqual(keys, ['accessToken'])
                self.assertFalse(any(e[0] in ('ready', 'getter') for e in case['events']))
            elif case['ready'] and case['state'] in (0, 100):
                self.assertEqual(keys, ['playerId', 'joinedCountryCode', 'accessToken'])
                self.assertEqual(all(value == '' for key, value in case['pairs']), case['empty_sdk'])
            else: self.assertEqual(keys, [])
            self.assertTrue(case['canaries_unchanged'])

    def test_corrupted_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name == 'details.json' else data
        with patch.object(Path, 'read_bytes', read):
            with self.assertRaisesRegex(ValueError, 'export SHA changed'): self.tool().replay()


if __name__ == '__main__': unittest.main()
