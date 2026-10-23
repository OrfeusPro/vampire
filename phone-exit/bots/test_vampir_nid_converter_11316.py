import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class NidConverter11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('nid_converter_test', HERE/'replay-nid-converter-11316.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_all_bytes_and_real_caller_gates(self):
        report = self.tool().replay()
        self.assertTrue(report['converter_native']); self.assertFalse(report['network_ready'])
        self.assertEqual(len(report['converter_cases']), 1024)
        self.assertEqual(len(report['cases']), 448)
        for case in report['converter_cases']:
            self.assertEqual(case['value'], {30:'steam', 31:'epic', 34:'xbox'}.get(case['byte'], 'sdk'))
            self.assertTrue(case['canaries_unchanged'])
        for case in report['cases']:
            fields = dict(case['pairs']); special = case['mode'] in (4, 5)
            self.assertEqual(fields['webViewType'], {30:'steam',31:'epic',34:'xbox'}.get(case['web'], 'sdk') if special else 'sdk')
            self.assertEqual('credential' in fields, special and case['optional'])
            self.assertFalse(any(event[0] == 'converter' for event in case['events']))

    def test_converter_export_corruption_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.parent.name == 'run-3ead5c3e47cf' and path.name == 'details.json' else data
        with patch.object(Path, 'read_bytes', read):
            with self.assertRaisesRegex(ValueError, 'export SHA changed'): self.tool().replay()


if __name__ == '__main__': unittest.main()
