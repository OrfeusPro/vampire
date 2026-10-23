import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class NidExtensions11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('nid_extensions_test', HERE/'replay-nid-extensions-11316.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_current_extension_dispatch_and_optional_gates(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 256)
        self.assertFalse(report['network_ready'])
        labels = ('signin', 'linkidp', 'withdraw', 'agreements', 'signin', 'linkidp')
        for case in report['cases']:
            fields = dict(case['pairs'])
            special = case['mode'] in (4, 5)
            self.assertEqual(fields['webViewType'], 'fixture-web-'+str(case['web'] if special else 0))
            self.assertEqual('credential' in fields, special and case['optional'])
            if case['mode'] < 6: self.assertEqual(fields['authType'], labels[case['mode']])
            else: self.assertNotIn('authType', fields)
            self.assertEqual(sum(e[0] == 'optional' for e in case['events']), int(special))
            self.assertTrue(case['canaries_unchanged'])

    def test_unverified_cleanup_tail_is_rejected(self):
        tool = self.tool(); tool.TAILS[0x1450e463f] = '90'
        with self.assertRaisesRegex(ValueError, 'instruction differs from source'): tool.replay()

    def test_corrupted_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name == 'details.json' else data
        with patch.object(Path, 'read_bytes', read):
            with self.assertRaisesRegex(ValueError, 'export SHA changed'): self.tool().replay()


if __name__ == '__main__': unittest.main()
