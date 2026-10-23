import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class NidResultSource11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('nid_result_source_test', HERE/'audit-nid-result-11316.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_current_routing_key_bindings_and_mode_mask(self):
        report = self.tool().audit()
        self.assertEqual(report['instructions_checked'], 1384)
        self.assertFalse(report['native_execution']); self.assertFalse(report['runtime_enabled'])
        self.assertEqual({r['text'] for r in report['bindings']},
            {'result','resultCode','accessToken','refreshToken','channelKey','netmarbleId','joinedCountryCode'})
        self.assertEqual(report['route']['address'],'0x1450f30bb')
        self.assertEqual(report['route']['references'],['0x1450f3e40'])
        self.assertIn('0xfffffffa',report['auth_mode_gate']['text'])
        self.assertTrue(all(len(r['instructions']) == 7 for r in report['bindings']))

    def test_changed_key_expectation_is_rejected(self):
        tool = self.tool(); tool.KEYS[0x14b5d5918] = 'wrong-key'
        with self.assertRaisesRegex(ValueError,'key binding differs'): tool.audit()

    def test_corrupted_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name == 'details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'): self.tool().audit()


if __name__ == '__main__': unittest.main()
