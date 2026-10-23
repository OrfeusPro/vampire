import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'


class WebPlatform11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('web_platform_test',HERE/'replay-web-platform-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_initialized_tls_and_console_override_gates(self):
        result=self.tool().replay()
        self.assertEqual(len(result['cases']),52)
        self.assertFalse(result['network_ready'])
        defaults=[c for c in result['cases'] if c['console_slots'] is None]
        self.assertEqual(len(defaults),4)
        for case in result['cases']:
            slots=case['console_slots']
            selected=3 if slots is None else slots[0 if case['first'] or case['second'] else 1]
            self.assertEqual(case['selected_byte'],selected)
            self.assertEqual(case['actual'],'PC' if selected==3 else '')
            expected=[] if slots is None else ['0x14148ee80']+([] if case['first'] else ['0x14148ee40'])
            self.assertEqual(case['predicate_calls'],expected)
            self.assertTrue(case['canaries_unchanged'])

    def test_changed_source_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):self.tool().replay()

    def test_changed_export_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):self.tool().replay()


if __name__=='__main__':unittest.main()
