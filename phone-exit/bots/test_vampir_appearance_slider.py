import importlib.util
from pathlib import Path
import struct
import unittest


class AppearanceSliderTests(unittest.TestCase):
    def test_native_handler_normalizes_and_stores_before_preview(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-release-appearance-slider.py'
        spec = importlib.util.spec_from_file_location('appearance_slider_check', path)
        tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 44)
        for case in report['cases'][:42]:
            self.assertEqual(bytes.fromhex(case['stored_float_hex']), struct.pack('<f', case['value'] / case['scale']))
            self.assertEqual(case['events'], ['hash', 'slot_lookup', 'key_copy', 'json_capture', 'preview_capture', 'refresh_capture'])
            self.assertTrue(case['guards_unchanged'])
        self.assertEqual([case['events'] for case in report['cases'][42:]], [[], []])
        values = [struct.unpack('<f', bytes.fromhex(case['stored_float_hex']))[0] for case in report['cases'][:42]]
        self.assertIn(-0.25, values)
        self.assertIn(1.25, values)


if __name__ == '__main__': unittest.main()
