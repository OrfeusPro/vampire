import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('entry_windows',
    Path(__file__).parent / 'resource-tools/vampir/build-entry-window-code.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EntryWindowCalls(unittest.TestCase):
    def test_signed_relative_target(self):
        data = b'\xe8' + struct.pack('<i', -21)
        result = module.direct_call_candidates(data, 0, len(data), lambda offset: 0x1000 + offset, {0xff0})
        self.assertEqual(result, [(0x1000, 0xff0)])

    def test_truncated_call_and_other_target_not_returned(self):
        for data in [b'\xe8\0', b'\xe8\0\0\0\0']:
            self.assertEqual(module.direct_call_candidates(data, 0, len(data), lambda offset: 0x1000 + offset, {0x2000}), [])

    def test_candidate_must_be_decoded_direct_call(self):
        good = dict(mnemonic='call', call=True, direct_target=0x2000, bytes='e801000000')
        self.assertTrue(module.checked_call(good, 0x2000))
        for changed in [None, dict(good, mnemonic='mov'), dict(good, bytes='ff10'),
                        dict(good, call=False), dict(good, direct_target=0x3000)]:
            self.assertFalse(module.checked_call(changed, 0x2000))

    def test_scan_respects_section_boundary(self):
        data = b'\0\xe8' + struct.pack('<i', 0)
        self.assertEqual(module.direct_call_candidates(data, 0, 3, lambda offset: offset, {6}), [])


if __name__ == '__main__':
    unittest.main()
