"""Native suffix transform agrees with independent AES-256 ECB for aligned fixtures."""
import importlib.util
import json
from pathlib import Path
import unittest
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.nid_storage_path import derive_nid_storage_suffix


class SdkNidSuffixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-sdk-nid-path-suffix.py'
        spec = importlib.util.spec_from_file_location('sdk_nid_suffix_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/sdk-nid-path-suffix-replay.json').read_text('utf-8'))

    def test_report_reproduces_and_source_edges_match(self):
        self.assertEqual(self.tool.build(), self.report)
        literals = {v['text'] for v in self.report['literals']}
        self.assertTrue({'sub', '%02X'} <= literals)
        rows = {r['address']: r for f in self.report['fragments'] for r in f['instructions']}
        self.assertIn(0x14151ecc0, rows[0x14150a559]['rip_references'])
        self.assertEqual(rows[0x14454cb92]['direct_target'], 0x1444e5ff0)
        self.assertEqual(rows[0x14454cc32]['direct_target'], 0x141525480)
        self.assertFalse(self.report['user_storage_read'])

    def test_native_transform_and_independent_cipher_result(self):
        self.assertEqual(len(self.report['cases']), 6)
        for case in self.report['cases']:
            fixture = case['fixture']
            if len(fixture['sub']) < 32:
                self.assertFalse(case['replaced'])
                self.assertIsNone(case['transformed_hex'])
                self.assertEqual(case['suffix'], 'old-suffix-fixture')
                continue
            transformed = bytes((ord(c) - 1) & 255 for c in fixture['sub'])
            self.assertEqual(case['transformed_hex'], transformed.hex())
            cipher = Cipher(algorithms.AES(fixture['nm_key'].encode('ascii')), modes.ECB()).encryptor()
            expected = (cipher.update(transformed) + cipher.finalize()).hex().upper()
            self.assertTrue(case['replaced'])
            self.assertEqual(case['suffix'], expected)
            self.assertEqual(derive_nid_storage_suffix(subject=fixture['sub'], nm_device_key=fixture['nm_key']), expected)

    def test_runtime_boundary_rejects_unverified_domain(self):
        key = '0123456789ABCDEF0123456789ABCDEF'
        for subject in ('', 'B' * 31, 'B' * 33, 'B' * 1040, '\0' * 32, 'я' * 32):
            with self.assertRaises(ValueError):
                derive_nid_storage_suffix(subject=subject, nm_device_key=key)
        for invalid in ('', key + '0', 'Z' * 32, 'я' * 32):
            with self.assertRaises(ValueError):
                derive_nid_storage_suffix(subject='B' * 32, nm_device_key=invalid)
        self.assertNotEqual(derive_nid_storage_suffix(subject='B' * 32, nm_device_key=key),
                            derive_nid_storage_suffix(subject='B' * 32, nm_device_key=key.lower()))


if __name__ == '__main__':
    unittest.main()
