"""Pinned negative key trial plus independent synthetic PAK hash controls."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent


class CdnPakKeyProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/probe-cdn-key-in-pak.py'
        spec = importlib.util.spec_from_file_location('cdn_pak_probe_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_current_pinned_report_rebuild_and_scoped_negative_result(self):
        report_path = self.module.ROOT / 'code-clues/cdn-pak-key-probe.json'
        report = json.loads(report_path.read_text('utf-8'))
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), report['tool_sha256'])
        self.assertEqual(self.module.build(), report)
        self.assertEqual(len(report['controls']), 8)
        self.assertTrue(all(c['sha1_matches'] for c in report['controls']))
        self.assertEqual(sum(c['sha1_matches'] is False for c in report['trials']), 18)
        self.assertEqual(sum(c['sha1_matches'] is None for c in report['trials']), 23)
        self.assertEqual(report['encrypted_records_total'], 75)
        self.assertEqual(report['matches'], 0)
        self.assertFalse(report['directory_trial']['ciphertext_sha1_matches'])
        self.assertEqual(report['directory_trial']['matching_plaintext_trims'], [])
        self.assertFalse(report['network_ready'])

    def test_plain_encrypted_positive_wrong_key_and_record_integrity(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key, plain = bytes(range(32)), b'known config bytes'
        for encrypted in (False, True):
            stored = plain
            if encrypted:
                encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
                stored = encryptor.update(plain.ljust(32, b'\0')) + encryptor.finalize()
            header = struct.pack('<qqqI', 0, len(plain), len(plain), 0) + hashlib.sha1(plain).digest()
            raw = header + bytes([encrypted]) + bytes(4) + stored
            row = dict(entry=1, offset=0, end=len(raw), bytes=len(plain), uncompressed=len(plain),
                       method=0, encrypted=encrypted, stored_record_sha256=hashlib.sha256(raw).hexdigest())
            result = self.module.probe_record(io.BytesIO(raw), row, len(raw), key)
            self.assertTrue(result['sha1_matches'])
            self.assertEqual(result['candidate_plaintext_sha256'], hashlib.sha256(plain).hexdigest())
            self.assertFalse(result['plaintext_saved'])
            if encrypted:
                self.assertFalse(self.module.probe_record(io.BytesIO(raw), row, len(raw), bytes(32))['sha1_matches'])
                truncated = raw[:53 + len(plain)]
                short_row = {**row, 'end': len(truncated), 'stored_record_sha256': hashlib.sha256(truncated).hexdigest()}
                result = self.module.probe_record(io.BytesIO(truncated), short_row, len(truncated), key)
                self.assertIsNone(result['sha1_matches'])
                self.assertIn('bounds', result['skipped'])
            with self.assertRaises(ValueError):
                self.module.probe_record(io.BytesIO(raw[:-1] + bytes([raw[-1] ^ 1])), row, len(raw), key)
            with self.assertRaises(ValueError):
                self.module.probe_record(io.BytesIO(raw), {**row, 'offset': -1}, len(raw), key)

    def test_directory_hash_padding_and_ciphertext_bounds(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key, plain, offset = bytes(range(32)), b'known directory payload', 32
        padded = plain.ljust(32, b'\0')
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        stored = enc.update(padded) + enc.finalize()
        footer = (bytes(16) + b'\1' + struct.pack('<Iiqq', 0x5a6f12e1, 11, offset, len(stored))
                  + hashlib.sha1(plain).digest() + bytes(160))
        raw = bytes(offset) + stored + bytes(40) + footer
        result = self.module.probe_directory(io.BytesIO(raw), len(raw), key)
        self.assertEqual(result['matching_plaintext_trims'], [len(padded) - len(plain)])
        self.assertFalse(result['directory_parsed'])
        self.assertFalse(result['plaintext_saved'])
        wrong = self.module.probe_directory(io.BytesIO(raw), len(raw), bytes(32))
        self.assertEqual(wrong['matching_plaintext_trims'], [])
        damaged = bytearray(raw)
        footer_start = len(raw) - len(footer)
        struct.pack_into('<q', damaged, footer_start + 33, len(raw) + 16)
        with self.assertRaises(ValueError):
            self.module.probe_directory(io.BytesIO(damaged), len(damaged), key)


if __name__ == '__main__':
    unittest.main()
