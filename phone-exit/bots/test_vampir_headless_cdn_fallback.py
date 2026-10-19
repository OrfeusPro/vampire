"""Native fallback orchestration evidence and portable envelope decoder."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_fallback import decrypt_cdn_fallback
from vampir_core.cdn_response import MAX_BODY_BYTES, decode_cdn_body_text, take_cdn_length_response


class CdnFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-fallback.py'
        spec = importlib.util.spec_from_file_location('cdn_fallback_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-fallback.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.body.head.headers.uri.http.preparation.url.settings.config.native.Image(cls.raw)
        cls.key = hashlib.sha256(cls.report['seed_literal']['text'].encode()).digest()

    def test_source_seed_cipher_name_and_descriptor_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for row in self.report['anchors'] + [self.report['seed_literal']] + [i for f in self.report['fragments'] for i in f['instructions']]:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        binding = self.report['cipher_name_binding']
        for name in ('name', 'record'):
            off, data = binding[name + '_file_offset'], bytes.fromhex(binding[name + '_bytes'])
            self.assertEqual(self.raw[off:off + len(data)], data)
        self.assertEqual(binding['nid'], 427)
        for anchor in self.report['anchors'][1:]:
            self.assertEqual(struct.unpack_from('<4I', bytes.fromhex(anchor['bytes'])), (427, 16, 32, 16))
        self.assertFalse(self.report['network_ready'])

    def test_native_orchestration_replays_capture_real_split_and_cleanup(self):
        cases = self.report['cases'] + self.report['failure_cases'] + [self.report['alternate_descriptor_case']]
        self.assertEqual(len(cases), 21)
        for case in cases:
            payload = bytes.fromhex(case['payload_hex'])
            emulator = self.module.FallbackEmulator(self.raw, self.image, self.report['fragments'],
                        fail=case['fail_fixture'], cpu_flags=case['cpu_flags_fixture'])
            self.assertEqual(emulator.decrypt(payload), case)
            self.assertTrue(case['evp_context_freed'])
            self.assertTrue(case['crypto_primitives_are_backend_shims'])
            if len(payload) >= 16:
                captured = case['captured']
                self.assertEqual(captured['key_hex'], self.key.hex())
                self.assertEqual(bytes.fromhex(captured['iv_hex']), payload[:16])
                if case['fail_fixture'] != 'init':
                    self.assertEqual(bytes.fromhex(captured['ciphertext_hex']), payload[16:])
            else:
                self.assertEqual(case['captured'], {})
        self.assertNotEqual(self.report['alternate_descriptor_case']['captured']['cipher_descriptor'],
                            self.report['cases'][8]['captured']['cipher_descriptor'])
        self.assertTrue(all(c['output_hex'] == '' for c in self.report['failure_cases']))

    def test_portable_matches_synthetic_native_success_vectors(self):
        expected = [b'', b'{}', b'{"NetmarbleS":{"Zone":"real"}}', 'Привет'.encode(),
                    b'a\0b', b'x' * 15, b'x' * 16, b'x' * 128]
        for case, plain in zip(self.report['cases'][6:14], expected):
            self.assertEqual(bytes.fromhex(case['output_hex']), plain)
            self.assertEqual(decrypt_cdn_fallback(bytes.fromhex(case['payload_hex'])), plain)

    def test_bad_padding_and_truncation_do_not_return_partial_plaintext(self):
        for case in self.report['cases'][:6] + self.report['cases'][14:]:
            payload = bytes.fromhex(case['payload_hex'])
            self.assertEqual(case['output_hex'], '')
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                decrypt_cdn_fallback(payload)
        for bad_pad in [b'\0' * 16, b'\x11' * 16, b'x' * 14 + b'\1\2']:
            payload = self.module.encrypt_fixture(bad_pad, self.key, bytes(16), pad=False)
            with self.assertRaises(ValueError):
                decrypt_cdn_fallback(payload)

    def test_iv_variants_boundaries_and_raw_nul_preservation(self):
        for iv in [bytes(16), bytes(range(16)), b'\xff' * 16]:
            for plain in [b'', b'a', b'x' * 31, b'\0{}\0', bytes(range(256))]:
                payload = self.module.encrypt_fixture(plain, self.key, iv)
                self.assertEqual(decrypt_cdn_fallback(payload), plain)
        for value in [bytearray(32), b'x' * (MAX_BODY_BYTES + 16), b'x' * 33]:
            with self.assertRaises(ValueError) as caught:
                decrypt_cdn_fallback(value)
            self.assertNotIn('xxxxxxxx', str(caught.exception))
        largest = b'x' * (MAX_BODY_BYTES - 32)
        payload = self.module.encrypt_fixture(largest, self.key, bytes(16))
        self.assertEqual(len(payload), MAX_BODY_BYTES)
        self.assertEqual(decrypt_cdn_fallback(payload), largest)

    def test_complete_http_body_to_decrypted_text_without_json_application(self):
        plain = '{"NetmarbleS":{"Zone":"real"},"name":"Вампир"}'
        encrypted = self.module.encrypt_fixture(plain.encode(), self.key, bytes(range(16)))
        header = f'HTTP/1.1 200\r\nContent-Length: {len(encrypted)}\r\n\r\n'.encode()
        self.assertIsNone(take_cdn_length_response(header + encrypted[:-1]))
        response = take_cdn_length_response(header + encrypted + b'next')
        self.assertEqual(response.consumed, len(header) + len(encrypted))
        self.assertEqual(decode_cdn_body_text(decrypt_cdn_fallback(response.body)), plain)

    def test_optional_backend_failure_is_clear_and_not_silent(self):
        import builtins
        original = builtins.__import__
        def without_crypto(name, *args, **kwargs):
            if name.startswith('cryptography'):
                raise ImportError('synthetic missing backend')
            return original(name, *args, **kwargs)
        payload = bytes.fromhex(self.report['cases'][8]['payload_hex'])
        with patch('builtins.__import__', side_effect=without_crypto), self.assertRaisesRegex(RuntimeError, 'optional cryptography'):
            decrypt_cdn_fallback(payload)


if __name__ == '__main__':
    unittest.main()
