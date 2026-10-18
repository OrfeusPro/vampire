"""Actual client OAEP validation, independent RSA backend and bounded chunk API."""
import base64
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.sdk_secret import decrypt_sdk_secret_chunk


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'Optional crypto backend is unavailable')
class SDKSecretChunkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.keys = []
        for bits in (2048, 3072, 4096):
            key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
            cls.keys.append((key, base64.b64encode(der).decode('ascii')))

    def test_real_backend_chunks_at_boundaries(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        for key, body in self.keys:
            for size in (0, 1, 32, key.key_size//8-66):
                plain = bytes((i*73)&255 for i in range(size))
                encrypted = key.public_key().encrypt(plain, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                          algorithm=hashes.SHA256(), label=None))
                self.assertEqual(decrypt_sdk_secret_chunk(base64.b64encode(encrypted).decode('ascii'), body), plain)

    def test_wrong_padding_label_key_size_and_sanitized_errors(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        key, body = self.keys[0]
        for pad in [padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b'wrong'),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None),
                    padding.PKCS1v15()]:
            text = base64.b64encode(key.public_key().encrypt(b'synthetic', pad)).decode('ascii')
            with self.assertRaises(ValueError):
                decrypt_sdk_secret_chunk(text, body)
        for text, bad_body in [('AA==', body), ('', body), ('AA==', 'not-a-private-key'),
                               ('AA==', body+'\n'), ('AA==', 'x'*8193), ('AA==', None)]:
            with self.assertRaises(ValueError) as error:
                decrypt_sdk_secret_chunk(text, bad_body)
            self.assertNotIn('not-a-private-key', str(error.exception))
            self.assertNotIn(body[:40], str(error.exception))


class ClientOAEPEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-oaep.json'
        if not path.exists():
            raise unittest.SkipTest('Generate client OAEP evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_loop_caller_key_format_and_tool_provenance(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-oaep.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments']+r['caller_fragments'] for i in f['instructions']}
        for f in r['fragments']+r['caller_fragments']:
            raw = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), f['sha256'])
            self.assertEqual(raw, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        fmt = r['key_format']
        raw = bytes.fromhex(fmt['bytes'])
        self.assertEqual(self.raw[fmt['file_offset']:fmt['file_offset']+len(raw)], raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), fmt['sha256'])
        self.assertEqual(rows[0x14451d6f2]['rip_references'], [fmt['address']])
        self.assertEqual(raw, b'-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\0')

    def test_native_results_and_public_rsa_relation(self):
        r = self.report
        self.assertEqual(r['statistics'], dict(valid_cases=24, invalid_cases=69))
        self.assertEqual([key['bits'] for key in r['public_keys']], [2048, 3072, 4096])
        for case in r['valid_cases']:
            self.assertEqual(case['result'], len(bytes.fromhex(case['output_hex'])))
            key = r['public_keys'][case['key_index']]
            self.assertEqual(pow(int.from_bytes(bytes.fromhex(case['encoded_hex']), 'big'), key['e'], int(key['n'])),
                             int.from_bytes(bytes.fromhex(case['ciphertext_hex']), 'big'))
        for case in r['invalid_cases']:
            self.assertEqual(case['result'], -1)
            self.assertEqual(case['output_hex'], '')
        # Reports must contain no private RSA key material.
        self.assertEqual(set(r['public_keys'][0]), {'bits', 'n', 'e'})

    def test_reexecute_client_oaep_valid_short_invalid_and_capacity(self):
        spec = importlib.util.spec_from_file_location('oaep_replay', HERE/'resource-tools/vampir/build-headless-sdk-oaep.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.OAEPEmulator()
        for case in self.report['valid_cases'][::3]+self.report['invalid_cases'][::8]:
            replay = emulator.run(bytes.fromhex(case['encoded_hex']), case['num'], case['capacity'],
                                  bytes.fromhex(case['label_hex']))
            for key, value in replay.items():
                self.assertEqual(value, case[key])


if __name__ == '__main__':
    unittest.main()
