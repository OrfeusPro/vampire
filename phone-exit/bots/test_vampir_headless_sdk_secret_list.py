"""Native list assembly and atomic portable secret-configuration decode."""
import base64
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.sdk_secret import decode_sdk_secret_constants


@unittest.skipUnless(importlib.util.find_spec('cryptography'), 'Optional crypto backend is unavailable')
class SecretConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = cls.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
        cls.body = base64.b64encode(der).decode('ascii')

    def seal(self, fragments):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        return json.dumps([base64.b64encode(self.key.public_key().encrypt(raw,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode('ascii')
                           for raw in fragments], separators=(',', ':'))

    def test_real_multichunk_config_unicode_and_trailing_nul(self):
        text = self.seal([b'"clientId":"synthetic"', '"name":"Карта 😀"'.encode('utf-8'),
                          b'"enabled":true,"items":[1,2]\0'])
        self.assertEqual(decode_sdk_secret_constants(text, self.body),
                         dict(clientId='synthetic', name='Карта 😀', enabled=True, items=[1, 2]))
        self.assertEqual(decode_sdk_secret_constants('[]', ''), {})

    def test_second_chunk_failure_and_invalid_json_never_return_partial(self):
        valid = json.loads(self.seal([b'"first":"synthetic-secret"']))[0]
        for text in [json.dumps([valid, 'AA==']), self.seal([b'"first":1', b'']),
                     self.seal([b'"first":1', b'"broken":']), self.seal([b'"first":1', b'\xff']),
                     self.seal([b'"same":1', b'"same":2']), self.seal([b'"value":NaN']),
                     self.seal([b'"value":1e999']),
                     self.seal([b'"value":1\0\0'])]:
            with self.assertRaises(ValueError) as error:
                decode_sdk_secret_constants(text, self.body)
            self.assertEqual(str(error.exception), 'Invalid SDK secret configuration')
            self.assertNotIn(valid, str(error.exception))

    def test_outer_shape_input_and_item_budgets(self):
        for text in [None, b'[]', 'x'*2049, 'null', '{}', '[1]', '[null]', '[[]]', '[""]',
                     json.dumps(['AA==']*17), '"'+'😀'*1100+'"']:
            with self.assertRaises(ValueError):
                decode_sdk_secret_constants(text, self.body)


class SecretListEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-secret-list.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native secret-list evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    @staticmethod
    def fixture_decoder(case):
        mapping = dict(zip(json.loads(case['input']), [bytes.fromhex(v) for v in case['fixture_plaintexts_utf8_hex']]))
        def decode(ciphertext, key):
            if ciphertext not in mapping:
                raise ValueError('Unknown synthetic ciphertext')
            return mapping[ciphertext]
        return decode

    def test_source_code_tool_and_assembly_anchors(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-secret-list.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments']+r['conversion_fragments'] for i in f['instructions']}
        for f in r['fragments']+r['conversion_fragments']:
            raw = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), f['sha256'])
            self.assertEqual(raw, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        self.assertEqual(rows[0x1444ddd4a]['direct_target'], 0x14451d5c0)
        self.assertEqual(rows[0x1444ddd55]['operands'], '0x1444dde17')
        self.assertEqual(rows[0x1444dddb9]['operands'], 'word ptr [rax + rcx*2 - 2], 0x7d')
        self.assertEqual(rows[0x14451d9ce]['operands'], 'byte ptr [rbx + rsi - 1], dil')

    def test_common_assembly_matches_native_and_rejects_ambiguous_json(self):
        self.assertEqual(self.report['statistics'], dict(native_assembly_cases=9, boundary_cases=4))
        accepted = 0
        for case in self.report['cases']:
            with patch('vampir_core.sdk_secret.decrypt_sdk_secret_chunk', side_effect=self.fixture_decoder(case)):
                if case['outcome'] == 'empty_list':
                    self.assertEqual(decode_sdk_secret_constants(case['input'], 'fixture'), {})
                elif case['outcome'] == 'empty_chunk' or case['assembled'] in ('{"notJson":}', '{"same":1,"same":2}'):
                    with self.assertRaises(ValueError):
                        decode_sdk_secret_constants(case['input'], 'fixture')
                else:
                    self.assertEqual(decode_sdk_secret_constants(case['input'], 'fixture'), json.loads(case['assembled']))
                    accepted += 1
        self.assertEqual(accepted, 4)

    def test_reexecute_native_control_flow_using_explicit_plaintext_fixtures(self):
        spec = importlib.util.spec_from_file_location('secret_list_replay',
                        HERE/'resource-tools/vampir/build-headless-sdk-secret-list.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.SecretListEmulator()
        for case in self.report['cases']:
            emulator.decrypt = self.fixture_decoder(case)
            replay = emulator.run(case['input'], 'fixture')
            for key, value in replay.items():
                self.assertEqual(value, case[key])


if __name__ == '__main__':
    unittest.main()
