"""Native Base64 parity and source-bound RSA/OAEP call preparation."""
import hashlib
import importlib.util
import json
import os
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.sdk_constants import decode_sdk_base64


class SDKBase64LimitsTests(unittest.TestCase):
    def test_canonical_padding_zero_bytes_and_size_limit(self):
        self.assertEqual(decode_sdk_base64('AA=='), b'\0')
        self.assertEqual(decode_sdk_base64('AA'), b'\0')
        self.assertEqual(decode_sdk_base64('/+8='), b'\xff\xef')
        self.assertEqual(decode_sdk_base64(''), b'')
        self.assertEqual(decode_sdk_base64('A'*2048), bytes(1536))
        with self.assertRaises(ValueError):
            decode_sdk_base64('A'*2049)

    def test_reject_partial_noncanonical_and_non_ascii_inputs(self):
        for invalid in [None, b'AA==', 'A', 'AA$A', 'AA A', 'AAAA\n', 'АА==',
                        '====', 'AB==', 'AA====', 'AA=', '-_8=', 'AAA===']:
            with self.assertRaises(ValueError) as error:
                decode_sdk_base64(invalid)
            self.assertNotIn(str(invalid), str(error.exception))


class SDKSecretEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-secret.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native SDK secret evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_fragments_literals_descriptor_and_call_chain(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-secret.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments'] for i in f['instructions']}
        for f in r['fragments']:
            raw = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), f['sha256'])
            self.assertEqual(raw, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for record in r['data']+r['constants']:
            raw = bytes.fromhex(record['bytes'])
            self.assertEqual(self.raw[record['file_offset']:record['file_offset']+len(raw)], raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
        descriptor = next(d for d in r['data'] if d['address'] == 0x14a722610)
        self.assertEqual(struct.unpack_from('<III', bytes.fromhex(descriptor['bytes'])), (672, 668, 32))
        version = r['openssl_version']
        self.assertEqual(self.raw[version['file_offset']:version['file_offset']+len(bytes.fromhex(version['bytes']))],
                         b'OpenSSL 1.1.1t  7 Feb 2023\0')
        self.assertEqual(rows[0x14451d8dd]['direct_target'], 0x141523200)
        self.assertEqual(rows[0x14152329d]['direct_target'], 0x14150cd70)
        self.assertEqual(rows[0x14451d8fa]['direct_target'], 0x148404190)
        self.assertEqual(rows[0x14451d999]['direct_target'], 0x148405020)

    def test_all_native_vectors_and_oaep_arguments(self):
        self.assertEqual(self.report['statistics'], dict(base64_valid=26, base64_boundary=8, oaep_preparation=16))
        for case in self.report['valid_cases']:
            self.assertTrue(case['success'])
            self.assertEqual(decode_sdk_base64(case['input']), bytes.fromhex(case['output_hex']))
        for case in self.report['boundary_cases']:
            with self.assertRaises(ValueError):
                decode_sdk_base64(case['input'])
        for case in self.report['oaep_preparation']:
            self.assertEqual(case['digest'], 0x14a722610)
            self.assertEqual(case['digest'], case['mgf1_digest'])
            self.assertEqual((case['label_pointer'], case['label_size']), (0, 0))
            self.assertEqual(case['input_size'], case['rsa_result_size']-case['zero_prefix'])

    def test_reexecute_native_decoder_and_argument_preparation(self):
        spec = importlib.util.spec_from_file_location('secret_replay', HERE/'resource-tools/vampir/build-headless-sdk-secret.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.SDKSecretEmulator()
        for case in self.report['valid_cases'][::4]+self.report['boundary_cases']:
            self.assertEqual(emulator.decode(case['input']), case)
        for case in self.report['oaep_preparation']:
            self.assertEqual(emulator.prepare(case['rsa_result_size'], case['zero_prefix']), case)


if __name__ == '__main__':
    unittest.main()
