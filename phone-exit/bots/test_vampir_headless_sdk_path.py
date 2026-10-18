"""Native path joining and offline token-request binding to SDK constants."""
import base64
import hashlib
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vampir-shared'))
from vampir_core.auth_request import bind_token_request, plan_authorization_code, plan_refresh_token, TokenRequestPlan
from vampir_core.sdk_config import append_sdk_path, merge_sdk_string_constants


class BoundTokenPlanTests(unittest.TestCase):
    def test_code_refresh_binding_slashes_body_and_redacted_repr(self):
        for plan in [plan_authorization_code(client_id='test', device_key='device', code='secret +/'),
                     plan_refresh_token(client_id='test', device_key='device', refresh_token='refresh +/')]:
            for base, result in [('https://auth.invalid/base', 'https://auth.invalid/base/v2/access-token'),
                                 ('https://auth.invalid/base/', 'https://auth.invalid/base/v2/access-token'),
                                 ('https://auth.invalid/base//', 'https://auth.invalid/base//v2/access-token')]:
                bound = bind_token_request(plan, {'AUTHTOKENURL': base})
                self.assertEqual(bound.url, result)
                self.assertIs(bound.body, plan.body)
                self.assertEqual(bound.method, 'POST')
                self.assertIn('grant_type', parse_qs(bound.body.decode('ascii')))
                self.assertNotIn('auth.invalid', repr(bound))
                self.assertNotIn('secret', repr(bound))

    def test_reject_unsupported_bases_metadata_and_path_budgets(self):
        plan = plan_authorization_code(client_id='test', device_key='device', code='code')
        for base in ['https://', 'http://', 'https://name:pass@auth.invalid/', 'https://auth.invalid/?x=1',
                     'https://auth.invalid/#part', 'https://auth.invalid/?', 'https://auth.invalid/\\',
                     'https://auth.invalid:99999/', 'https://auth.invalid/\t', 'https://auth.invalid/\u00a0',
                     'ftp://auth.invalid/']:
            with self.assertRaises(ValueError):
                bind_token_request(plan, {'authTokenUrl': base})
        with self.assertRaises(ValueError):
            bind_token_request(plan, {})
        with self.assertRaises(ValueError):
            bind_token_request(TokenRequestPlan(body=b'x', relative_path='unproven'), {'authTokenUrl': 'https://auth.invalid/'})
        for base, part in [(None, 'x'), ('x\0', 'x'), ('x'*4096, 'x'), ('😀'*3000, '')]:
            with self.assertRaises(ValueError):
                append_sdk_path(base, part)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'Optional crypto backend is unavailable')
    def test_secret_list_to_merged_map_to_bound_form_without_network(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from vampir_core.sdk_secret import decode_sdk_secret_constants
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        body = base64.b64encode(key.private_bytes(serialization.Encoding.DER,
                      serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())).decode('ascii')
        fragment = b'"authTokenUrl":"https://secret.invalid/base"'
        chunk = base64.b64encode(key.public_key().encrypt(fragment, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))).decode('ascii')
        secret = decode_sdk_secret_constants(json.dumps([chunk]), body)
        constants = merge_sdk_string_constants({'authTokenUrl': 'https://ordinary.invalid/', 'clientId': 'synthetic'}, secret)
        plan = plan_authorization_code(client_id=constants['clientId'], device_key='synthetic-device', code='synthetic-code')
        bound = bind_token_request(plan, constants)
        self.assertEqual(bound.url, 'https://secret.invalid/base/v2/access-token')
        self.assertEqual(parse_qs(bound.body.decode())['code'], ['synthetic-code'])


class SDKPathEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-path.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native SDK path evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_auth_callers_and_conversion_branches(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        tool = HERE/'resource-tools/vampir/build-headless-sdk-path.py'
        self.assertEqual(hashlib.sha256(tool.read_bytes()).hexdigest(), r['tool_sha256'])
        rows = {i['address']: i for f in r['fragments'] for i in f['instructions']}
        for f in r['fragments']:
            raw = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), f['sha256'])
            self.assertEqual(raw, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for record in r['constants']:
            raw = bytes.fromhex(record['bytes'])
            self.assertEqual(self.raw[record['file_offset']:record['file_offset']+len(raw)], raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
        for call, literal in [(0x1450e2b01, 0x1450e2af5), (0x1450e3451, 0x1450e3445)]:
            self.assertEqual(rows[call]['direct_target'], 0x14142c9d0)
            self.assertEqual(next(c['text'] for c in r['constants'] if c['instruction']['address'] == literal), 'v2/access-token')
        self.assertEqual(rows[0x1444769f8]['operands'], 'qword ptr [rax + 0x58]')

    def test_all_native_vectors_and_reexecution(self):
        self.assertEqual(self.report['statistics'], dict(native_path_cases=70))
        spec = importlib.util.spec_from_file_location('path_replay', HERE/'resource-tools/vampir/build-headless-sdk-path.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emulator = module.SDKPathEmulator()
        for case in self.report['cases']:
            self.assertEqual(append_sdk_path(case['base'], case['segment']), case['result'])
            self.assertEqual(emulator.append(case['base'], case['segment'], case['empty_count']), case)


if __name__ == '__main__':
    unittest.main()
