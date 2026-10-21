"""Real public SDK envelope plus synthetic PKCS1/PKCS8 and transport policies."""
import base64
from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from vampir_test_sources import historical_exe_reads

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.gmc2_response import decode_gmc2_configuration
from vampir_core.sdk_config import lookup_sdk_url_value
from vampir_core.sdk_secret import decrypt_sdk_secret_chunk
from vampir_core.cdn_config import _load_object
from vampir_core.auth_request import plan_authorization_code, bind_token_request


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / 'resource-tools/vampir' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicGmc2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile_tool = load('gmc2_public_profile_test', 'build-headless-gmc2-public-profile.py')
        cls.fetch_tool = load('gmc2_public_fetch_test', 'fetch-public-gmc2-config.py')
        cls.decode_tool = load('gmc2_public_decode_test', 'decode-public-gmc2-config.py')
        stored=json.loads((cls.fetch_tool.ROOT/'code-clues/headless-gmc2-public-profile.json').read_text('utf-8'))
        cls.enterClassContext(historical_exe_reads(stored['source'],stored['sha256']))
        cls.profile = cls.fetch_tool.profile()
        cls.folder = cls.fetch_tool.ROOT / 'public-gmc2-snapshots' / cls.decode_tool.SNAPSHOT
        cls.manifest = json.loads((cls.folder / 'manifest.json').read_text('utf-8'))
        cls.body = (cls.folder / 'body.bin').read_bytes()

    def test_profile_source_service_binding_and_reproducible_report(self):
        self.assertEqual(json.loads(json.dumps(self.profile_tool.build())), self.profile)
        self.assertEqual(self.profile['profile']['service_code'], 'netmarbles')
        self.assertEqual(self.profile['profile']['build_code'], 0)
        self.assertFalse(self.profile['active_settings_verified'])
        self.assertEqual(dict(self.profile['request']['headers'])['nmDeviceKey'], '')
        raw = Path(self.profile['source']).read_bytes()
        for fragment in self.profile['fragments']:
            data = b''.join(bytes.fromhex(row['bytes']) for row in fragment['instructions'])
            self.assertEqual(raw[fragment['file_offset']:fragment['file_offset'] + len(data)], data)
        for literal in self.profile['literals']:
            data = bytes.fromhex(literal['bytes'])
            self.assertEqual(raw[literal['file_offset']:literal['file_offset'] + len(data)], data)

    def test_real_success_response_and_offline_decoding(self):
        self.assertEqual(hashlib.sha256((self.folder / 'manifest.json').read_bytes()).hexdigest(), self.decode_tool.SNAPSHOT)
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), self.manifest['body_sha256'])
        self.assertEqual(len(self.body), 13788)
        self.assertEqual(self.manifest['transport']['status'], 200)
        with patch.object(self.fetch_tool.urllib.request, 'build_opener', side_effect=AssertionError('offline')):
            result = decode_gmc2_configuration(self.body, self.manifest['transport']['headers'])
            summary = self.decode_tool.build()
        self.assertEqual((result.normal_count, result.secret_count, len(result.constants)), (93, 1, 94))
        self.assertEqual(summary['merged_count'], 94)
        for key in ('authTokenUrl', 'authAccountUrl', 'authUrl'):
            self.assertIsNotNone(lookup_sdk_url_value(dict(result.constants), key))
            self.assertNotIn(result.constants[key], repr(result))
        self.assertIn('nidEncryptKey', result.constants)
        self.assertNotIn(result.constants['nidEncryptKey'], repr(result))
        with self.assertRaises(TypeError):
            result.constants['new'] = 'value'
        first = dict(result.constants)
        second = decode_gmc2_configuration(self.body, self.manifest['transport']['headers'])
        self.assertIsNot(result.constants, second.constants)
        self.assertEqual(first, dict(second.constants))
        draft = plan_authorization_code(client_id='client-fixture', device_key='device-fixture', code='unused-code-fixture')
        bound = bind_token_request(draft, dict(result.constants))
        self.assertEqual(bound.method, 'POST')
        self.assertEqual(bound.body, draft.body)
        self.assertTrue(bound.url.endswith('/v2/access-token'))
        self.assertNotIn('unused-code-fixture', repr(bound))

    def test_synthetic_pkcs1_pkcs8_full_envelopes_and_override(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        normal = {'authTokenUrl': 'https://auth.invalid', 'Case': 'old'}
        fragment = b'"case":"new","nidEncryptKey":"fixture"\0'
        ciphertext = private.public_key().encrypt(fragment, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        chunk = base64.b64encode(ciphertext).decode('ascii')
        for fmt in (serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8):
            der = private.private_bytes(serialization.Encoding.DER, fmt, serialization.NoEncryption())
            key = base64.b64encode(der).decode('ascii')
            def encrypt(text):
                units = struct.unpack('<' + 'H' * len(text), text.encode('utf-16le'))
                return struct.pack('<' + 'H' * len(units), *(u ^ ord(key[i % len(key)]) for i, u in enumerate(units))).decode('utf-16le')
            outer = {'errorCode': 0, 'resultData': {'encConstants': encrypt(json.dumps(normal)),
                'encSecretConstants': encrypt(json.dumps([chunk]))}}
            body = json.dumps(outer).encode('utf-8')
            result = decode_gmc2_configuration(body, [('dEcKeY', key)])
            self.assertEqual(dict(result.constants), {'authTokenUrl': 'https://auth.invalid', 'case': 'new', 'nidEncryptKey': 'fixture'})
            self.assertEqual(decrypt_sdk_secret_chunk(chunk, key), fragment)
            with self.assertRaises(ValueError):
                decrypt_sdk_secret_chunk(chunk, base64.b64encode(der + b'trailing').decode())

    def test_envelope_failures_do_not_expose_key_or_partial_constants(self):
        headers = self.manifest['transport']['headers']
        key = next(v for k, v in headers if k.lower() == 'deckey')
        variants = [[], [('DECKEY', '')], [('DECKEY', key), ('deckey', key)], [('DECKEY', 'key\n')]]
        for changed in variants:
            with self.assertRaises(ValueError) as error:
                decode_gmc2_configuration(self.body, changed)
            self.assertNotIn(key[:30], str(error.exception))
        outer = json.loads(self.body)
        for mutate in (lambda d: d.update(errorCode=False), lambda d: d.update(errorCode=1),
                       lambda d: d.update(resultData=[]), lambda d: d['resultData'].update(encConstants=None),
                       lambda d: d['resultData'].update(encSecretConstants='bad')):
            changed = json.loads(self.body)
            mutate(changed)
            with self.assertRaises(ValueError):
                decode_gmc2_configuration(json.dumps(changed).encode(), headers)
        self.assertIn('\0', outer['resultData']['encConstants'])
        with self.assertRaises(ValueError):
            _load_object('{"x":"\\u0000"}')  # CDN/plaintext policy remains strict.

    def test_public_transport_rejects_credentials_and_redirect_policy(self):
        request = self.profile['request']
        for update in ({'url': 'https://elsewhere.invalid'}, {'method': 'POST'},
                       {'headers': request['headers'] + [['accessToken', 'fixture']]},
                       {'headers': [[k, 'identity' if k == 'nmDeviceKey' else v] for k, v in request['headers']]}):
            with patch.object(self.fetch_tool.urllib.request, 'build_opener') as opener:
                with self.assertRaises(ValueError):
                    self.fetch_tool.fetch({**request, **update})
                opener.assert_not_called()
        self.assertIsNone(self.fetch_tool.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.invalid'))

    def test_public_transport_tls_identity_body_limits_and_status_capture(self):
        class Response(io.BytesIO):
            code = 200
            def __init__(self, body=b'abc', fields=()):
                super().__init__(body)
                self.headers = Message()
                for key, value in fields:
                    self.headers[key] = value
            def geturl(self):
                return self_url
        self_url = self.profile['request']['url']
        opener = Mock()
        opener.open.return_value = Response(fields=[('Content-Length', '3'), ('DECKEY', 'synthetic')])
        with patch.object(self.fetch_tool.urllib.request, 'build_opener', return_value=opener) as build:
            body, info = self.fetch_tool.fetch(self.profile['request'])
        self.assertEqual(body, b'abc')
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertTrue(build.call_args.args[2]._context.check_hostname)
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 10)
        self.assertTrue(info['tls_certificate_verification'])
        self.assertFalse(info['account_credentials_sent'])
        for response in (Response(fields=[('Content-Encoding', 'gzip')]),
                         Response(fields=[('Content-Length', '2'), ('Content-Length', '3')]),
                         Response(fields=[('Content-Length', '4')]),
                         Response(b'x' * (self.fetch_tool.MAX_BODY + 1))):
            opener.open.return_value = response
            with patch.object(self.fetch_tool.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaises(ValueError):
                    self.fetch_tool.fetch(self.profile['request'])

    def test_public_snapshot_immutable_and_bound_to_body(self):
        body = b'fixture'
        report = dict(body_sha256=self.fetch_tool.digest(body))
        with tempfile.TemporaryDirectory() as temp, patch.object(self.fetch_tool, 'ROOT', Path(temp)):
            path, identity = self.fetch_tool.save(report, body)
            self.assertEqual(self.fetch_tool.save(report, body), (path, identity))
            with self.assertRaises(ValueError):
                self.fetch_tool.save(report, b'changed')
            (path.parent / 'body.bin').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                self.fetch_tool.save(report, body)


if __name__ == '__main__':
    unittest.main()
