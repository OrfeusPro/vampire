"""NID public browser contract, isolated JS padding replay and offline plan."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.nid_email import nid_js_string_bytes, encrypt_nid_field, plan_nid_email_sign_in


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / 'resource-tools/vampir' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NidEmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = load('email_index_test', 'build-headless-email-auth.py')
        cls.capture = load('nid_capture_test', 'capture-netmarble-auth-web.py')
        cls.inspect = load('nid_inspect_test', 'inspect-nid-auth-web.py')
        cls.report = json.loads((cls.inspect.ROOT / 'code-clues/nid-auth-web-evidence.json').read_text('utf-8'))
        cls.folder = cls.inspect.ROOT / 'auth-web-snapshots' / cls.inspect.SNAPSHOT

    def test_public_page_script_and_reviewed_source_anchors(self):
        self.assertEqual(hashlib.sha256((self.folder / 'manifest.json').read_bytes()).hexdigest(), self.inspect.SNAPSHOT)
        meta = json.loads((self.folder / 'manifest.json').read_text('utf-8'))
        for name in ('auth.html', 'auth.js'):
            self.assertEqual(hashlib.sha256((self.folder / name).read_bytes()).hexdigest(), meta['files'][name]['sha256'])
        script = (self.folder / 'auth.js').read_bytes()
        for row in self.report['anchors'] + [self.report['padding_function']] + self.report['request_functions']:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(script[row['byte_offset']:row['byte_offset'] + len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        self.assertEqual(self.report['relative_path'], '/api/signin/netmarble')
        self.assertEqual(self.report['expected_action'], 'members_signin')
        self.assertFalse(self.report['account_authentication_attempted'])

    def test_distinct_email_family_and_nid_browser_preparation_index(self):
        path = self.inspect.ROOT / 'code-clues/headless-email-auth.json'
        report = json.loads(path.read_text('utf-8'))
        self.assertEqual(json.loads(json.dumps(self.index.build())), report)
        self.assertEqual(len(report['symbols']), 19)
        self.assertEqual(len(report['references']), 20)
        self.assertEqual(len({f['root_begin_rva'] for f in report['fragments']}), 18)
        self.assertEqual(report['missing'], [])
        self.assertEqual(report['rejected'], [])
        names = {c['text'] for c in report['constants']}
        self.assertTrue({'emailAuthViewUrl', 'emailAuthTokenUrl', 'authWebViewUrl', 'channelAccessToken', 'members_signin'} - names == {'members_signin'})
        self.assertIn('emailauth/login?', names)
        self.assertFalse(report['native_execution'])

    def test_reviewed_js_padding_replay_and_cesu8_payload(self):
        self.assertEqual(self.inspect.build(), self.report)
        for case in self.report['replay']['cases']:
            if case['bytes'] is None:
                self.assertEqual(len(case['text']), 118)
                continue
            block = bytes(case['bytes'])
            self.assertEqual(block[:2], b'\0\2')
            separator = block.index(b'\0', 2)
            if case['text']:
                self.assertEqual(block[separator + 1:], nid_js_string_bytes(case['text']))
            else:
                self.assertEqual(block[separator + 1:], b'')
        self.assertEqual(nid_js_string_bytes('🔒'), bytes.fromhex('eda0bdedb492'))
        with self.assertRaises(ValueError):
            encrypt_nid_field('é' * 60, self.report['public_key_pem'])

    def test_local_rsa_and_request_fields_without_network(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
        context = dict(clientId='client-fixture', gameCode='thered', buildCode='A', deviceKey='device-fixture', osType='pc', webViewType='sdk')
        with patch('socket.create_connection', side_effect=AssertionError('offline plan')):
            plan = plan_nid_email_sign_in(email='user@example.invalid', password='pw-fixture🔒', public_key_pem=public,
                webview_url='https://members.netmarble.com/auth', context=context, recaptcha_token='captcha-fixture')
        body = json.loads(plan.body)
        self.assertEqual(plan.url, 'https://members.netmarble.com/api/signin/netmarble')
        self.assertEqual(plan.method, 'POST')
        self.assertEqual(body['expectedAction'], 'members_signin')
        self.assertEqual(body['reCaptchaScoreToken'], 'captcha-fixture')
        self.assertEqual(body['deviceKey'], 'device-fixture')
        for field, text in (('email', 'user@example.invalid'), ('password', 'pw-fixture🔒')):
            self.assertEqual(key.decrypt(base64.b64decode(body[field]), padding.PKCS1v15()), nid_js_string_bytes(text))
            self.assertNotIn(text, repr(plan))
        self.assertEqual(dict(plan.headers)['os'], 'pc')
        self.assertEqual(dict(plan.headers)['Pragma'], 'no-cache')
        self.assertNotIn('accessToken', dict(plan.headers))

    def test_reviewed_request_interceptor_matches_plan_context(self):
        cases = self.report['replay']['request_cases']
        self.assertEqual(cases[0]['result']['url'], '/api/signin/netmarble')
        self.assertEqual(cases[1]['result']['url'], '/api/already')
        self.assertEqual(cases[2]['result']['url'], 'https://members.netmarble.com/auth')
        plan = plan_nid_email_sign_in(email='user@example.invalid', password='password-fixture',
            public_key_pem=self.report['public_key_pem'], webview_url='https://members.netmarble.com/auth',
            context=cases[0]['params'], recaptcha_token='captcha-fixture')
        headers = dict(plan.headers)
        for name, value in cases[0]['result']['headers'].items():
            self.assertEqual(headers[name], value)

    def test_invalid_plaintext_context_key_and_captcha_are_rejected(self):
        for text in ('', 'secret\0', 'secret\r\n', '\ud800', 'x' * 4097, None):
            with self.assertRaises(ValueError) as error:
                nid_js_string_bytes(text)
            self.assertNotIn('secret', str(error.exception))
        for text in ('a' * 118, '🔒' * 20):
            with self.assertRaises(ValueError):
                encrypt_nid_field(text, self.report['public_key_pem'])
        args = dict(email='user@example.invalid', password='password-fixture', public_key_pem=self.report['public_key_pem'],
            webview_url='https://members.netmarble.com/auth', context=dict(clientId='c', gameCode='g', buildCode='A'), recaptcha_token='captcha-fixture')
        for changes in ({'recaptcha_token': ''}, {'context': {}}, {'context': {**args['context'], 'Cookie': 'fixture'}},
                        {'webview_url': 'http://members.netmarble.com/auth'},
                        {'webview_url': 'https://user:secret@members.netmarble.com/auth'},
                        {'public_key_pem': 'bad-key-fixture'}):
            with self.assertRaises(ValueError):
                plan_nid_email_sign_in(**{**args, **changes})

    def test_capture_scope_declared_script_and_immutable_files(self):
        self.assertEqual(self.capture.source_url(), 'https://members.netmarble.com/auth')
        html = (self.folder / 'auth.html').read_bytes()
        url = self.capture.module_url(html, 'https://members.netmarble.com/auth')
        self.assertEqual(url, self.report['sources']['auth.js']['url'])
        for url in ('http://members.netmarble.com/auth', 'https://elsewhere.invalid/assets/a.js',
                    'https://members.netmarble.com/assets/../a.js', 'https://members.netmarble.com/auth?code=fixture'):
            with self.assertRaises(ValueError):
                self.capture.checked_url(url)
        files = {'auth.html': b'html-fixture', 'auth.js': b'js-fixture'}
        report = dict(files={name: dict(sha256=self.capture.digest(body), size=len(body)) for name, body in files.items()})
        with tempfile.TemporaryDirectory() as temp, patch.object(self.capture, 'ROOT', Path(temp)):
            path, identity = self.capture.save(report, files)
            self.assertEqual(self.capture.save(report, files), (path, identity))
            with self.assertRaises(ValueError):
                self.capture.save(report, {'../escape': b'fixture'})
            (path.parent / 'auth.js').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                self.capture.save(report, files)


if __name__ == '__main__':
    unittest.main()
