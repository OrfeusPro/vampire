import importlib.util
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import parse_qsl, urlsplit

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.auth_request import _escape_ascii
from vampir_core.nid_web_context import NidWebContext
from vampir_core.nid_web_url import bind_nid_web_url


def context(**overrides):
    pairs = dict(gameCode='thered', buildCode='A', countryCode='KR', language='en-US', os='windows',
                 nmDeviceKey='nm-fixture', deviceKey='nid-fixture', osVersion='os-fixture',
                 clientId='client-fixture', nidV='3', webViewType='sdk', authType='signin')
    pairs.update(overrides)
    return NidWebContext(tuple(pairs.items()))


class NidWebUrlTests(unittest.TestCase):
    def bind(self, plan=None, **kwargs):
        params = dict(constants={'authWebViewUrl': 'https://members.netmarble.com/auth'}, max_url_size=32768)
        params.update(kwargs)
        return bind_nid_web_url(plan or context(), **params)

    def test_whole_native_ascii_encoder_reproduces_and_matches_shared_escape(self):
        path = HERE / 'resource-tools/vampir/replay-nid-query-encode.py'
        spec = importlib.util.spec_from_file_location('nid_query_encode_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/nid-query-encode-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 99)
        self.assertFalse(report['network_ready'])
        for case in report['cases']:
            self.assertEqual(_escape_ascii(case['value']) if case['value'] else '', case['encoded'])

    def test_url_parameters_roundtrip_and_no_secret_repr(self):
        plan = context(osVersion='a b+c&d=e%f/?#', countryCode='')
        result = self.bind(plan)
        parsed = urlsplit(result.url)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ('https', 'members.netmarble.com', '/auth'))
        self.assertEqual(tuple(parse_qsl(parsed.query, keep_blank_values=True)), plan.parameters)
        self.assertIn('osVersion=a%20b%2Bc%26d%3De%25f%2F%3F%23', result.url)
        self.assertNotIn('fixture', repr(result))

    def test_endpoint_from_verified_public_sdk_snapshot(self):
        path = HERE / 'resource-tools/vampir/capture-netmarble-auth-web.py'
        spec = importlib.util.spec_from_file_location('nid_auth_endpoint_test', path)
        capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capture)
        base = capture.source_url()  # Offline hashes + existing GMC2 decoder; no fetch.
        result = self.bind(constants={'authWebViewUrl': base})
        self.assertTrue(result.url.startswith(base + '?gameCode=thered&'))

    def test_endpoint_injection_and_unsupported_modes_rejected(self):
        for base in ('http://members.netmarble.com/auth', 'https://elsewhere.invalid/auth',
                     'https://members.netmarble.com/auth?next=x', 'https://members.netmarble.com/auth#x',
                     'https://user@members.netmarble.com/auth'):
            with self.assertRaises(ValueError): self.bind(constants={'authWebViewUrl': base})
        for params in (context(authType='linkidp'), context(webViewType='unknown'), context(nidV='4'),
                       context(deviceKey=''), context(clientId='')):
            with self.assertRaises(ValueError): self.bind(params)
        with self.assertRaises(ValueError): self.bind(NidWebContext(context().parameters + (('accessToken', 'unexpected'),)))

    def test_limits_unicode_and_malformed_context(self):
        with self.assertRaises(BufferError): self.bind(max_url_size=1)
        with self.assertRaises(ValueError): self.bind(max_url_size=True)
        with self.assertRaises(ValueError): self.bind(context(language='Українська'))
        with self.assertRaises(ValueError): self.bind(context(language='bad\0text'))
        with self.assertRaises(ValueError): self.bind(NidWebContext(tuple(reversed(context().parameters))))


if __name__ == '__main__': unittest.main()
