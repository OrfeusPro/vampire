"""Saved real CDN decoding plus bounded HTTPS policy using synthetic responses."""
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import Mock, patch

TOOL = Path(__file__).parent / 'resource-tools/vampir/fetch-public-cdn-config.py'
spec = importlib.util.spec_from_file_location('public_cdn_test_tool', TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Response(io.BytesIO):
    def __init__(self, body=b'abc', headers=None, status=200, url=module.PUBLIC_URL):
        super().__init__(body)
        self.status, self.url, self.headers = status, url, Message()
        for key, value in (headers or []):
            self.headers[key] = value

    def geturl(self):
        return self.url


class PublicCdnTests(unittest.TestCase):
    def test_explicit_socks_route_does_not_use_a_direct_opener(self):
        route = module.SocksRoute(17948)
        opener = Mock()
        opener.open.return_value = Response(headers=[('Content-Length', '3')])
        with patch.object(module.SocksRoute, 'opener', return_value=opener) as selected, \
                patch.object(module.urllib.request, 'build_opener', side_effect=AssertionError('Direct fallback')):
            body, metadata = module.fetch(module.PUBLIC_URL, route=route)
        self.assertEqual(body, b'abc')
        self.assertEqual(metadata['socks5_loopback_port'], 17948)
        self.assertIsInstance(selected.call_args.args[0], module.NoRedirect)
        with self.assertRaises(TypeError): module.fetch(module.PUBLIC_URL, route='17948')

    def test_saved_real_document_decodes_offline_with_source_profile(self):
        # Fixed historical input: a new public fetch must not change this fixture.
        identity = '4939dc4752684068106f52bc4954d3f8ebd43ff470fa43d1ae14e8f0d0a6736a'
        manifest = module.ROOT / 'public-cdn-snapshots' / identity / 'manifest.json'
        self.assertEqual(module.digest(manifest.read_bytes()), identity)
        report = json.loads(manifest.read_text('utf-8'))
        body = (manifest.parent / 'body.bin').read_bytes()
        # Historical immutable receipt belongs to the extractor before release support.
        self.assertIn(report['tool_sha256'], (module.digest(TOOL.read_bytes()),
            '8d9ce1d61917b424cea6ed6604b0706cf7a0f7a019d52d983d72647d2be6cf52'))
        self.assertEqual(module.digest(body), report['body_sha256'])
        self.assertEqual(len(body), 6000)
        self.assertEqual(module.profile(), report['profile'])
        with patch.object(module.urllib.request, 'build_opener', side_effect=AssertionError('No network in offline analysis')):
            result = module.analyze(body)
        self.assertEqual(result, report['analysis'])
        self.assertEqual(result['environment'], 'real')
        self.assertEqual(result['sdk_mode'], 2)
        self.assertEqual(result['server_selection']['entry_type'], 'REAL')
        self.assertEqual(result['server_selection']['lobby_port'], '12000')
        self.assertTrue(result['server_selection']['lobby_address'])
        for flag in ('config_applied', 'lobby_connection_attempted', 'authentication_attempted'):
            self.assertFalse(result[flag])
        self.assertFalse(report['active_runtime_settings_verified'])
        self.assertFalse(report['network_ready'])

    def test_new_release_url_is_bound_to_verified_source_and_same_route(self):
        profile = module.profile('recovered-release')
        self.assertEqual(profile['url'], module.RELEASE_URL)
        self.assertEqual(profile['config_snapshot_sha256'], 'c67314cea3e6d3f28f98073a6f6346b1fa0233143feb6e18e7e0914a152f4c7d')
        opener = Mock()
        opener.open.return_value = Response(url=module.RELEASE_URL)
        with patch.object(module.SocksRoute, 'opener', return_value=opener), \
                patch.object(module.urllib.request, 'build_opener', side_effect=AssertionError('Direct fallback')):
            body, metadata = module.fetch(profile['url'], route=module.SocksRoute(17948))
        self.assertEqual(body, b'abc')
        self.assertEqual(metadata['socks5_loopback_port'], 17948)
        with self.assertRaises(ValueError): module.profile('automatic')

    def test_transport_policy_and_valid_bounded_response(self):
        response = Response(headers=[('Content-Length', '3')])
        opener = Mock()
        opener.open.return_value = response
        with patch.object(module.urllib.request, 'build_opener', return_value=opener) as build:
            body, info = module.fetch(module.PUBLIC_URL)
        self.assertEqual(body, b'abc')
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], module.NoRedirect)
        self.assertIsNone(handlers[1].redirect_request(None, None, 302, '', {}, 'https://elsewhere.invalid'))
        context = handlers[2]._context
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        request = opener.open.call_args.args[0]
        self.assertIsNone(request.data)
        self.assertEqual(request.full_url, module.PUBLIC_URL)
        self.assertEqual(request.get_header('Accept-encoding'), 'identity')
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 10)
        self.assertTrue(info['tls_certificate_verification'])
        self.assertFalse(info['redirects_followed'])

    def test_transport_rejects_unexpected_framing_size_status_and_url(self):
        cases = [Response(status=302), Response(url='https://elsewhere.invalid'),
            Response(headers=[('Content-Encoding', 'gzip')]),
            Response(headers=[('Content-Length', '3'), ('Content-Length', '3')]),
            Response(headers=[('Content-Length', '-1')]),
            Response(headers=[('Content-Length', str(module.MAX_BODY + 1))]),
            Response(headers=[('Content-Length', '4')]),
            Response(b'x' * (module.MAX_BODY + 1))]
        for response in cases:
            opener = Mock()
            opener.open.return_value = response
            with self.subTest(headers=response.headers, status=response.status), \
                    patch.object(module.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaises(ValueError):
                    module.fetch(module.PUBLIC_URL)
        with patch.object(module.urllib.request, 'build_opener') as build:
            with self.assertRaises(ValueError):
                module.fetch('http://red.gcdn.netmarble.com/')
            build.assert_not_called()

    def test_timeout_certificate_failure_and_immutable_snapshot(self):
        opener = Mock()
        opener.open.return_value = Response()
        with patch.object(module.urllib.request, 'build_opener', return_value=opener), \
                patch.object(module.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaises(TimeoutError):
                module.fetch(module.PUBLIC_URL)
        opener.open.side_effect = ssl.SSLCertVerificationError('fixture')
        with patch.object(module.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(ssl.SSLCertVerificationError):
                module.fetch(module.PUBLIC_URL)
        body = b'fixture'
        report = dict(body_sha256=module.digest(body))
        with tempfile.TemporaryDirectory() as temp, patch.object(module, 'ROOT', Path(temp)):
            path, identity = module.save(report, body)
            self.assertEqual(module.save(report, body), (path, identity))
            with self.assertRaisesRegex(ValueError, 'body mismatch'):
                module.save(report, b'changed')
            (path.parent / 'body.bin').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'snapshot differs'):
                module.save(report, body)


if __name__ == '__main__':
    unittest.main()
