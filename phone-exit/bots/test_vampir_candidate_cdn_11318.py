"""Explicit current CDN source/route policy; all HTTP responses are synthetic."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_headless_public_cdn import Response

TOOL=Path(__file__).parent/'resource-tools/vampir/fetch-public-cdn-config.py'
spec=importlib.util.spec_from_file_location('candidate_cdn_11318_test',TOOL)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class CandidateCdn11318Tests(unittest.TestCase):
    def test_actual_current_loader_provenance_without_http(self):
        with patch.object(module.urllib.request,'build_opener',side_effect=AssertionError('No network')), \
                patch.object(module.SocksRoute,'opener',side_effect=AssertionError('No SOCKS connection')):
            result=module.profile('candidate-11318')
        self.assertEqual(result['url'],module.CANDIDATE_11318_URL)
        self.assertEqual(result['config_snapshot_sha256'],module.CANDIDATE_11318_CONFIG)
        self.assertFalse(result['active_profile_verified'])

    def value(self,**changes):
        values=dict(source_exe_sha256=module.CANDIDATE_11318_SOURCE,
            source_snapshot_sha256=module.CANDIDATE_11318_CONFIG,
            active_game_cache_verified=False,live_probe_only=True,bounded_world_probe=True,
            cdn_url=module.CANDIDATE_11318_URL)
        values.update(changes);return SimpleNamespace(**values)

    def profiled(self,value):
        # Isolate the source-loader boundary here; the real loader has its own
        # native-proof checks. The pinned real config manifest still supplies rows.
        source=SimpleNamespace(load_profile=Mock(return_value=value))
        selected=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda target:None))
        with patch.object(module.importlib.util,'spec_from_file_location',return_value=selected), \
                patch.object(module.importlib.util,'module_from_spec',return_value=source):
            result=module.profile('candidate-11318')
        source.load_profile.assert_called_once_with(selected_profile='candidate-11318',root=module.ROOT)
        return result

    def test_explicit_profile_uses_current_source_and_pinned_real_manifest(self):
        result=self.profiled(self.value())
        self.assertEqual(result['url'],module.CANDIDATE_11318_URL)
        self.assertEqual(result['config_snapshot_sha256'],module.CANDIDATE_11318_CONFIG)
        self.assertFalse(result['active_profile_verified'])
        self.assertTrue(result['https_added_by_local_policy'])

    def test_old_source_snapshot_or_expanded_scope_refused(self):
        for changes in (dict(source_exe_sha256='0'*64),dict(source_snapshot_sha256='0'*64),
                        dict(active_game_cache_verified=True),dict(live_probe_only=False),
                        dict(bounded_world_probe=False)):
            with self.subTest(changes=changes),self.assertRaisesRegex(ValueError,'candidate source or scope'):
                self.profiled(self.value(**changes))
        with self.assertRaisesRegex(ValueError,'verified release CDN URL'):
            self.profiled(self.value(cdn_url=module.CANDIDATE_URL))

    def test_manifest_changed_after_loader_is_refused(self):
        original=Path.read_bytes
        def changed(path):
            value=original(path)
            return value+b' ' if path.name=='manifest.json' else value
        with patch.object(Path,'read_bytes',changed),self.assertRaisesRegex(ValueError,'manifest changed'):
            self.profiled(self.value())

    def test_current_url_keeps_explicit_socks_route_without_direct_fallback(self):
        route=module.SocksRoute(17948);opener=Mock()
        opener.open.return_value=Response(url=module.CANDIDATE_11318_URL,headers=[('Content-Length','3')])
        with patch.object(module.SocksRoute,'opener',return_value=opener) as selected, \
                patch.object(module.urllib.request,'build_opener',side_effect=AssertionError('Direct fallback')):
            body,transport=module.fetch(module.CANDIDATE_11318_URL,route=route)
        self.assertEqual(body,b'abc')
        self.assertEqual(transport['socks5_loopback_port'],17948)
        self.assertTrue(transport['tls_certificate_verification'])
        self.assertFalse(transport['redirects_followed'] or transport['proxy_environment_used'])
        self.assertIsInstance(selected.call_args.args[0],module.NoRedirect)
        request=opener.open.call_args.args[0]
        self.assertEqual(request.full_url,module.CANDIDATE_11318_URL)
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header('Accept-encoding'),'identity')

    def test_current_response_status_url_encoding_and_redirects_stay_strict(self):
        for response in (Response(url=module.CANDIDATE_11318_URL,status=302),
                         Response(url=module.CANDIDATE_URL),
                         Response(url=module.CANDIDATE_11318_URL,headers=[('Content-Encoding','gzip')])):
            opener=Mock();opener.open.return_value=response
            with patch.object(module.SocksRoute,'opener',return_value=opener),self.assertRaises(ValueError):
                module.fetch(module.CANDIDATE_11318_URL,route=module.SocksRoute(17948))
        for url in (module.CANDIDATE_11318_URL.replace('https:','http:'),
                    module.CANDIDATE_11318_URL+'?redirect=1',
                    module.CANDIDATE_11318_URL.replace('red.gcdn.netmarble.com','example.invalid')):
            with patch.object(module.urllib.request,'build_opener') as direct,self.assertRaises(ValueError):
                module.fetch(url)
            direct.assert_not_called()

    def test_previous_candidate_url_remains_supported(self):
        opener=Mock();opener.open.return_value=Response(url=module.CANDIDATE_URL)
        with patch.object(module.SocksRoute,'opener',return_value=opener):
            body,_=module.fetch(module.CANDIDATE_URL,route=module.SocksRoute(17948))
        self.assertEqual(body,b'abc')


if __name__=='__main__':unittest.main()
