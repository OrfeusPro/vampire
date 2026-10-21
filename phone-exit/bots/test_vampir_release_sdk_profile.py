"""Current SDK profile selection, changed-source rejection and snapshot isolation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseSdkProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = load('release_sdk_source_test', HERE / 'vampir-headless/sdk-source-profile.py')
        cls.runner = load('release_nid_runner_test', HERE / 'vampir-headless/run-nid-sdk-sign-in.py')
        cls.fetch = load('release_gmc_fetch_test', HERE / 'resource-tools/vampir/fetch-public-gmc2-config.py')

    def test_current_installed_profile_has_replayed_request_and_nid_values(self):
        public = self.loader.load_release_profile('public_gmc2')
        nid = self.loader.load_release_profile('nid')
        self.assertEqual(public['profile_sha256'], nid['profile_sha256'])
        self.assertEqual(public['source_sha256'], nid['source_sha256'])
        self.assertEqual(public['profile']['sdk_version'], '5.2.11')
        self.assertEqual((nid['profile']['game_code'], nid['profile']['os_type'], nid['profile']['build_code']), ('thered', 'PC', 0))
        self.assertEqual(dict(public['request']['headers'])['nmDeviceKey'], '')
        self.assertNotIn('accessToken', dict(public['request']['headers']))
        self.assertEqual(self.fetch.profile('recovered-release'), public)
        self.assertFalse(nid['active_runtime_settings_verified'])

    def test_tampered_manifest_and_changed_installed_exe_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'client.exe'
            source.write_bytes(b'current-source-fixture')
            source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            report = dict(name='recovered-release', source=str(source), source_sha256=source_sha,
                          nid=dict(profile={}), public_gmc2=dict(profile={}, request={}))
            payload = json.dumps(report).encode()
            manifest_sha = hashlib.sha256(payload).hexdigest()
            folder = root / 'sdk-source-profiles' / manifest_sha
            folder.mkdir(parents=True)
            manifest = folder / 'manifest.json'
            manifest.write_bytes(payload)
            with patch.object(self.loader, 'RELEASE_PROFILE_SHA', manifest_sha), patch.object(self.loader, 'RELEASE_SOURCE_SHA', source_sha):
                self.loader.load_release_profile('nid', root=root)
                source.write_bytes(b'updated-source-fixture')
                with self.assertRaisesRegex(ValueError, 'Installed SDK source changed'):
                    self.loader.load_release_profile('nid', root=root)
                manifest.write_bytes(payload + b' ')
                with self.assertRaisesRegex(ValueError, 'source profile changed'):
                    self.loader.load_release_profile('nid', root=root)

    def test_missing_release_and_unknown_selection_do_not_fall_back(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileNotFoundError):
                self.loader.load_release_profile('nid', root=temp)
        with self.assertRaises(ValueError):
            self.loader.load_release_profile('unknown')
        with self.assertRaises(ValueError):
            self.fetch.profile('automatic')
        with self.assertRaises(ValueError):
            self.runner.load_inputs('fixture@example.invalid', selected_profile='automatic')

    def test_release_fetches_fresh_configuration_without_reading_old_snapshot(self):
        binding = SimpleNamespace(kind='real', identity_recorded=True, nid_identity_recorded=True, confirmation='unknown',
                                  device_key='sdk-fixture', nid_device_key='nid-fixture', nm_device_key='nm-fixture')
        identity = SimpleNamespace(device_key=binding.device_key, nid_device_key=binding.nid_device_key, nm_device_key=binding.nm_device_key)
        # Keep the real pinned profile and installed-source check; replace only the public response pointer.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'code-clues').mkdir()
            folder = root / 'sdk-source-profiles' / self.loader.RELEASE_PROFILE_SHA
            folder.mkdir(parents=True)
            original = self.loader.ROOT / 'sdk-source-profiles' / self.loader.RELEASE_PROFILE_SHA / 'manifest.json'
            (folder / 'manifest.json').write_bytes(original.read_bytes())
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(dict(profile_sha256='old-profile', selected_profile='recovered-base')), encoding='utf-8')
            (root / 'code-clues/public-gmc2-recovery.json').write_text(json.dumps(
                dict(manifest=str(manifest), sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())), encoding='utf-8')
            with patch.object(self.runner, 'ROOT', root), patch.object(self.runner, 'DeviceRegistry') as registry, \
                    patch.object(self.runner, 'observe_windows_device_identity', return_value=identity), \
                    patch.object(self.runner, 'decode_gmc2_configuration', side_effect=AssertionError('must reject before decode')), \
                    patch.object(self.runner, 'fetch_gmc2', side_effect=ValueError('fresh-fetch-fixture')) as fetch:
                registry.return_value.get.return_value = binding
                with self.assertRaisesRegex(ValueError, 'fresh-fetch-fixture'):
                    self.runner.load_inputs('fixture@example.invalid', selected_profile='recovered-release')
                fetch.assert_called_once()

    def test_run_passes_selected_profile_before_browser_is_started(self):
        with patch.object(self.runner, 'load_inputs', side_effect=ValueError('preflight-fixture')) as inputs:
            with self.assertRaisesRegex(ValueError, 'preflight-fixture'):
                self.runner.run('fixture@example.invalid', selected_profile='recovered-release', socks_port=17948,
                                _capture=lambda *a, **k: self.fail('browser must not start'))
        inputs.assert_called_once_with('fixture@example.invalid', route=self.runner.SocksRoute(17948), selected_profile='recovered-release')


if __name__ == '__main__':
    unittest.main()
