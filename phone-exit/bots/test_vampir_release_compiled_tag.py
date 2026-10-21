"""Current source tag reaches both packets; mixed profiles and changed literals fail."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_vampir_initial_game_login as fixtures

HERE = Path(__file__).parent
TAG = '32283C4C6485307BCF524765A84409C3'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / 'vampir-headless' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseCompiledTagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load('release_tag_profile_test', 'game-source-profile.py')
        cls.version = load('release_tag_version_test', 'probe-game-version.py')

    def test_pinned_installed_source_selects_current_tag(self):
        profile = self.profile.load_profile(selected_profile='recovered-release')
        self.assertEqual(profile.compiled_tag, TAG)
        self.assertNotEqual(profile.compiled_tag, self.version.COMPILED_TAG)

    def test_current_tag_reaches_version_and_login_without_reusing_auth_data(self):
        from vampir_core.version_cpu import VersionCpuInput
        from vampir_core.login_context import prepare_initial_windows_game_login
        _, inputs = fixtures.InitialGameLoginTests().inputs()
        version = self.version.prepare_version(app_version='1.13.14', nm_device_key='nm-fixture', local_address=None,
            cpu=VersionCpuInput('GenuineIntel', 'brand-fixture'), windows_version=None, compiled_tag=TAG)
        login = prepare_initial_windows_game_login(version, **inputs, compiled_tag=TAG)
        self.assertEqual(version.strings[9], TAG)
        self.assertEqual(login.strings[14], TAG)
        self.assertEqual(login.strings[8], inputs['sdk_data'].access_token)
        with self.assertRaises(ValueError):
            prepare_initial_windows_game_login(version, **inputs)
        with self.assertRaises(ValueError):
            prepare_initial_windows_game_login(replace(version, strings=(*version.strings[:9], self.version.COMPILED_TAG)),
                                               **inputs, compiled_tag=TAG)

    def test_changed_source_pointer_or_literal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'source.exe'
            pointer = bytes.fromhex('0800000000000000')
            original = pointer + (TAG + '\0').encode()
            with patch.object(self.profile, 'WIRE_TAGS', {'fixture': (0, pointer.hex(), 8, TAG)}):
                path.write_bytes(original)
                self.assertEqual(self.profile.verify_compiled_tag(path, 'fixture'), TAG)
                for changed in (b'\xff' + original[1:], original[:-2] + b'F\0'):
                    path.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        self.profile.verify_compiled_tag(path, 'fixture')
                with self.assertRaises(ValueError):
                    self.profile.verify_compiled_tag(path, 'unknown-source')


if __name__ == '__main__':
    unittest.main()
