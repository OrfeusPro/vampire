"""SDK class defaults versus game overrides; active values remain unknown."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.sdk_config import select_game_sdk_zone


class SDKSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-sdk-settings.py'
        spec = importlib.util.spec_from_file_location('sdk_settings_test_tool', cls.tool)
        cls.study = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.study)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report_path = root / 'code-clues/headless-sdk-settings.json'
        cls.report = json.loads(cls.report_path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.study.config.native.Image(cls.raw)

    def test_provenance_and_code_bytes(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for row in self.report['anchors'] + self.report['descriptors']:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        for fragment in self.report['fragments']:
            for row in fragment['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['active_settings_proven'])
        self.assertFalse(self.report['network_ready'])

    def test_reflected_offsets_and_constructor_native_replay(self):
        self.assertEqual(len(self.report['descriptors']), 9)
        for descriptor in self.report['descriptors']:
            data = bytes.fromhex(descriptor['bytes'])
            self.assertEqual(struct.unpack_from('<I', data, 0x30)[0], descriptor['offset'] << 16 | 1)
        for case in self.report['cases']:
            self.assertEqual(self.study.replay(self.raw, self.image, case['poison']), case)
            self.assertEqual(case['values']['GameCode'], 'thered')
            self.assertEqual(case['values']['Market'], '')
            self.assertEqual(case['values']['BuildCode'], 0)
            self.assertEqual(case['values']['SDKZone'], 1)
            self.assertEqual(case['string_calls'], 7)

    def test_native_game_override_and_portable_selection(self):
        globals_text = {int(k): v for k, v in self.report['game_globals'].items()}
        self.assertEqual(len(self.report['game_cases']), 13)
        for case in self.report['game_cases']:
            env = case['environment_fixture']
            actual = self.study.replay_game_override(self.raw, self.image, env, globals_text)
            self.assertEqual(actual, case)
            self.assertEqual(select_game_sdk_zone(env), actual['values']['SDKZone'])
            self.assertEqual(actual['values']['Market'], 'nmp')
            self.assertEqual(actual['values']['GameCode'], 'thered')
            self.assertEqual(actual['values']['NetmarbleClientId'], globals_text[0x14b574090])

    def test_environment_input_is_explicit_and_bounded(self):
        for value in [None, b'real', 1, 'real\0dev', 'x' * 129, '😀' * 65]:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                select_game_sdk_zone(value)
        self.assertEqual(select_game_sdk_zone('x' * 128), 1)
        self.assertEqual(select_game_sdk_zone('😀' * 64), 1)
        self.assertEqual(select_game_sdk_zone(' real'), 1)


if __name__ == '__main__':
    unittest.main()
