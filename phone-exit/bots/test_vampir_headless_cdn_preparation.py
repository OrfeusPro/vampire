"""Native AppVersion preprocessing/platform chain and composed offline URL."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.sdk_config import prepare_cdn_version_ascii, select_cdn_platform_label, prepare_cdn_config_url_ascii


class CdnPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-preparation.py'
        spec = importlib.util.spec_from_file_location('cdn_preparation_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-preparation.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.url.settings.config.native.Image(cls.raw)

    def test_provenance_calls_and_platform_object(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for row in self.report['anchors']:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        rows = {i['address']: i for f in self.report['fragments'] for i in f['instructions']}
        for row in rows.values():
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertEqual(rows[0x14563f287]['direct_target'], self.module.REPLACE)
        self.assertEqual(rows[0x14563f17e]['operands'], 'word ptr [rsp + 0x58], 0x5f')
        self.assertEqual(rows[0x14563f195]['operands'], 'word ptr [rsp + 0x78], 0x2e')
        self.assertEqual(rows[0x14563f275]['operands'], 'r9, [rsp + 0x58]')
        self.assertEqual(rows[0x14563f27a]['operands'], 'r8, [rsp + 0x78]')
        self.assertEqual(rows[0x1445eae31]['rip_references'], [0x1495045d0])
        self.assertEqual(rows[0x1445eae38]['rip_references'], [0x14b4f39c8])
        self.assertEqual({row['name'] for row in self.report['imports']}, {'memchr', 'memcmp'})
        self.assertFalse(self.report['network_ready'])

    def test_native_version_replacement_and_portable_code(self):
        self.assertEqual(len(self.report['version_cases']), 15)
        for case in self.report['version_cases']:
            emulator = self.module.PreparationEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.version(case['app_version']), case)
            self.assertEqual(prepare_cdn_version_ascii(case['app_version']), case['result'])
            self.assertEqual(case['input_after'], case['app_version'])

    def test_platform_initialization_and_branch_return_fixtures(self):
        emulator = self.module.PreparationEmulator(self.raw, self.image, self.report['fragments'])
        self.assertEqual(emulator.platform(), self.report['platform'])
        self.assertEqual(self.report['platform']['code'], 2)
        self.assertEqual(self.report['platform']['label'], 'window')
        self.assertIsNone(self.report['platform']['return_code_fixture'])
        self.assertEqual(len(self.report['platform_cases']), 7)
        for case in self.report['platform_cases']:
            emulator = self.module.PreparationEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.platform(case['return_code_fixture']), case)
            code = case['code'] if case['code'] < 0x80000000 else case['code'] - 0x100000000
            self.assertEqual(select_cdn_platform_label(code), case['label'])

    def test_explicit_settings_to_native_url_tail(self):
        app_version = '1.2.3'
        emulator = self.module.PreparationEmulator(self.raw, self.image, self.report['fragments'])
        version = emulator.version(app_version)['result']
        emulator = self.module.PreparationEmulator(self.raw, self.image, self.report['fragments'])
        platform = emulator.platform()
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        tail = json.loads((root / 'code-clues/headless-cdn-url.json').read_text('utf-8'))
        native = self.module.url.replay(self.raw, self.image, tail['fragments'],
                    'https://cdn.invalid/', platform['label'], 'real', version)
        result = prepare_cdn_config_url_ascii(normal='https://cdn.invalid/', qa='https://qa.invalid/',
                    prefix='real', app_version=app_version, platform_code=platform['code'])
        self.assertEqual(result, native['result'])
        self.assertEqual(result, 'https://cdn.invalid/window/real/1_2_3/config.json')
        self.assertEqual(prepare_cdn_config_url_ascii(normal='normal/', qa='qa/', prefix='dev',
                    app_version='2..1', platform_code=0), 'qa/android/dev/2__1/config.json')

    def test_local_validation_no_guessed_settings(self):
        for value in [None, b'1.2', '\0', '\n', 'версия', 'x' * 4097]:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                prepare_cdn_version_ascii(value)
        self.assertEqual(prepare_cdn_version_ascii('.' * 4096), '_' * 4096)
        for value in [None, True, 2.0, '2', -(1 << 31) - 1, 1 << 31]:
            with self.subTest(code=type(value).__name__), self.assertRaises(ValueError):
                select_cdn_platform_label(value)
        with self.assertRaises(TypeError):
            prepare_cdn_config_url_ascii(normal='normal/')


if __name__ == '__main__':
    unittest.main()
