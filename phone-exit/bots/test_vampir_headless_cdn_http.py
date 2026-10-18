"""Native HTTP default/request-line evidence and offline-only draft binding."""
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_request import draft_cdn_config_request


class CdnHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-http.py'
        spec = importlib.util.spec_from_file_location('cdn_http_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-http.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.preparation.url.settings.config.native.Image(cls.raw)

    def test_source_bytes_and_static_cdn_handoff(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        rows = {i['address']: i for f in self.report['fragments'] for i in f['instructions']}
        for row in rows.values():
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        for address, target in [(0x14563fd0d, 0x1445ea140), (0x1445e234b, self.module.CTOR_START),
                                (0x1445e4b67, self.module.REQUEST_LINE)]:
            self.assertEqual(rows[address]['direct_target'], target)
        self.assertEqual(rows[0x1445e25f3]['operands'], 'dword ptr [rcx + 8], 1')
        self.assertEqual(rows[0x14563fd00]['operands'], 'r9d, r9d')
        self.assertEqual(rows[0x14563fd07]['operands'], 'r8d, r8d')
        self.assertFalse(self.report['network_ready'])

    def test_native_constructor_to_get_http10_lines(self):
        self.assertEqual(len(self.report['cases']), 16)
        for case in self.report['cases']:
            emulator = self.module.HttpLineEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.request_line(case['path_fixture'], case['poison']), case)
            self.assertEqual(case['method_code'], 1)
            self.assertEqual(case['default_user_agent_field'], 'Aqua/1.0')
            self.assertEqual(case['request_line'], 'GET /' + case['path_fixture'] + ' HTTP/1.0\r\n')
            self.assertTrue(case['query_collection_empty'])
            self.assertFalse(case['network_used'])

    def test_explicit_settings_bind_draft_defaults_and_redacted_repr(self):
        draft = draft_cdn_config_request(normal='https://cdn.invalid/', qa='https://qa.invalid/',
                    prefix='real', app_version='1.2.3', platform_code=2)
        self.assertEqual(draft.url, 'https://cdn.invalid/window/real/1_2_3/config.json')
        self.assertEqual((draft.method, draft.http_version), ('GET', '1.0'))
        self.assertNotIn('cdn.invalid', repr(draft))
        with self.assertRaises(FrozenInstanceError):
            draft.url = 'https://changed.invalid/'
        native = next(case for case in self.report['cases'] if case['path_fixture'] == 'window/real/1_2_3/config.json')
        self.assertTrue(native['request_line'].startswith(draft.method + ' /'))
        self.assertIn('HTTP/' + draft.http_version, native['request_line'])

    def test_local_url_policy_before_any_request(self):
        args = dict(normal='https://cdn.invalid/', qa='https://qa.invalid/', prefix='real', app_version='1.2', platform_code=2)
        for base in ['http://cdn.invalid/', 'https://', 'https://cdn.invalid', 'https://u:p@cdn.invalid/',
                     'https://cdn.invalid:99999/', 'https://cdn.invalid/a?x=',
                     'https://cdn.invalid/#', 'https://cdn.invalid/ ', 'https://cdn.invalid/\\']:
            with self.subTest(base=base), self.assertRaises(ValueError):
                draft_cdn_config_request(**dict(args, normal=base))
        for prefix in ['real ', 'real?x', 'real#']:
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                draft_cdn_config_request(**dict(args, prefix=prefix))
        with self.assertRaises(TypeError):
            draft_cdn_config_request(normal='https://cdn.invalid/')


if __name__ == '__main__':
    unittest.main()
