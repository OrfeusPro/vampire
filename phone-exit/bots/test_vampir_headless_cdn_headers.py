"""Native full header blocks and narrow portable empty-body GET serializer."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_request import draft_cdn_config_request, encode_cdn_get_headers


class CdnHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-headers.py'
        spec = importlib.util.spec_from_file_location('cdn_headers_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-headers.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.uri.http.preparation.url.settings.config.native.Image(cls.raw)

    def test_source_native_header_and_crt_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        self.assertEqual(hashlib.sha256(Path(self.report['system_crt']['path']).read_bytes()).hexdigest(),
                         self.report['system_crt']['sha256'])
        self.assertEqual(self.report['format_import']['name'], '__stdio_common_vsprintf')
        leaf = self.report['format_options_leaf']
        self.assertEqual(self.raw[leaf['file_offset']:leaf['file_offset'] + 8], bytes.fromhex(leaf['bytes']))
        for fragment in self.report['fragments']:
            for row in fragment['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['network_ready'])

    def test_all_native_header_replays_and_default_portable_matches(self):
        self.assertEqual(len(self.report['cases']), 11)
        matched = 0
        for case in self.report['cases']:
            emulator = self.module.HeaderEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.header(case['url_fixture'], case['keep_alive_fixture'],
                                             case['user_agent_fixture'], case['referer_fixture']), case)
            if not case['keep_alive_fixture'] and case['user_agent_fixture'] is None and case['referer_fixture'] is None:
                self.assertEqual(encode_cdn_get_headers(case['url_fixture']), case['header'].encode('ascii'))
                matched += 1
            self.assertTrue(case['header'].endswith('\r\n\r\n'))
            self.assertTrue(case['body_empty'])
            self.assertFalse(case['network_used'])
        self.assertEqual(matched, 7)

    def test_override_observations_not_assumed_as_default(self):
        cases = self.report['cases']
        normal = cases[0]['header']
        self.assertNotIn('Connection:', normal)
        self.assertNotIn('Content-Type:', normal)
        self.assertNotIn('Content-Length:', normal)
        keep = next(c for c in cases if c['keep_alive_fixture'])
        self.assertIn('Connection: Keep-Alive\r\n', keep['header'])
        empty = next(c for c in cases if c['user_agent_fixture'] == '')
        self.assertNotIn('User-Agent:', empty['header'])
        custom = next(c for c in cases if c['user_agent_fixture'] == 'TestAgent/2.0')
        self.assertIn('User-Agent: TestAgent/2.0\r\n', custom['header'])
        referer = next(c for c in cases if c['referer_fixture'])
        self.assertIn('Referer: https://ref.invalid/\r\n', referer['header'])

    def test_offline_settings_to_full_default_header(self):
        draft = draft_cdn_config_request(normal='https://cdn.invalid/', qa='https://qa.invalid/',
                    prefix='real', app_version='1.2.3', platform_code=2)
        self.assertEqual(draft.header_bytes, self.report['cases'][0]['header'].encode('ascii'))
        self.assertTrue(draft.header_bytes.startswith(draft.request_line))
        self.assertIn(b'Host: cdn.invalid:443\r\n', draft.header_bytes)
        self.assertEqual(draft.header_bytes.split(b'\r\n\r\n')[1], b'')
        self.assertNotIn('cdn.invalid', repr(draft))

    def test_no_header_injection_or_implicit_extra_fields(self):
        for value in ['https://cdn.invalid/a\r\nX: y', 'https://cdn.invalid/a\n',
                      'https://u:p@cdn.invalid/a', 'https://cdn.invalid/a?x=1',
                      'HTTPS://cdn.invalid/a', 'https://cdn.invalid:0/a']:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                encode_cdn_get_headers(value)
        value = 'https://cdn.invalid/' + 'a' * (4096 - len('https://cdn.invalid/'))
        self.assertLessEqual(len(encode_cdn_get_headers(value)), 8192)


if __name__ == '__main__':
    unittest.main()
