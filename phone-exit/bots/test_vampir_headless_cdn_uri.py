"""Native parser/request-line pipeline and strict portable URI subset."""
from dataclasses import asdict, FrozenInstanceError
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_uri import parse_cdn_uri_ascii
from vampir_core.cdn_request import CdnConfigRequestDraft, draft_cdn_config_request


class CdnUriTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-uri.py'
        spec = importlib.util.spec_from_file_location('cdn_uri_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-uri.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.http.preparation.url.settings.config.native.Image(cls.raw)

    def test_source_and_crt_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        self.assertEqual(hashlib.sha256(Path(self.report['system_crt']['path']).read_bytes()).hexdigest(),
                         self.report['system_crt']['sha256'])
        self.assertEqual(self.report['atoi_import']['name'], 'atoi')
        rows = {i['address']: i for f in self.report['fragments'] for i in f['instructions']}
        for row in rows.values():
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertEqual(rows[0x1445e2dfd]['direct_target'], self.module.PARSE)
        self.assertEqual(rows[0x1445e6ba1]['operands'], 'word ptr [rsi + 0x48], ax')
        self.assertFalse(self.report['network_ready'])

    def test_native_parser_through_actual_get_line_and_portable_subset(self):
        self.assertEqual(len(self.report['cases']), 22)
        matched, rejected = 0, 0
        for case in self.report['cases']:
            emulator = self.module.UriEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.parse(case['url_fixture']), case)
            try:
                parsed = parse_cdn_uri_ascii(case['url_fixture'])
            except ValueError:
                rejected += 1
                continue
            matched += 1
            self.assertEqual(asdict(parsed), case['fields'])
            line = 'GET ' + parsed.request_target + ' HTTP/1.0\r\n'
            self.assertEqual(line, case['request_line'])
        self.assertEqual((matched, rejected), (16, 6))

    def test_native_quirks_are_not_validated_server_addresses(self):
        cases = {case['url_fixture']: case for case in self.report['cases']}
        self.assertEqual(cases['HTTPS://cdn.invalid/a']['fields']['port'], 0)
        self.assertEqual(cases['https://cdn.invalid/a#frag']['fields']['path'], 'a#frag')
        self.assertEqual(cases['https://cdn.invalid/a?x=1']['fields']['path'], 'a?x=1')
        for value in ['https://cdn.invalid:65536/a', 'https://cdn.invalid:abc/a', 'https://cdn.invalid:0/a']:
            self.assertEqual(cases[value]['fields']['port'], 0)
            with self.assertRaises(ValueError):
                parse_cdn_uri_ascii(value)

    def test_supported_subset_bounds_host_case_and_escape_preservation(self):
        parsed = parse_cdn_uri_ascii('https://CDN.INVALID:00443//a%2Fb/../c')
        self.assertEqual((parsed.host, parsed.port, parsed.path), ('CDN.INVALID', 443, '/a%2Fb/../c'))
        self.assertEqual(parsed.request_target, '//a%2Fb/../c')
        self.assertNotIn('CDN.INVALID', repr(parsed))
        with self.assertRaises(FrozenInstanceError):
            parsed.port = 80
        for value in [None, b'https://host/', 'HTTPS://host/', 'ftp://host/a', 'https://',
                      'https://user:pw@host/a', 'https://[::1]/a', 'https://host:/a',
                      'https://host:000443/a', 'https://host/a?', 'https://host/a#',
                      'https://host/a\\b', 'https://host/a b', 'https://host/é', 'https://host/\0',
                      'https://host/' + 'a' * 4096]:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                parse_cdn_uri_ascii(value)

    def test_draft_integrates_native_uri_and_request_line(self):
        draft = draft_cdn_config_request(normal='https://cdn.invalid/', qa='https://qa.invalid/',
                                        prefix='real', app_version='1.2.3', platform_code=2)
        native = next(c for c in self.report['cases'] if c['url_fixture'] == draft.url)
        self.assertEqual(asdict(draft.uri), native['fields'])
        self.assertEqual(draft.request_line, native['request_line'].encode('ascii'))
        self.assertFalse(draft.request_line.endswith(b'\r\n\r\n'))  # Only first line, no claimed complete request.
        self.assertNotIn('cdn.invalid', repr(draft))
        for value in ['HTTPS://cdn.invalid/a', 'http://cdn.invalid/a', 'https://cdn.invalid/a?x']:
            with self.assertRaises(ValueError):
                CdnConfigRequestDraft(value)


if __name__ == '__main__':
    unittest.main()
