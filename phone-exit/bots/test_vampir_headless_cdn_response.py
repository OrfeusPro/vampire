"""Native response head observations and strict portable boundary policy."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_response import MAX_HEAD_BYTES, probe_cdn_response_head


class CdnResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-response-head.py'
        spec = importlib.util.spec_from_file_location('cdn_response_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-response-head.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.headers.uri.http.preparation.url.settings.config.native.Image(cls.raw)

    def test_source_and_native_scan_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        crt = self.report['system_crt']
        self.assertEqual(hashlib.sha256(Path(crt['path']).read_bytes()).hexdigest(), crt['sha256'])
        self.assertEqual(self.report['scan_import']['name'], '__stdio_common_vsscanf')
        for row in self.report['anchors'] + [i for f in self.report['fragments'] for i in f['instructions']]:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['network_ready'])

    def test_native_replays_and_independent_boundary_counts(self):
        self.assertEqual(len(self.report['cases']), 52)
        for case in self.report['cases']:
            payload = bytes.fromhex(case['payload_hex'])
            emulator = self.module.ResponseHeadEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.probe(payload), case)
            # Native strstr sees only the prefix before NUL, not a binary search.
            offset = payload.split(b'\0', 1)[0].find(b'\r\n\r\n')
            expected = offset + 4 if offset >= 0 else 0
            self.assertEqual(case['header_bytes'], expected)
            self.assertEqual(case['available_body_bytes'], len(payload) - expected if expected else 0)

    def test_all_accumulated_prefixes_and_native_status_quirks(self):
        cases = self.report['cases']
        for case in cases[:41]:
            head = probe_cdn_response_head(bytes.fromhex(case['payload_hex']))
            if case['header_bytes']:
                self.assertEqual((head.status, head.header_bytes), (case['status'], case['header_bytes']))
                self.assertEqual(head.get_all('CONTENT-LENGTH'), ('2',))
            else:
                self.assertIsNone(head)
        for case in cases[41:]:
            payload = bytes.fromhex(case['payload_hex'])
            if payload.startswith((b'HTTP/2', b'anything', b'HTTP/1.1 nope', b'HTTP/1.1 -1')) or b'OK\0\r' in payload:
                with self.assertRaises(ValueError):
                    probe_cdn_response_head(payload)
            elif case['header_bytes']:
                head = probe_cdn_response_head(payload)
                self.assertEqual((head.status, head.header_bytes), (case['status'], case['header_bytes']))
        negative = next(c for c in cases if b' -1 ' in bytes.fromhex(c['payload_hex']))
        self.assertEqual(negative['status'], 0xffffffff)

    def test_duplicate_fields_body_separation_and_no_completion_claim(self):
        header = b'HTTP/1.1 200 OK\r\nX-Test: a\r\nx-test:\tb \t\r\nContent-Length: 999\r\n\r\n'
        head = probe_cdn_response_head(header + b'\0{}\xff')
        self.assertEqual(head.header_bytes, len(header))
        self.assertEqual(head.get_all('X-TEST'), ('a', 'b'))
        self.assertEqual(head.get_all('missing'), ())
        self.assertEqual(head, probe_cdn_response_head(header))
        self.assertNotIn('999', repr(head))
        with self.assertRaises(ValueError):
            head.get_all('x\r\n')

    def test_local_limits_and_malformed_header_rejection(self):
        exact = b'HTTP/1.0 200\r\nX: ' + b'a' * (MAX_HEAD_BYTES - 21) + b'\r\n\r\n'
        self.assertEqual(len(exact), MAX_HEAD_BYTES)
        self.assertEqual(probe_cdn_response_head(exact + b'z' * 100000).header_bytes, MAX_HEAD_BYTES)
        self.assertIsNone(probe_cdn_response_head(exact[:-1]))
        invalid = [exact[:-1] + b'x', exact[:-4] + b'x\r\n\r\n', b'a' * MAX_HEAD_BYTES,
                   b'HTTP/1.1 200\r\n folded\r\n\r\n', b'HTTP/1.1 200\r\nBad Name: x\r\n\r\n',
                   b'HTTP/1.1 200\r\nX: a\nb\r\n\r\n', b'HTTP/1.1 200\r\nX: \x00\r\n\r\n',
                   b'HTTP/1.1 200\r\nX: \xff\r\n\r\n', b'HTTP/1.1 600\r\n\r\n',
                   b'HTTP/1.1 200\r\n' + b'X: a\r\n' * 65 + b'\r\n', bytearray(b'x')]
        for data in invalid:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                probe_cdn_response_head(data)


if __name__ == '__main__':
    unittest.main()
