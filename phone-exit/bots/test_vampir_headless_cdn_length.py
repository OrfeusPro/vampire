"""Native length observations, receive comparison and bounded body extraction."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_response import MAX_BODY_BYTES, take_cdn_length_response


class CdnLengthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-response-length.py'
        spec = importlib.util.spec_from_file_location('cdn_length_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-response-length.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.head.headers.uri.http.preparation.url.settings.config.native.Image(cls.raw)

    def test_native_sources_crt_and_instruction_bytes(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        crt = self.report['system_crt']
        self.assertEqual(hashlib.sha256(Path(crt['path']).read_bytes()).hexdigest(), crt['sha256'])
        self.assertEqual([i['name'] for i in self.report['imports']], ['strncpy', '_strnicmp', 'atoi'])
        for fragment in self.report['fragments']:
            for row in fragment['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['network_ready'])

    def test_all_native_replays_and_independent_unsigned_comparison(self):
        self.assertEqual(len(self.report['cases']), 30)
        for case in self.report['cases']:
            payload = bytes.fromhex(case['payload_hex'])
            emulator = self.module.LengthEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.probe(payload, case['initial_length_fixture']), case)
            available = len(payload) - payload.index(b'\r\n\r\n') - 4
            self.assertEqual(case['receive_ready'], available >= (case['declared_length'] & 0xffffffff))
        for case in self.report['bounded_abort_cases']:
            emulator = self.module.LengthEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.probe(bytes.fromhex(case['payload_hex']), expect_lookup_budget=True), case)
            self.assertEqual(case['instruction_budget'], 32768)

    def test_native_quirks_are_observations_not_portable_policy(self):
        cases = self.report['cases']
        def native(fragment):
            return next(c for c in cases if fragment in bytes.fromhex(c['payload_hex']))
        self.assertEqual(native(b'Content-Length: 2junk')['declared_length'], 2)
        self.assertEqual(native(b'Content-Length: nope')['declared_length'], 0)
        self.assertEqual(native(b'Content-Length: 2147483648')['declared_length'], 2147483647)
        self.assertEqual(native(b'CONTENT-LENGTH=2')['declared_length'], 2)
        self.assertEqual(native(b'Content-Length: 2\r\nContent-Length: 9')['declared_length'], 2)
        self.assertEqual(native(b'Content-Length: 9\r\nContent-Length: 2')['declared_length'], 9)
        self.assertEqual(native(b'Content-Range:')['range_text'], 'bytes 0-1/2')
        missing = [c for c in cases if c['initial_length_fixture'] == 7]
        self.assertTrue(all(c['declared_length'] == 7 and not c['receive_ready'] for c in missing))

    def test_valid_native_subset_and_every_split_before_completion(self):
        selected = [self.report['cases'][i] for i in [2, 4, 5, 6, 15, 16, 17, 18, 19]]
        for case in selected:
            payload = bytes.fromhex(case['payload_hex'])
            result = take_cdn_length_response(payload)
            self.assertEqual(result is not None, case['receive_ready'])
            if result:
                self.assertEqual(result.body, b'{}')
                self.assertEqual(payload[result.consumed:], b'x' if payload.endswith(b'{}x') else b'')
        full = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\0\xff{}'
        for split in range(len(full)):
            self.assertIsNone(take_cdn_length_response(full[:split]))
        response = take_cdn_length_response(full + b'next')
        self.assertEqual(response.body, b'\0\xff{}')
        self.assertEqual(response.consumed, len(full))
        self.assertNotIn('body=', repr(response))

    def test_reject_unsupported_and_ambiguous_framing(self):
        fields = [b'', b'Content-Length: +2', b'Content-Length: -1', b'Content-Length: 2junk',
                  b'Content-Length: nope', b'Content-Length: ', b'CONTENT-LENGTH=2',
                  b'Content-Length: 2, 2', b'Content-Length: 2\r\nContent-Length: 2',
                  b'Content-Length: 2\r\nContent-Length: 9',
                  b'Content-Length: 2\r\nTransfer-Encoding: chunked',
                  b'Content-Length: 2\r\nTransfer-Encoding: ',
                  b'Content-Length: 2\r\nContent-Range: bytes 0-1/2',
                  b'Content-Length: 2\r\nContent-Encoding: gzip',
                  b'Content-Length: 2\r\nContent-Encoding: identity\r\nContent-Encoding: identity',
                  b'Content-Length: 2\r\n 3']
        for field in fields:
            with self.subTest(field=field), self.assertRaises(ValueError):
                take_cdn_length_response(b'HTTP/1.1 200 OK\r\n' + field + b'\r\n\r\n{}')
        for status in [100, 204, 206, 301, 404, 500]:
            with self.assertRaises(ValueError):
                take_cdn_length_response(f'HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n'.encode())

    def test_body_budget_zero_and_identity(self):
        def header(length):
            return f'HTTP/1.0 200\r\nContent-Length: {length}\r\nContent-Encoding: IDENTITY\r\n\r\n'.encode()
        self.assertEqual(take_cdn_length_response(header(0)).body, b'')
        self.assertIsNone(take_cdn_length_response(header(MAX_BODY_BYTES)))
        result = take_cdn_length_response(header(MAX_BODY_BYTES) + b'x' * MAX_BODY_BYTES)
        self.assertEqual(len(result.body), MAX_BODY_BYTES)
        for length in [MAX_BODY_BYTES + 1, 2147483648, '0' * 11]:
            with self.assertRaises(ValueError):
                take_cdn_length_response(header(length))


if __name__ == '__main__':
    unittest.main()
