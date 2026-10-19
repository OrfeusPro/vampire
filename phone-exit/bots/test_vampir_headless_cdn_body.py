"""Native body/BOM evidence and bounded portable Unicode decoding policy."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_response import MAX_BODY_BYTES, decode_cdn_body_text, take_cdn_length_response


class CdnBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-body.py'
        spec = importlib.util.spec_from_file_location('cdn_body_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-body.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.head.headers.uri.http.preparation.url.settings.config.native.Image(cls.raw)

    def test_source_tool_and_instruction_provenance(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        for fragment in self.report['fragments']:
            for row in fragment['instructions']:
                data = bytes.fromhex(row['bytes'])
                self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertFalse(self.report['network_ready'])

    def test_native_replays_and_independent_byte_results(self):
        cases = self.report['cases'] + self.report['guard_cases']
        self.assertEqual(len(cases), 31)
        for case in cases:
            body, guard = bytes.fromhex(case['body_hex']), bytes.fromhex(case['guard_byte_hex'])
            emulator = self.module.BodyEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.probe(body, guard), case)
            expected = body
            if len(body) >= 3 and body.startswith(b'\xef\xbb\xbf'):
                expected = body[3:]
            elif len(body) >= 3 and body.startswith(b'\xff\xfe'):
                # Actual byte-count-as-unit-count read from explicitly owned guard.
                count = len(body) - 2
                source = (body[2:] + b'\0' + guard * 1024)[:2 * count]
                expected = b''.join(chr(int.from_bytes(source[i:i + 2], 'little')).encode('utf-8', 'surrogatepass')
                                    for i in range(0, len(source), 2))
                self.assertEqual(case['wide_requests'], [dict(units=count, bytes_requested=2 * count,
                                     source_bytes_remaining=count, beyond_body_bytes=count)])
            self.assertEqual(bytes.fromhex(case['output_hex']), expected)

    def test_status_gate_boundaries_without_claiming_full_callback(self):
        self.assertEqual(len(self.report['status_gate_cases']), 9)
        for case in self.report['status_gate_cases']:
            emulator = self.module.BodyEmulator(self.raw, self.image, self.report['fragments'])
            self.assertEqual(emulator.status_gate(case['status']), case)
            self.assertEqual(case['enters_body_branch'], 200 <= case['status'] <= 299)
            self.assertTrue(case['callback_prefix_only'])

    def test_native_wide_guard_dependency_and_individual_surrogate_units(self):
        normal = {c['body_hex']: c for c in self.report['cases']}
        for case in self.report['guard_cases']:
            original = normal[case['body_hex']]
            if case['wide_requests']:
                self.assertNotEqual(case['output_hex'], original['output_hex'])
                self.assertGreater(case['wide_requests'][0]['beyond_body_bytes'], 0)
            else:
                self.assertEqual(case['output_hex'], original['output_hex'])
        emoji = normal[(b'\xff\xfe' + '😀'.encode('utf-16le')).hex()]
        self.assertTrue(bytes.fromhex(emoji['output_hex']).startswith(b'\xed\xa0\xbd\xed\xb8\x80'))

    def test_portable_utf8_subset_and_native_permissiveness(self):
        matched = 0
        for case in self.report['cases']:
            if case['wide_requests'] or bytes.fromhex(case['body_hex']).startswith(b'\xff\xfe'):
                continue
            result = bytes.fromhex(case['output_hex'])
            try:
                expected = result.decode('utf-8', 'strict')
            except UnicodeDecodeError:
                with self.assertRaises(ValueError):
                    decode_cdn_body_text(bytes.fromhex(case['body_hex']))
                continue
            if '\0' in expected:
                with self.assertRaises(ValueError):
                    decode_cdn_body_text(bytes.fromhex(case['body_hex']))
                continue
            self.assertEqual(decode_cdn_body_text(bytes.fromhex(case['body_hex'])), expected)
            matched += 1
        self.assertGreaterEqual(matched, 10)
        self.assertEqual(decode_cdn_body_text(b'\xef\xbb\xbf\xef\xbb\xbf{}'), '\ufeff{}')

    def test_portable_wide_policy_corrects_bounds_and_validates_unicode(self):
        for text in ['', 'A', '{}', 'Привет', '\u07ff\u0800', '😀', 'x' * 180]:
            body = b'\xff\xfe' + text.encode('utf-16le')
            self.assertEqual(decode_cdn_body_text(body), text)
        for body in [b'\xff\xfeA', b'\xff\xfe\0\xd8', b'\xff\xfe\0\xdc',
                     b'\xfe\xff\0A', b'\xff\xfe\0\0', b'\xed\xa0\x80']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                decode_cdn_body_text(body)

    def test_fixed_length_to_text_integration_and_budget(self):
        text = '{"name":"Вампир 😀"}'
        for body in [text.encode(), b'\xef\xbb\xbf' + text.encode(), b'\xff\xfe' + text.encode('utf-16le')]:
            header = f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n'.encode()
            self.assertIsNone(take_cdn_length_response(header + body[:-1]))
            response = take_cdn_length_response(header + body + b'trailing')
            self.assertEqual(response.decode_text(), text)
            self.assertEqual(response.consumed, len(header) + len(body))
        self.assertEqual(len(decode_cdn_body_text(b'x' * MAX_BODY_BYTES)), MAX_BODY_BYTES)
        for body in [b'x' * (MAX_BODY_BYTES + 1), bytearray(b'{}'), b'prefix\0private', b'\xffprivate']:
            with self.assertRaises(ValueError) as caught:
                decode_cdn_body_text(body)
            self.assertNotIn('private', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
