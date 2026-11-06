"""Current lobby layout; bounded native fixtures, no game or network."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import (CURRENT_LOBBY_VERSION_SOURCE,
    CurrentLobbyVersionResultBody, LobbyVersionResultBody,
    decode_current_lobby_version_result, decode_lobby_version_result, make_windows_lobby_login)


class CurrentLobbyVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/verify-lobby-version-result-current.py'
        spec = importlib.util.spec_from_file_location('current_lobby_layout_fixture', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        result = cls.tool.verify()
        cls.report = json.loads(Path(result['report']).read_bytes())

    def decode(self, data):
        return decode_current_lobby_version_result(data, source_sha256=CURRENT_LOBBY_VERSION_SOURCE)

    def test_whole_current_reader_order_and_handler_forwarding_match_portable_fields(self):
        report = self.report
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertFalse(report['runtime_admitted'])
        self.assertEqual(len(report['cases']), 3)
        for case in report['cases']:
            result = self.decode(bytes.fromhex(case['payload_hex']))
            self.assertIsInstance(result, CurrentLobbyVersionResultBody)
            self.assertEqual((result.result_code, result.flag_14, result.time_bits, result.raw_38),
                (0, True, (0x1020304050607080, 1792600142863), 540))
            self.assertEqual((result.raw_40, result.raw_50, result.raw_54),
                (case['text'], 0x89abcdef, 0xffffffff))
            self.assertEqual([event['destination'] for event in case['operations']],
                [0x10, 0x14, 0x18, 0x28, 0x38, 0x40, 0x50, 0x54])
            self.assertNotIn(case['text'] if case['text'] else 'unavailable-text', repr(result))
        self.assertEqual(len(report['handler_cases']), 6)
        for case in report['handler_cases']:
            apply = next(e for e in case['events'] if e['operation'] == 'metadata_apply')
            self.assertEqual(apply['packet_string'], case['metadata_valid'])
            self.assertEqual(apply['blank'], not case['metadata_valid'])

    def test_short_prefixes_and_each_failed_native_operation_stop_the_reader(self):
        self.assertEqual(len(self.report['prefix_cases']), 114)
        for case in self.report['cases']:
            body = bytes.fromhex(case['payload_hex'])
            for size in range(len(body)):
                with self.subTest(text=case['text'], size=size), self.assertRaises(ValueError):
                    self.decode(body[:size])
        failures = self.report['failure_cases']
        self.assertEqual(len(failures), 24)
        self.assertTrue(all(case['operations'] == case['failing_operation'] for case in failures))
        self.assertEqual({case['failing_operation'] for case in failures}, set(range(1, 9)))

    def test_strict_length_utf8_bounds_and_explicit_source(self):
        body = bytes.fromhex(self.report['cases'][0]['payload_hex'])
        for malformed in (body + b'\0', bytearray(body), None, body[:23],
                          body[:23] + struct.pack('<H', 10) + body[25:]):
            with self.subTest(malformed=type(malformed)), self.assertRaises(ValueError):
                self.decode(malformed)
        for text in (b'\xff', b'\0', b'\xef\xbf\xbf'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.decode(body[:23] + struct.pack('<H', len(text)) + text + body[-8:])
        maximum = body[:23] + struct.pack('<H', 65535) + b'x' * 65535 + body[-8:]
        self.assertEqual(len(self.decode(maximum).raw_40), 65535)
        with self.assertRaises(ValueError):
            decode_current_lobby_version_result(body, source_sha256='0' * 64)
        with self.assertRaises(TypeError):
            decode_current_lobby_version_result(body)

    def test_legacy_decoder_and_binder_cannot_silently_consume_new_layout(self):
        body = bytes.fromhex(self.report['cases'][0]['payload_hex'])
        legacy = decode_lobby_version_result(body[:23])
        self.assertIsInstance(legacy, LobbyVersionResultBody)
        self.assertEqual(legacy.time_bits, self.decode(body).time_bits)
        with self.assertRaises(ValueError):
            decode_lobby_version_result(body)
        with self.assertRaises(TypeError):
            make_windows_lobby_login(version_result=self.decode(body), kind=2, selected_server_id=387, metadata='')

    def test_corrupt_export_and_leaf_are_rejected_without_publishing_proof(self):
        original = json.loads(self.tool.CONTEXT.read_bytes())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'context.json'
            for kind in ('export', 'leaf'):
                changed = json.loads(json.dumps(original))
                if kind == 'export':
                    key = next(iter(changed['exports']))
                    changed['exports'][key] = '0' * 64
                else:
                    key = next(iter(changed['leaves']))
                    changed['leaves'][key] = '90' + changed['leaves'][key][2:]
                path.write_text(json.dumps(changed), 'utf-8')
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    self.tool.verify(path)


if __name__ == '__main__':
    unittest.main()
