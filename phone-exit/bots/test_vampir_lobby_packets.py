import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import (LobbyVersionPayload, LobbyServerListPayload,
    LobbyVersionResultBody, decode_lobby_version_result)


class LobbyCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-handshake-codecs.json').read_text('utf-8'))

    def test_whole_native_writers_and_reader_reproduce(self):
        path = HERE / 'resource-tools/vampir/replay-lobby-handshake-codecs.py'
        spec = importlib.util.spec_from_file_location('test_lobby_codecs_native', path)
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        self.assertEqual(native.build(), self.report)

    def test_all_native_writer_vectors_match_portable_bodies(self):
        self.assertEqual(len(self.report['cases']), 20)
        for case in self.report['cases']:
            if case['kind'] == 'version':
                value = LobbyVersionPayload(tuple(case['strings']), tuple(case['raw_bytes']), case['integer'])
            else:
                value = LobbyServerListPayload(tuple(case['strings']), case['integer'], tuple(case['raw_bytes']))
            data = bytes.fromhex(case['payload_hex'])
            self.assertEqual(value.encode(max_payload_size=len(data)), data)
            if any(case['strings']):
                with self.assertRaises(BufferError): value.encode(max_payload_size=len(data) - 1)

    def test_all_native_results_short_prefixes_and_local_exact_length(self):
        self.assertEqual(len(self.report['results']), 4)
        for case in self.report['results']:
            result = decode_lobby_version_result(bytes.fromhex(case['payload_hex']))
            self.assertEqual((result.result_code, result.flag_14, result.time_bits, result.raw_38),
                (case['result_code'], bool(case['flag']), tuple(case['time_bits']), case['raw_38']))
            self.assertEqual(case['returned'], 1)
            self.assertEqual(case['consumed'], 23)
        for case in self.report['truncated']:
            self.assertEqual(case['returned'], 0)
            with self.assertRaises(ValueError): decode_lobby_version_result(bytes.fromhex(case['payload_hex']))
        with self.assertRaises(ValueError):
            decode_lobby_version_result(bytes.fromhex(self.report['trailing']['payload_hex']))
        with self.assertRaises(ValueError): decode_lobby_version_result(bytearray(23))

    def test_explicit_fields_budgets_and_sensitive_repr(self):
        version = LobbyVersionPayload(('sensitive-fixture',) * 5, (0, 3), 1)
        self.assertNotIn('sensitive-fixture', repr(version))
        request = LobbyServerListPayload(('identity-fixture', 'nid-fixture'), 2, (1, 255))
        self.assertNotIn('nid-fixture', repr(request))
        self.assertEqual(request.encode(max_payload_size=4096)[-2:], b'\x01\xff')
        for invalid in (None, True, -1, 0x1000000):
            with self.assertRaises(ValueError): version.encode(max_payload_size=invalid)
        for bad in ((True, 0), (0, 256), [0, 1]):
            with self.assertRaises(ValueError): LobbyVersionPayload(('',) * 5, bad, 1)
        for bad in ('\0', '\ud800', '\uffff', 'é' * 32768):
            with self.assertRaises(ValueError): LobbyServerListPayload((bad, ''), 0, (0, 0))
        with self.assertRaises(ValueError): LobbyVersionResultBody(0, 1, (0, 0), 0)
        self.assertEqual(len(LobbyVersionPayload(('',) * 5, (0, 0), 0).encode(max_payload_size=16)), 16)
        self.assertEqual(len(LobbyServerListPayload(('',) * 2, 0, (0, 0)).encode(max_payload_size=10)), 10)


if __name__ == '__main__': unittest.main()
