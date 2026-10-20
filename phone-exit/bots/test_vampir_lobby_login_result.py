import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
from dataclasses import replace

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_login_result import LobbyLoginResultBody, decode_lobby_login_result
from vampir_core.login_context import bind_lobby_login_fields
from vampir_core.login_packet import LoginPayload

ROOT = Path('F:/PhoneExit Resources/Vampir/code-clues')


def tool(filename):
    spec = importlib.util.spec_from_file_location('test_lobby_' + filename.replace('-', '_'),
        HERE / 'resource-tools/vampir' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LobbyLoginResultTests(unittest.TestCase):
    def test_actual_native_reader_vectors_and_every_short_prefix(self):
        report = json.loads((ROOT / 'lobby-login-result-replay.json').read_text('utf-8'))
        self.assertEqual(tool('replay-lobby-login-result.py').build(), report)
        self.assertEqual(len(report['cases']), 7)
        for case in report['cases']:
            data = bytes.fromhex(case['payload_hex'])
            result = decode_lobby_login_result(data, max_payload_size=4096)
            self.assertEqual(result.strings, tuple(case['strings']))
            self.assertEqual(result.integers, tuple(case['integers']) + (case['tail'],))
            self.assertEqual(case['consumed'], len(data))
            self.assertEqual(case['returned'], 1)
        self.assertEqual(len(report['truncated']), 72)
        for case in report['truncated']:
            self.assertEqual(case['returned'], 0)
            with self.assertRaises(ValueError):
                decode_lobby_login_result(bytes.fromhex(case['payload_hex']), max_payload_size=4096)
        with self.assertRaises(ValueError):
            decode_lobby_login_result(bytes.fromhex(report['trailing']['payload_hex']), max_payload_size=4096)

    def test_local_budgets_text_validation_and_hidden_repr(self):
        minimal = bytes(26)
        self.assertEqual(decode_lobby_login_result(minimal, max_payload_size=26).result_code, 0)
        for budget in (25, True, 0x1000000):
            with self.assertRaises(ValueError): decode_lobby_login_result(minimal, max_payload_size=budget)
        with self.assertRaises(BufferError): decode_lobby_login_result(minimal + b'x', max_payload_size=26)
        with self.assertRaises(ValueError): decode_lobby_login_result(bytearray(minimal), max_payload_size=26)
        for bad in (b'\xff', b'\0', '\uffff'.encode('utf-8')):
            body = bytes(12) + struct.pack('<H', len(bad)) + bad + bytes(12)
            with self.assertRaises(ValueError): decode_lobby_login_result(body, max_payload_size=4096)
        value = LobbyLoginResultBody(('sensitive-fixture',) * 5, (0,) * 4)
        self.assertNotIn('sensitive-fixture', repr(value))
        with self.assertRaises(ValueError): LobbyLoginResultBody(('',) * 5, (0, 0, 0, True))

    def test_lobby_success_binds_two_game_fields_without_overwriting_other_context(self):
        login = LoginPayload(('', '') + tuple('field-' + str(i) for i in range(2, 15)),
            (1, 2, 3, 4), (1, 2, 3, 4, 5), 7)
        result = LobbyLoginResultBody(('lobby-a', 'lobby-b', 'unused-c', 'unused-d', 'unused-e'), (0, 7, 8, 9))
        bound = bind_lobby_login_fields(login, lobby_result=result)
        self.assertEqual(bound, replace(login, strings=('lobby-a', 'lobby-b') + login.strings[2:]))
        self.assertEqual(login.strings[:2], ('', ''))
        self.assertEqual(bind_lobby_login_fields(bound, lobby_result=result), bound)
        with self.assertRaises(ValueError):
            bind_lobby_login_fields(bound, lobby_result=replace(result, strings=('other',) + result.strings[1:]))
        with self.assertRaises(ValueError):
            bind_lobby_login_fields(login, lobby_result=replace(result, integers=(1, 7, 8, 9)))
        with self.assertRaises(ValueError):
            bind_lobby_login_fields(login, lobby_result=replace(result, strings=('',) + result.strings[1:]))
        with self.assertRaises(TypeError): bind_lobby_login_fields(login, lobby_result=object())

    def test_static_call_discovery_is_source_bound_and_connects_server_result(self):
        report = json.loads((ROOT / 'lobby-login-path.json').read_text('utf-8'))
        self.assertEqual(tool('build-lobby-login-path.py').build(), report)
        edges = {(row['root'], row['target']) for row in report['calls']}
        self.assertIn((0x1467a9360, 0x145744fa0), edges)
        self.assertIn((0x1467a9360, 0x144aa89b0), edges)
        self.assertIn((0x14677f350, 0x145d4afe0), edges)
        self.assertIn((0x146425730, 0x145d39440), edges)


if __name__ == '__main__': unittest.main()
