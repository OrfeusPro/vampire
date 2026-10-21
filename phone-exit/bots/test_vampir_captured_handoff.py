import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

from test_vampir_login_flow import LOGIN
from test_vampir_version_probe import incoming
from vampir_core.lobby_packets import LobbyLoginPayload
from vampir_core.send_frame import encode_lobby_login_frame, encode_login_frame_b


class CapturedHandoffTests(unittest.TestCase):
    def test_only_equality_and_public_shape_are_saved(self):
        path = Path(__file__).parent / 'vampir-headless/inspect-captured-handoff.py'
        spec = importlib.util.spec_from_file_location('test_handoff', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        from dataclasses import replace
        texts = list(LOGIN.strings)
        texts[0:2] = ['private-ticket-first', 'private-ticket-second']
        texts[11] = '{"I_PID":"private-player"}'
        game = replace(LOGIN, strings=tuple(texts))
        request = LobbyLoginPayload(('private-player', game.strings[8], game.strings[6],
            'HK', game.strings[2], game.strings[11]), (2, 0, game.integers[1], 0), 7)
        response = struct.pack('<III', 0, 0, 0)
        for value in (*game.strings[:2], '', '', ''):
            data = value.encode()
            response += struct.pack('<H', len(data)) + data
        response += bytes(4)
        rows = []
        for flow, direction, data in ((88, 'c2s', encode_lobby_login_frame(request, 1, max_payload_size=65536)),
                (88, 's2c', incoming(4, response)[3:]),
                (89, 'c2s', encode_login_frame_b(game, 3, 0, max_payload_size=65536))):
            rows.append(dict(type='data', flow=flow, direction=direction, data=base64.b64encode(data).decode()))
        raw = ('\n'.join(json.dumps(r) for r in rows) + '\n').encode()
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / 'traffic.jsonl'
            capture.write_bytes(raw)
            result = tool.inspect(capture, expected_sha256=hashlib.sha256(raw).hexdigest(), lobby_flow=88, game_flow=89)
            with self.assertRaises(ValueError):
                tool.inspect(capture, expected_sha256='wrong-sha', lobby_flow=88, game_flow=89)
        self.assertTrue(all(result['expected_bindings'].values()))
        self.assertEqual(result['lobby_request_raw_80'], 7)
        self.assertEqual(result['nonempty_response_to_game_matches'], [
            dict(lobby_string_index=0, game_string_index=0), dict(lobby_string_index=1, game_string_index=1)])
        self.assertNotIn('private-', json.dumps(result))
        self.assertNotIn('lobby_response_numbers', result)


if __name__ == '__main__': unittest.main()
