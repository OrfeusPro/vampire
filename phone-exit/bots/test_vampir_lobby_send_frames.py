import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import LobbyVersionPayload, LobbyServerListPayload
from vampir_core.version_packet import VersionPayload
from vampir_core.send_frame import encode_lobby_version_frame, encode_lobby_server_list_frame


class LobbySendFrameTests(unittest.TestCase):
    def test_whole_native_frame_with_actual_lobby_writers_reproduces(self):
        saved = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-send-frames.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location('test_lobby_native_frames', HERE / 'resource-tools/vampir/replay-lobby-send-frames.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['cases']), 12)
        for case in saved['cases']:
            if case['kind'] == 'version':
                value = LobbyVersionPayload(tuple(case['strings']), tuple(case['raw_bytes']), case['integer'])
                actual = encode_lobby_version_frame(value, case['sequence'], max_payload_size=4096)
            else:
                value = LobbyServerListPayload(tuple(case['strings']), case['integer'], tuple(case['raw_bytes']))
                actual = encode_lobby_server_list_frame(value, case['sequence'], max_payload_size=4096)
            self.assertEqual(actual.hex(), case['frame_hex'])
            self.assertEqual(case['sequence_after'], (case['sequence'] + 1) & 65535)

    def test_game_payload_cannot_enter_lobby_encoder_and_budgets_are_explicit(self):
        with self.assertRaises(TypeError):
            encode_lobby_version_frame(VersionPayload(('',) * 10, (0, 0, 0)), 0, max_payload_size=4096)
        value = LobbyVersionPayload(('',) * 5, (0, 3), 1)
        for sequence in (-1, 65536, True):
            with self.assertRaises(ValueError): encode_lobby_version_frame(value, sequence, max_payload_size=16)
        with self.assertRaises(TypeError): encode_lobby_server_list_frame(value, 0, max_payload_size=4096)
        with self.assertRaises(ValueError): encode_lobby_version_frame(value, 0, max_payload_size=15)


if __name__ == '__main__': unittest.main()
