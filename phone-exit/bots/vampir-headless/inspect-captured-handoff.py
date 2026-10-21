"""Compare lobby-to-game session fields in memory; save equality only."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.frame_primitives import xor_transform, payload_crc32
from vampir_core.receive_stream import ReceiveStream, ReceiveLimits
from vampir_core.lobby_login_result import decode_lobby_login_result
from vampir_core.lobby_packets import LobbyLoginPayload
from vampir_core.login_packet import decode_login_payload


def decode_lobby_request(body):
    position = 8
    numbers = struct.unpack_from('<II', body)
    def text():
        nonlocal position
        count = int.from_bytes(body[position:position+2], 'little')
        position += 2
        if position + count > len(body): raise ValueError('Truncated lobby string')
        value = body[position:position+count].decode('utf-8')
        position += count
        return value
    strings = [text() for _ in range(5)]
    numbers += struct.unpack_from('<II', body, position)
    position += 8
    strings.append(text())
    if position + 1 != len(body): raise ValueError('Lobby request tail differs')
    result = LobbyLoginPayload(tuple(strings), numbers, body[position])
    if result.encode(max_payload_size=65536) != body: raise ValueError('Lobby roundtrip differs')
    return result


def inspect(path, *, expected_sha256, lobby_flow, game_flow):
    with Path(path).open('rb') as stream:
        raw = stream.read(12582913)
    if len(raw) > 12582912 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('Capture size or SHA differs')
    records = [json.loads(line) for line in raw.splitlines()]
    lobby = [r for r in records if r.get('flow') == lobby_flow and r['type'] == 'data']
    outgoing = b''.join(base64.b64decode(r['data'], validate=True) for r in lobby if r['direction'] == 'c2s')
    request = None
    while outgoing:
        size = int.from_bytes(outgoing[:3], 'little')
        if not 11 <= size <= len(outgoing): raise ValueError('Lobby frame bounds')
        plain = xor_transform(outgoing[3:size])
        outgoing = outgoing[size:]
        if int.from_bytes(plain[:4], 'little') != payload_crc32(plain[4:]): raise ValueError('Lobby CRC differs')
        if int.from_bytes(plain[4:6], 'little') == 3:
            if request is not None: raise ValueError('Multiple lobby Logins')
            request = decode_lobby_request(plain[8:])
    receiver = ReceiveStream(ReceiveLimits(65536, 65536, 65536, 131072, 131072), uncompressed_offset=0)
    response = None
    for row in lobby:
        if row['direction'] != 's2c': continue
        receiver.feed(base64.b64decode(row['data'], validate=True))
        while (packet := receiver.next_packet(key_bits=0, max_transport_frames=32)) is not None:
            if packet.packet_id == 4:
                if response is not None: raise ValueError('Multiple lobby responses')
                response = decode_lobby_login_result(packet.body, max_payload_size=65536)
    if receiver.raw_bytes or receiver.decoded_bytes or request is None or response is None:
        raise ValueError('Incomplete lobby exchange')
    spec = importlib.util.spec_from_file_location('handoff_login_inspector', HERE / 'inspect-captured-login.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    games = []
    def consume(identifier, body):
        if identifier == 3: games.append(decode_login_payload(body, max_payload_size=65536))
    tool.inspect(path, flow=game_flow, expected_sha256=expected_sha256, _consume_frame=consume)
    if len(games) != 1: raise ValueError('Expected one game Login')
    game = games[0]
    # Do not save hashes or values of credentials, even transient session strings.
    pairs = [(i, j) for i, a in enumerate(response.strings) for j, b in enumerate(game.strings) if a and a == b]
    return dict(capture_sha256=expected_sha256, lobby_flow=lobby_flow, game_flow=game_flow,
        lobby_result_code=response.result_code,
        lobby_request_numbers=request.integers, lobby_request_raw_80=request.raw_80,
        nonempty_response_to_game_matches=[dict(lobby_string_index=i, game_string_index=j) for i, j in pairs],
        expected_bindings=dict(first_lobby_string_to_game_0=response.strings[0] == game.strings[0],
            second_lobby_string_to_game_1=response.strings[1] == game.strings[1],
            sdk_token_lobby_1_to_game_8=request.strings[1] == game.strings[8],
            nid_lobby_4_to_game_2=request.strings[4] == game.strings[2],
            device_lobby_2_to_game_6=request.strings[2] == game.strings[6],
            metadata_lobby_5_to_game_11=request.strings[5] == game.strings[11],
            selected_server_matches=request.integers[2] == game.integers[1]),
        metadata_lengths=dict(lobby=len(request.strings[5].encode()), game=len(game.strings[11].encode())),
        auth_values_saved=False, network_used=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--lobby-flow', type=int, required=True)
    parser.add_argument('--game-flow', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.capture, expected_sha256=args.sha256, lobby_flow=args.lobby_flow, game_flow=args.game_flow)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(report=str(args.output), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        expected_bindings=result['expected_bindings'], metadata_lengths=result['metadata_lengths'])))
