"""Selected offline frame assembly for the investigated send-A/send-B paths.

Evidence: HEADLESS-SEND-FRAME.md and HEADLESS-SEND-B.md. No socket/login.
"""
import struct
from .ping import PingPayload, SOURCE_SHA256
from .frame_primitives import payload_crc32, xor_transform
from .key_change import KeyChangePayload, KEY_CHANGED_ID
from .character_select import CharacterSelectPayload
from .version_packet import VersionPayload
from .login_packet import LoginPayload


def _encode(packet_id: int, body: bytes, sequence: int, key_bits: int) -> bytes:
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 65535:
        raise ValueError('Expected unsigned 16-bit sequence')
    inner = struct.pack('<HH', packet_id, sequence) + body
    total_size = 3 + 4 + len(inner)
    return total_size.to_bytes(3, 'little') + xor_transform(struct.pack('<I', payload_crc32(inner)) + inner, key_bits)


def encode_ping_frame(payload: PingPayload, sequence: int) -> bytes:
    """Build the native send-A Ping frame; caller owns the per-connection sequence."""
    if not isinstance(payload, PingPayload):
        raise TypeError('Expected PingPayload')
    return _encode(16, payload.encode(), sequence, 0)


def encode_lobby_version_frame(payload, sequence: int, *, max_payload_size: int) -> bytes:
    """Separate lobby ID1/send-A, fixed fallback XOR; no game key/flow."""
    from .lobby_packets import LobbyVersionPayload
    if not isinstance(payload, LobbyVersionPayload): raise TypeError('Expected LobbyVersionPayload')
    return _encode(1, payload.encode(max_payload_size=max_payload_size), sequence, 0)


def encode_lobby_login_frame(payload, sequence: int, *, max_payload_size: int) -> bytes:
    """Separate lobby ID3/send-A, not the game Login schema."""
    from .lobby_packets import LobbyLoginPayload
    if not isinstance(payload, LobbyLoginPayload): raise TypeError('Expected LobbyLoginPayload')
    return _encode(3, payload.encode(max_payload_size=max_payload_size), sequence, 0)


def encode_lobby_server_list_frame(payload, sequence: int, *, max_payload_size: int) -> bytes:
    """Lobby ID103/send-A; readiness and source of fields belong to the owner."""
    from .lobby_packets import LobbyServerListPayload
    if not isinstance(payload, LobbyServerListPayload): raise TypeError('Expected LobbyServerListPayload')
    return _encode(103, payload.encode(max_payload_size=max_payload_size), sequence, 0)


def encode_ping_frame_b(payload: PingPayload, sequence: int, key_bits: int) -> bytes:
    """Build keyed send-B Ping; caller owns the per-connection sequence/key."""
    if not isinstance(payload, PingPayload):
        raise TypeError('Expected PingPayload')
    return _encode(16, payload.encode(), sequence, key_bits)


def encode_key_changed_frame_b(payload: KeyChangePayload, sequence: int, key_bits: int) -> bytes:
    """Build send-B ack carrying the new key, encrypted with the current key."""
    if not isinstance(payload, KeyChangePayload):
        raise TypeError('Expected KeyChangePayload')
    return _encode(KEY_CHANGED_ID, payload.encode(), sequence, key_bits)


def encode_world_move_finish_frame_b(sequence: int, key_bits: int) -> bytes:
    """Encode ID205 with its verified empty body; no readiness check or IO.

    Evidence: HEADLESS-WORLD-MOVE-FINISH-SEND.md. The caller owns the live
    sequence/key and must establish the world-move completion conditions.
    """
    return _encode(205, b'', sequence, key_bits)


def encode_initial_tutorial_ack_frame_b(sequence: int, key_bits: int, *, source_sha256) -> bytes:
    """Explicit diagnostic ack for tutorial 1001/step 2; not a quest-panel click."""
    from .tutorial_request import encode_tutorial_request
    return _encode(9903, encode_tutorial_request(1001, 2, 0,
        source_sha256=source_sha256), sequence, key_bits)


def encode_quest_list_read_frame_b(sequence: int, key_bits: int, *, source_sha256) -> bytes:
    """Explicit reset-field diagnostic, not inferred quest pagination."""
    from .quest_request import encode_quest_list_read
    return _encode(1801, encode_quest_list_read(0, 0, source_sha256=source_sha256), sequence, key_bits)


def encode_world_move_start_frame_b(payload, sequence: int, key_bits: int) -> bytes:
    from .world_move_start import WorldMoveStartPayload
    if not isinstance(payload,WorldMoveStartPayload): raise TypeError('Expected WorldMoveStartPayload')
    return _encode(203,payload.encode(max_payload_size=8),sequence,key_bits)


def encode_character_list_frame_b(sequence: int, key_bits: int) -> bytes:
    """Verified ID101 empty request; lifecycle permission belongs to the owner."""
    return _encode(101, b'', sequence, key_bits)


def encode_version_frame_b(payload: VersionPayload, sequence: int, key_bits: int, *, max_payload_size: int) -> bytes:
    if not isinstance(payload, VersionPayload): raise TypeError('Expected VersionPayload')
    return _encode(1, payload.encode(max_payload_size=max_payload_size), sequence, key_bits)


def encode_login_frame_b(payload: LoginPayload, sequence: int, key_bits: int, *, max_payload_size: int) -> bytes:
    if not isinstance(payload, LoginPayload): raise TypeError('Expected LoginPayload')
    return _encode(3, payload.encode(max_payload_size=max_payload_size), sequence, key_bits)


def encode_character_select_frame_b(payload: CharacterSelectPayload, sequence: int, key_bits: int) -> bytes:
    """Verified ID109 body/frame; does not infer readiness or a character ID."""
    if not isinstance(payload, CharacterSelectPayload):
        raise TypeError('Expected CharacterSelectPayload')
    return _encode(109, payload.encode(max_payload_size=20), sequence, key_bits)
