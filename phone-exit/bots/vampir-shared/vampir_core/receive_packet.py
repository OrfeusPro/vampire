"""Selected incoming game packet decoding. No session/handler side effects."""
from .ping import PingResultPayload
from .receive_frame import take_receive_a_frame, take_receive_b_frame


def _decode_one(result: tuple[bytes, int] | None, frame_size: int) -> PingResultPayload:
    if result is None:
        raise ValueError('Incomplete receive frame')
    plain, consumed = result
    if consumed != frame_size:
        raise ValueError('Expected exactly one receive frame')
    if int.from_bytes(plain[3:5], 'little') != 17:
        raise ValueError('Expected game PingResult ID17')
    return PingResultPayload.decode(plain[5:])


def decode_game_ping_result(frame: bytes, *, max_frame_size: int) -> PingResultPayload:
    """Decode exactly one receive-A game PingResult frame (ID17, body12).

    Local policy rejects trailing bytes/extra frames although the native reader
    tolerates trailing body data. Evidence: HEADLESS-DISPATCH.md. This is not a
    universal ID registry: lobby/game factories can assign different types to IDs.
    """
    result = take_receive_a_frame(frame, max_frame_size=max_frame_size)
    return _decode_one(result, len(frame))


def decode_game_ping_result_b(frame: bytes, key_bits: int, *, max_frame_size: int) -> PingResultPayload:
    """Decode exactly one receive-B game PingResult, with the explicit peer key.

    Same strict body/one-frame policy as the A helper; no session notifications
    or integrity guarantees. Evidence: HEADLESS-RECEIVE-B.md.
    """
    result = take_receive_b_frame(frame, key_bits, max_frame_size=max_frame_size)
    return _decode_one(result, len(frame))
