"""Bounded block grammar recovered from native 0x14141ba60.

Literal/match tokens, LE16 backward offsets and extended lengths; no dictionary,
frame magic or checksum is implied. See HEADLESS-BLOCK-DECODE.md for provenance.
"""


def decode_transport_block(block: bytes, *, max_output_size: int) -> bytes:
    """Decode one independent block within an explicit output budget (<=1 MiB).

    Malformed input raises ValueError. Zero offsets are rejected by local policy;
    native writes for that invalid case are not a portable protocol definition.
    """
    if (isinstance(max_output_size, bool) or not isinstance(max_output_size, int)
            or not 1 <= max_output_size <= 0x100000):
        raise ValueError('Expected an output limit between 1 and 1048576')
    if not block:
        raise ValueError('Missing block token')
    output = bytearray()
    cursor = 0

    def length(base: int) -> int:
        nonlocal cursor
        if base == 15:
            while True:
                if cursor == len(block):
                    raise ValueError('Truncated extended length')
                extra = block[cursor]
                cursor += 1
                base += extra
                if base > max_output_size:
                    raise ValueError('Block exceeds output limit')
                if extra != 255:
                    break
        return base

    matched = False
    while cursor < len(block):
        token = block[cursor]
        cursor += 1
        literals = length(token >> 4)
        if cursor + literals > len(block) or len(output) + literals > max_output_size:
            raise ValueError('Literal range outside block or output limit')
        output.extend(block[cursor:cursor + literals])
        cursor += literals
        if cursor == len(block):
            if matched and literals < 5:
                raise ValueError('Missing final literal tail')
            return bytes(output)
        if cursor + 2 > len(block):
            raise ValueError('Truncated match offset')
        offset = int.from_bytes(block[cursor:cursor + 2], 'little')
        cursor += 2
        if offset == 0 or offset > len(output):
            raise ValueError('Match offset outside decoded history')
        count = length(token & 15) + 4
        if len(output) + count > max_output_size:
            raise ValueError('Match exceeds output limit')
        # The native decoder requires room for the final five literal bytes.
        if len(block) - cursor < 6:
            raise ValueError('Missing final literal sequence')
        matched = True
        # Extend in bounded chunks. This preserves overlapping match semantics.
        while count:
            chunk = min(count, offset)
            output.extend(output[-offset:][:chunk])
            count -= chunk
    raise ValueError('Block ends without a literal sequence')
