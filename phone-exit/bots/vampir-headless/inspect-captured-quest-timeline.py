"""Offline game-frame timeline: IDs, sizes and observation times; no packet bodies."""
import argparse
import base64
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'vampir-shared'))
from vampir_core.frame_primitives import xor_transform, payload_crc32
from vampir_core.key_change import KeyChangePayload
from vampir_core.receive_stream import ReceiveStream, ReceiveLimits


def inspect(path, *, flow, expected_sha256):
    if type(flow) is not int or not 1 <= flow <= 1024:
        raise ValueError('Invalid flow')
    with Path(path).open('rb') as stream:
        raw = stream.read(12582913)
    if len(raw) > 12582912 or not raw.endswith(b'\n'):
        raise ValueError('Capture bounds')
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise ValueError('Capture SHA differs')
    records = [json.loads(line) for line in raw.splitlines()]
    if records[0].get('type') != 'start' or records[-1].get('type') != 'end':
        raise ValueError('Finalized capture required')
    # The complete JSONL must also pass pc/src/capture-inspect.js. Here check
    # the selected flow again before passing any bytes to the frame codecs.
    selected = [r for r in records if r.get('flow') == flow]
    if not selected or selected[0]['type'] != 'open':
        raise ValueError('Flow open missing')
    receiver = ReceiveStream(ReceiveLimits(1048576, 1048576, 1048576, 2097152, 2097152),
        uncompressed_offset=3)
    rxkey = txkey = 0
    pending = None
    send = bytearray()
    offsets = dict(c2s=0, s2c=0)
    packets = []
    closed = False
    previous_ms = -1

    def observe(direction, identifier, size, ms):
        if len(packets) >= 65536:
            raise ValueError('Packet budget exceeded')
        packets.append(dict(index=len(packets), direction=direction, id=identifier,
            size=size, observed_ms=ms))

    for row in selected[1:]:
        if closed:
            raise ValueError('Flow event after close')
        if row['type'] == 'close':
            if row['c2s'] != offsets['c2s'] or row['s2c'] != offsets['s2c']:
                raise ValueError('Close counters differ')
            closed = True
            continue
        if row['type'] != 'data' or row.get('direction') not in offsets:
            raise ValueError('Invalid selected flow event')
        direction = row['direction']
        ms = row.get('ms')
        if type(ms) not in (int, float) or not math.isfinite(ms) or ms < 0 or ms < previous_ms:
            raise ValueError('Invalid observation time')
        previous_ms = ms
        value = base64.b64decode(row['data'], validate=True)
        if row['offset'] != offsets[direction] or row['length'] != len(value):
            raise ValueError('Selected flow offsets differ')
        offsets[direction] += len(value)
        if direction == 's2c':
            receiver.feed(value)
            for _ in range(65536):
                packet = receiver.next_packet(key_bits=rxkey, max_transport_frames=4096)
                if packet is None:
                    break
                observe(direction, packet.packet_id, len(packet.body), ms)
                if packet.packet_id == 11:
                    if pending is not None:
                        raise ValueError('Overlapping key change')
                    pending = KeyChangePayload.decode(packet.body).key_bits
                    rxkey = pending
            else:
                raise ValueError('Receive packet budget exceeded')
        else:
            send.extend(value)
            while len(send) >= 3:
                size = int.from_bytes(send[:3], 'little')
                if not 11 <= size <= 1048576:
                    raise ValueError('Outgoing frame bounds')
                if len(send) < size:
                    break
                plain = xor_transform(bytes(send[3:size]), txkey)
                del send[:size]
                if int.from_bytes(plain[:4], 'little') != payload_crc32(plain[4:]):
                    raise ValueError('Outgoing CRC differs')
                identifier = int.from_bytes(plain[4:6], 'little')
                body = plain[8:]
                observe(direction, identifier, len(body), ms)
                if identifier == 12:
                    key = KeyChangePayload.decode(body).key_bits
                    if pending is None or pending != key:
                        raise ValueError('Key acknowledgement differs')
                    txkey, pending = key, None
    if send or receiver.raw_bytes or receiver.decoded_bytes:
        raise ValueError('Incomplete game frame tail')
    return dict(capture_sha256=digest, flow=flow, mode='game_uncompressed_offset_3',
        packet_count=len(packets), byte_counts=offsets, flow_closed=closed,
        counts={d:dict(Counter(str(p['id']) for p in packets if p['direction'] == d))
            for d in offsets}, packets=packets, pending_key_ack=pending is not None,
        auth_values_saved=False, network_used=False,
        limits=['Run capture-inspect.js first for full JSONL validation.',
            'Times are TCP chunk observation times, not exact clicks or server execution times.',
            'Only framing, CRC, key changes, IDs and sizes checked; no action semantics inferred.',
            'An open flow at capture stop is allowed only with no incomplete frame tail.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--flow', type=int, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect(args.capture, flow=args.flow, expected_sha256=args.sha256)
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps(dict(report=str(args.output), sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
            packets=result['packet_count'])))
    except (ValueError, OSError, KeyError, TypeError, BufferError, RuntimeError):
        print(json.dumps(dict(status='capture_quest_timeline_not_inspected')))
        sys.exit(2)
