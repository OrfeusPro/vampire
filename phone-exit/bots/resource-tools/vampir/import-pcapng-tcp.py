"""Offline Ethernet/IPv4 TCP import; private output, no network or packet replay."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct

MAX_FILE = 64 * 1024 * 1024
MAX_STREAM = 8 * 1024 * 1024


def packets(raw):
    """Read bounded PCAPNG sections and Ethernet enhanced packet blocks."""
    if not raw:
        raise ValueError('Empty capture')
    offset, endian, interfaces = 0, None, []
    while offset < len(raw):
        if offset + 12 > len(raw):
            raise ValueError('Truncated block')
        if raw[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
            endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(raw[offset + 8:offset + 12])
            interfaces = []
        if endian is None:
            raise ValueError('Missing supported section')
        kind, size = struct.unpack_from(endian + 'II', raw, offset)
        if size < 12 or size % 4 or offset + size > len(raw):
            raise ValueError('Invalid block size')
        if struct.unpack_from(endian + 'I', raw, offset + size - 4)[0] != size:
            raise ValueError('Block sizes differ')
        if kind == 1:
            if size < 20:
                raise ValueError('Short interface')
            interfaces.append(struct.unpack_from(endian + 'H', raw, offset + 8)[0])
        elif kind == 6:
            if size < 32:
                raise ValueError('Short packet block')
            interface, _, _, captured, original = struct.unpack_from(endian + 'IIIII', raw, offset + 8)
            if interface >= len(interfaces) or captured > original or captured > size - 32:
                raise ValueError('Invalid packet bounds')
            yield interfaces[interface], raw[offset + 28:offset + 28 + captured], captured < original
        elif kind in (2, 3):
            raise ValueError('Unsupported packet block')
        offset += size


def assemble(segments, initial=None):
    """Deduplicate equal retransmissions; reject gaps and conflicting overlaps."""
    if not segments:
        return b''
    anchor = initial if initial is not None else segments[0][0]
    ordered = []
    for sequence, data in segments:
        delta = (sequence - anchor + 2**31) % 2**32 - 2**31
        ordered.append((delta, data))
    if initial is None:
        start = min(pos for pos, _ in ordered)
        ordered = [(pos - start, data) for pos, data in ordered]
    output = bytearray()
    for pos, data in sorted(ordered):
        if pos < 0 or pos > len(output):
            raise ValueError('TCP gap or missing prefix')
        overlap = min(len(data), len(output) - pos)
        if output[pos:pos + overlap] != data[:overlap]:
            raise ValueError('Conflicting TCP overlap')
        if len(output) + len(data) - overlap > MAX_STREAM:
            raise ValueError('TCP stream limit')
        output.extend(data[overlap:])
    return bytes(output)


def inspect(raw, port):
    if not 1 <= port <= 65535 or len(raw) > MAX_FILE:
        raise ValueError('Import bounds')
    flows, skipped = {}, {}
    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1
    for link, packet, truncated in packets(raw):
        if link != 1:
            raise ValueError('Only Ethernet links supported')
        if len(packet) < 14:
            raise ValueError('Short Ethernet packet')
        ethertype, pos = struct.unpack_from('!H', packet, 12)[0], 14
        while ethertype in (0x8100, 0x88a8):
            if pos + 4 > len(packet):
                raise ValueError('Short VLAN header')
            ethertype, pos = struct.unpack_from('!H', packet, pos + 2)[0], pos + 4
        if ethertype != 0x800:
            skip('non_ipv4'); continue
        ip = packet[pos:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            raise ValueError('Invalid IPv4 header')
        ihl, total, fragment = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], 'big'), int.from_bytes(ip[6:8], 'big')
        if ip[9] != 6:
            skip('non_tcp'); continue
        if fragment & 0x3fff:
            raise ValueError('Fragmented TCP not supported')
        if ihl < 20 or len(ip) < ihl + 20:
            raise ValueError('Short TCP packet')
        source, target = struct.unpack_from('!HH', ip, ihl)
        if port not in (source, target):
            skip('other_tcp_port'); continue
        if source == target:
            raise ValueError('Ambiguous direction')
        if truncated or total < ihl + 20 or total > len(ip):
            raise ValueError('Selected TCP packet truncated or offloaded')
        tcp = ip[ihl:total]
        header = (tcp[12] >> 4) * 4
        if not 20 <= header <= len(tcp):
            raise ValueError('Invalid TCP header')
        outgoing = target == port
        key = (ip[12:16], source, ip[16:20], target) if outgoing else (ip[16:20], target, ip[12:16], source)
        flow = flows.setdefault(key, dict(c2s=[], s2c=[], initial={}, fin=set(), rst=False))
        if len(flows) > 16:
            raise ValueError('Flow limit')
        direction = 'c2s' if outgoing else 's2c'
        sequence = int.from_bytes(tcp[4:8], 'big')
        if tcp[13] & 2:
            initial = (sequence + 1) % 2**32
            if direction in flow['initial'] and flow['initial'][direction] != initial:
                raise ValueError('Reused TCP tuple requires separate capture')
            flow['initial'][direction] = initial
            sequence = initial
        if tcp[13] & 1:
            flow['fin'].add(direction)
        if tcp[13] & 4:
            flow['rst'] = True
        if len(tcp) > header:
            flow[direction].append((sequence, tcp[header:]))
    result = []
    for number, flow in enumerate(flows.values(), 1):
        streams = {}
        for direction in ('c2s', 's2c'):
            try:
                streams[direction] = assemble(flow[direction], flow['initial'].get(direction))
            except ValueError as error:
                raise ValueError(f'Flow {number} {direction}: {error}') from None
        result.append(dict(streams=streams,
            prefix_observed={d: d in flow['initial'] for d in ('c2s', 's2c')},
            closed=flow['rst'] or len(flow['fin']) == 2))
    return result, skipped


def export(path, output, port, expected_sha256):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_FILE + 1)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise ValueError('PCAPNG SHA differs')
    flows, skipped = inspect(raw, port)
    # Validate every stream before creating output; existing data is never replaced.
    rows = [dict(type='start', version=1, mode='endpoints', producer='pcapng-tcp-import',
        source_sha256=digest, secrets=True, point='Reassembled observed Ethernet/IPv4 TCP payload; no remote-receipt proof')]
    total = 0
    for number, flow in enumerate(flows, 1):
        rows.append(dict(type='open', flow=number, port=port))
        for direction, data in flow['streams'].items():
            total += len(data)
            for offset in range(0, len(data), 65536):
                chunk = data[offset:offset + 65536]
                rows.append(dict(type='data', flow=number, direction=direction, offset=offset,
                    length=len(chunk), data=base64.b64encode(chunk).decode('ascii')))
        if flow['closed']:
            rows.append(dict(type='close', flow=number, **{d: len(data) for d, data in flow['streams'].items()}))
    rows.append(dict(type='end', reason='import_complete', flows=len(flows), bytes=total))
    encoded = ('\n'.join(json.dumps(row) for row in rows) + '\n').encode('utf-8')
    if total > 8388608 or len(encoded) > 12582912:
        raise ValueError('Diagnostic format limits exceeded')
    with Path(output).open('xb') as stream:
        stream.write(encoded)
    return dict(source_sha256=digest, output_sha256=hashlib.sha256(encoded).hexdigest(), skipped=skipped,
        flows=[dict(flow=i, bytes={d: len(v) for d, v in f['streams'].items()}, prefix_observed=f['prefix_observed'],
            closed=f['closed']) for i, f in enumerate(flows, 1)],
        limits='Only Ethernet/IPv4 TCP at explicit port. Missing SYN means prefix unproven. End marks import completion, not complete sessions. Checksums not validated.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(export(args.capture, args.output, args.port, args.sha256)))
    except ValueError as error:
        # Only fixed local validation messages and flow numbers reach this path.
        print(json.dumps(dict(status='pcapng_import_rejected', reason=str(error))))
        raise SystemExit(2)
    except (OSError, KeyError, struct.error):
        print(json.dumps(dict(status='pcapng_import_rejected')))
        raise SystemExit(2)
