import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

PATH = Path(__file__).parent / 'resource-tools/vampir/import-pcapng-tcp.py'
SPEC = importlib.util.spec_from_file_location('pcapng_tcp_test', PATH)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def block(kind, body):
    body += bytes((-len(body)) % 4)
    size = len(body) + 12
    return struct.pack('<II', kind, size) + body + struct.pack('<I', size)


def capture(*frames):
    data = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    data += block(1, struct.pack('<HHI', 1, 0, 65535))
    for frame in frames:
        data += block(6, struct.pack('<IIIII', 0, 0, 0, len(frame), len(frame)) + frame)
    return data


def frame(seq, payload=b'', flags=24, *, incoming=False, total=None, target=12000):
    tcp = struct.pack('!HHIIBBHHH', target if incoming else 50000, 50000 if incoming else target,
        seq, 0, 0x50, flags, 1000, 0, 0) + payload
    ip = bytearray(20)
    ip[0] = 0x45; ip[9] = 6
    ip[2:4] = struct.pack('!H', total if total is not None else len(tcp) + 20)
    ip[12:20] = bytes((8, 8, 8, 8, 1, 1, 1, 1)) if incoming else bytes((1, 1, 1, 1, 8, 8, 8, 8))
    return bytes(12) + b'\x08\x00' + ip + tcp


class PcapngTcpTests(unittest.TestCase):
    def test_reorders_deduplicates_and_validates_overlap(self):
        self.assertEqual(TOOL.assemble([(104, b'ef'), (100, b'abcd'), (102, b'cde')], 100), b'abcdef')
        for rows, initial in (([(102, b'gap')], 100), ([(100, b'ab'), (101, b'X')], 100)):
            with self.assertRaises(ValueError): TOOL.assemble(rows, initial)
        self.assertEqual(TOOL.assemble([(0xffffffff, b'ab'), (1, b'cd')], 0xffffffff), b'abcd')

    def test_direction_prefix_and_half_close_are_explicit(self):
        raw = capture(frame(9, flags=2), frame(12, b'cd'), frame(10, b'ab'),
            frame(50, b'reply', incoming=True), frame(14, flags=17))
        flows, _ = TOOL.inspect(raw, 12000)
        self.assertEqual(flows[0]['streams'], {'c2s': b'abcd', 's2c': b'reply'})
        self.assertEqual(flows[0]['prefix_observed'], {'c2s': True, 's2c': False})
        self.assertFalse(flows[0]['closed'])
        flows, _ = TOOL.inspect(raw + block(6, struct.pack('<IIIII', 0, 0, 0, 54, 54) + frame(55, flags=17, incoming=True)), 12000)
        self.assertTrue(flows[0]['closed'])

    def test_rejects_bad_blocks_selected_offload_gap_and_tuple_reuse(self):
        good = capture(frame(9, flags=2), frame(10, b'ab'))
        for data in (b'', good[:-1], good[:-4] + bytes(4), capture(frame(10, b'private', total=0)),
                capture(frame(9, flags=2), frame(11, b'missing')), capture(frame(9, flags=2), frame(99, flags=2))):
            with self.subTest(size=len(data)), self.assertRaises(ValueError): TOOL.inspect(data, 12000)
        flows, skipped = TOOL.inspect(capture(frame(10, b'private', total=0, target=443)), 12000)
        self.assertEqual(flows, [])
        self.assertEqual(skipped, {'other_tcp_port': 1})

    def test_export_hash_no_overwrite_and_private_data_excluded_from_summary(self):
        raw = capture(frame(9, flags=2), frame(10, b'private-token'))
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'source.pcapng', Path(folder) / 'traffic.jsonl'
            source.write_bytes(raw)
            with self.assertRaises(ValueError): TOOL.export(source, output, 12000, 'wrong')
            self.assertFalse(output.exists())
            result = TOOL.export(source, output, 12000, hashlib.sha256(raw).hexdigest())
            self.assertNotIn('private-token', json.dumps(result))
            self.assertEqual(result['flows'][0]['bytes']['c2s'], 13)
            before = output.read_bytes()
            with self.assertRaises(FileExistsError): TOOL.export(source, output, 12000, hashlib.sha256(raw).hexdigest())
            self.assertEqual(output.read_bytes(), before)
            checked = subprocess.run(['node', str(PATH.parents[3] / 'pc/src/capture-inspect.js'), str(output)],
                capture_output=True, text=True, check=True, timeout=10)
            summary = json.loads(checked.stdout)
            self.assertEqual(summary['bytes'], 13)
            self.assertEqual(summary['fileSha256'], result['output_sha256'])


if __name__ == '__main__': unittest.main()
