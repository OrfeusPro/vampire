import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

from test_vampir_version_probe import incoming
from vampir_core.send_frame import _encode


class CapturedQuestTimelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'vampir-headless/inspect-captured-quest-timeline.py'
        spec = importlib.util.spec_from_file_location('quest_timeline_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def inspect(self, chunks, *, alter=None, sha=None):
        rows = [dict(type='start', version=1), dict(type='open', flow=7)]
        offsets = dict(c2s=0, s2c=0)
        for i, (direction, value) in enumerate(chunks):
            rows.append(dict(type='data', flow=7, direction=direction, ms=i + 1,
                offset=offsets[direction], length=len(value), data=base64.b64encode(value).decode()))
            offsets[direction] += len(value)
        rows.append(dict(type='end', reason='manual'))
        if alter:
            alter(rows)
        raw = ('\n'.join(json.dumps(row) for row in rows) + '\n').encode()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'traffic.jsonl'
            path.write_bytes(raw)
            return self.tool.inspect(path, flow=7, expected_sha256=sha or hashlib.sha256(raw).hexdigest())

    def test_fragmented_frames_and_coalesced_packets_do_not_save_bodies(self):
        sent = _encode(3, b'private-auth-token', 1, 0) + _encode(1810, bytes(29), 2, 0)
        received = incoming(1811, b'private-character-data') + incoming(206, bytes(8))
        result = self.inspect([('c2s', sent[:2]), ('c2s', sent[2:]),
            ('s2c', received[:4]), ('s2c', received[4:])])
        self.assertEqual(result['packet_count'], 4)
        self.assertEqual([p['id'] for p in result['packets']], [3, 1810, 1811, 206])
        self.assertEqual([p['observed_ms'] for p in result['packets']], [2, 2, 4, 4])
        self.assertFalse(result['flow_closed'])
        self.assertNotIn('private-', json.dumps(result))
        self.assertNotIn('body', json.dumps(result))

    def test_key_switch_waits_for_matching_ack_and_does_not_save_key(self):
        key = 0x123456789abcdef0
        body = struct.pack('<Q', key)
        result = self.inspect([('s2c', incoming(11, body)),
            ('c2s', _encode(12, body, 1, 0)),
            ('s2c', incoming(1840, b'private-state', key)),
            ('c2s', _encode(1810, bytes(29), 2, key))])
        self.assertEqual([p['id'] for p in result['packets']], [11, 12, 1840, 1810])
        self.assertFalse(result['pending_key_ack'])
        self.assertNotIn(str(key), json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'acknowledgement'):
            self.inspect([('s2c', incoming(11, body)),
                ('c2s', _encode(12, struct.pack('<Q', key + 1), 1, 0))])

    def test_sha_crc_offsets_and_partial_tails_are_rejected(self):
        sent = _encode(1810, bytes(29), 1, 0)
        with self.assertRaisesRegex(ValueError, 'SHA'):
            self.inspect([('c2s', sent)], sha='wrong')
        broken = bytearray(sent)
        broken[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'CRC'):
            self.inspect([('c2s', bytes(broken))])
        with self.assertRaisesRegex(ValueError, 'offsets'):
            self.inspect([('c2s', sent)], alter=lambda rows: rows[2].update(offset=1))
        with self.assertRaisesRegex(ValueError, 'tail'):
            self.inspect([('c2s', sent[:-1])])
        with self.assertRaises((ValueError, BufferError)):
            self.inspect([('s2c', incoming(1811, bytes(30))[:-1])])

    def test_time_order_and_duplicate_open_are_rejected(self):
        chunks = [('c2s', _encode(1810, b'', 1, 0)), ('s2c', incoming(1811, b''))]
        with self.assertRaisesRegex(ValueError, 'time'):
            self.inspect(chunks, alter=lambda rows: rows[3].update(ms=0))
        with self.assertRaisesRegex(ValueError, 'event'):
            self.inspect(chunks, alter=lambda rows: rows.insert(2, dict(type='open', flow=7)))


if __name__ == '__main__':
    unittest.main()
