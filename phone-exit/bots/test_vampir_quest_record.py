"""Whole record parity; no authorization, socket or gameplay actions."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.quest_record import decode_quest_record
from vampir_core.world_move_start import SOURCE_SHA256


class QuestRecordTests(unittest.TestCase):
    def test_exact_source_and_size(self):
        body = bytes(39)
        for size in range(39):
            with self.assertRaises(ValueError):
                decode_quest_record(body[:size], source_sha256=SOURCE_SHA256)
        for body in (body + b'x', bytearray(body)):
            with self.assertRaises(ValueError): decode_quest_record(body, source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError): decode_quest_record(bytes(39), source_sha256='old')

    def test_fields_and_clamps_are_independent(self):
        record = decode_quest_record(struct.pack('<QBBQQBIII',
            0xffffffffffffffff, 255, 255, 0x8000000000000000, 2, 255, 3, 4, 5),
            source_sha256=SOURCE_SHA256)
        self.assertEqual((record.raw08, record.raw10, record.progress.raw08,
            record.progress.raw10, record.progress.raw18, record.raw38,
            record.raw3c, record.raw40, record.raw44),
            (0xffffffffffffffff, 6, 255, 0x8000000000000000, 2, True, 3, 4, 5))
        self.assertNotIn('18446744073709551615', repr(record))
        self.assertNotIn('9223372036854775808', repr(record))

    def test_whole_native_readers_and_short_inputs(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-quest-record.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 216)
        self.assertEqual([r['size'] for r in report['short']], list(range(39)))


if __name__ == '__main__': unittest.main()
