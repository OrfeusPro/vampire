"""Current full quest snapshot parity and bounds. No authentication or game IO."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.quest_sync import decode_quest_sync
from vampir_core.quest_record import CURRENT_SOURCE_SHA256


class QuestSyncTests(unittest.TestCase):
    def decode(self, body, **limits):
        return decode_quest_sync(body, source_sha256=CURRENT_SOURCE_SHA256,
            **dict(dict(max_collection_items=8, max_total_items=72, max_payload_size=8192), **limits))

    def test_empty_is_received_and_raw_suffix_stays_exact(self):
        value = self.decode(bytes(2) + struct.pack('<Q', 2**64 - 1))
        self.assertEqual(value.groups, ())
        self.assertEqual(value.raw18, 2**64 - 1)
        self.assertNotIn(str(2**64 - 1), repr(value))

    def test_collection_budgets_include_groups_and_nested_quests(self):
        record = struct.pack('<QBBQQBIII', 2**64 - 1, 255, 255, 2**63, 2, 255, 3, 4, 5)
        body = struct.pack('<HBH', 1, 255, 1) + record + bytes(8)
        value = self.decode(body)
        self.assertEqual(value.groups[0].raw08, 12)
        quest = value.groups[0].quests[0]
        self.assertEqual((quest.raw08, quest.raw10, quest.progress.raw08, quest.progress.raw10,
            quest.progress.raw18, quest.raw38, quest.raw3c, quest.raw40, quest.raw44),
            (2**64 - 1, 6, 255, 2**63, 2, True, 3, 4, 5))
        for limits in (dict(max_collection_items=0), dict(max_total_items=1), dict(max_payload_size=len(body) - 1)):
            with self.assertRaises(BufferError):
                self.decode(body, **limits)
        for size in range(len(body)):
            with self.assertRaises(ValueError):
                self.decode(body[:size])
        with self.assertRaises(ValueError):
            self.decode(body + b'x')

    def test_source_type_and_explicit_limits(self):
        body = bytes(10)
        with self.assertRaises(ValueError):
            decode_quest_sync(body, source_sha256='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e',
                max_collection_items=8, max_total_items=72, max_payload_size=8192)
        with self.assertRaises(ValueError):
            self.decode(bytearray(body))
        for key in ('max_collection_items', 'max_total_items', 'max_payload_size'):
            for value in (True, -1, None, 2**32):
                with self.assertRaises(ValueError):
                    self.decode(body, **{key: value})

    def test_whole_native_packet_and_final_records_after_cleanup(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-quest-sync-11316.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'], CURRENT_SOURCE_SHA256)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 96)
        self.assertEqual([r['size'] for r in report['short']], list(range(172)))


if __name__ == '__main__':
    unittest.main()
