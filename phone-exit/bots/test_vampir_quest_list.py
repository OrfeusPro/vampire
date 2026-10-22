"""Bounded complete list parsing and whole native parity, without network."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.quest_list import decode_quest_list_result
from vampir_core.world_move_start import SOURCE_SHA256


def fixture(*, populated=False):
    if not populated:
        return struct.pack('<IBHHBBHQ', 0, 0, 0, 0, 0, 0, 0, 7)
    quest = struct.pack('<QBBQQBIII', 11, 255, 255, 22, 33, 255, 44, 55, 66)
    return (struct.pack('<IBH', 9, 255, 1) + quest + struct.pack('<HBQQ', 1, 255, 77, 88)
        + b'\xff\0' + struct.pack('<HBH', 1, 255, 2) + quest * 2 + struct.pack('<Q', 99))


def decode(body, **limits):
    return decode_quest_list_result(body, source_sha256=SOURCE_SHA256,
        **({'max_collection_items': 8, 'max_total_items': 64, 'max_payload_size': 8192} | limits))


class QuestListTests(unittest.TestCase):
    def test_empty_and_nested_fields(self):
        result = decode(fixture())
        self.assertEqual((result.code, result.raw14, result.quests, result.assets,
            result.data.groups, result.data.raw18), (0, 0, (), (), (), 7))
        result = decode(fixture(populated=True))
        self.assertEqual((result.code, result.raw14, result.raw38, result.raw39), (9, 12, True, False))
        self.assertEqual((len(result.quests), len(result.assets), len(result.data.groups)), (1, 1, 1))
        self.assertEqual(result.quests[0].raw10, 6)
        self.assertEqual(result.quests[0].progress.raw08, 255)
        self.assertEqual((result.assets[0].raw08, result.assets[0].raw10), (97, 77))
        self.assertEqual((result.data.groups[0].raw08, len(result.data.groups[0].quests)), (12, 2))
        self.assertEqual(result.data.groups[0].quests, result.quests * 2)
        self.assertEqual(result.data.raw18, 99)
        self.assertNotIn('99', repr(result))

    def test_every_short_prefix_and_trailing_bytes(self):
        body = fixture(populated=True)
        for size in range(len(body)):
            with self.subTest(size=size), self.assertRaises(ValueError): decode(body[:size])
        for invalid in (body + b'\0', bytearray(body), None):
            with self.assertRaises(ValueError): decode(invalid)

    def test_nested_total_and_individual_budgets(self):
        body = fixture(populated=True)
        # One top quest, one asset, one group and two nested quests = five.
        with self.assertRaises(BufferError): decode(body, max_total_items=4)
        self.assertEqual(len(decode(body, max_total_items=5).data.groups), 1)
        with self.assertRaises(BufferError): decode(body, max_collection_items=1)
        with self.assertRaises(BufferError): decode(body, max_payload_size=len(body) - 1)
        self.assertEqual(decode(fixture(), max_collection_items=0, max_total_items=0).code, 0)
        # A declared huge count is rejected before any item allocation / read.
        with self.assertRaises(BufferError): decode(struct.pack('<IBH', 0, 0, 65535))
        for name in ('max_total_items', 'max_collection_items', 'max_payload_size'):
            for value in (True, -1, 0x1000000, None):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    decode(body, **{name: value})
        with self.assertRaises(ValueError):
            decode_quest_list_result(body, source_sha256='old', max_collection_items=8,
                max_total_items=64, max_payload_size=8192)

    def test_whole_native_list_and_nested_callbacks(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-quest-list.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 243)
        self.assertEqual([case['size'] for case in report['short']], list(range(295)))


if __name__ == '__main__': unittest.main()
