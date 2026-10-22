"""Source-bound ID 1801 body and whole native codecs, no game IO."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.quest_request import encode_quest_list_read
from vampir_core.world_move_start import SOURCE_SHA256


class QuestRequestTests(unittest.TestCase):
    def test_exact_body_source_and_types(self):
        self.assertEqual(encode_quest_list_read(0, 0, source_sha256=SOURCE_SHA256), bytes(9))
        self.assertEqual(encode_quest_list_read(255, 0xffffffffffffffff, source_sha256=SOURCE_SHA256),
                         struct.pack('<BQ', 255, 0xffffffffffffffff))
        for kind, value in ((True, 0), (-1, 0), (256, 0), (0, True), (0, -1),
                             (0, 1 << 64), (None, 0), (0, 1.0)):
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                encode_quest_list_read(kind, value, source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError): encode_quest_list_read(0, 0, source_sha256='old')

    def test_whole_native_writer_reader_and_failures(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-quest-request.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 32)
        self.assertEqual([r['widths'] for r in report['failures']], [[1], [1, 8]])
        self.assertEqual([r['size'] for r in report['short']], list(range(9)))


if __name__ == '__main__': unittest.main()
