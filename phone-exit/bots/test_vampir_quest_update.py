"""ID 1810 shape, strict public codec and whole native replay; no game IO."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.quest_update import QuestUpdate, encode_quest_update, decode_quest_update
from vampir_core.world_move_start import SOURCE_SHA256


class QuestUpdateTests(unittest.TestCase):
    def test_exact_wire_and_signed_zero(self):
        value = QuestUpdate((-0.0, 1.5, -2.25), 1 << 63, (1 << 64) - 1, 255)
        body = encode_quest_update(value, source_sha256=SOURCE_SHA256)
        self.assertEqual(body, struct.pack('<fffQQB', *value.vector, value.raw28, value.raw30, value.raw38))
        self.assertEqual(len(body), 29)
        parsed = decode_quest_update(body, source_sha256=SOURCE_SHA256)
        self.assertEqual(encode_quest_update(parsed, source_sha256=SOURCE_SHA256), body)
        self.assertEqual(struct.pack('<f', parsed.vector[0]), b'\0\0\0\x80')
        self.assertNotIn(str(value.raw28), repr(parsed))

    def test_source_types_ranges_and_nonfinite(self):
        for vector, a, b, flag in [((True, 0., 0.), 0, 0, 0), ((float('nan'), 0., 0.), 0, 0, 0),
                ((float('inf'), 0., 0.), 0, 0, 0), ((1e300, 0., 0.), 0, 0, 0),
                ((1 << 4096, 0., 0.), 0, 0, 0), ((0.,), 0, 0, 0), ([0., 0., 0.], 0, 0, 0),
                ((0., 0., 0.), True, 0, 0), ((0., 0., 0.), -1, 0, 0),
                ((0., 0., 0.), 0, 1 << 64, 0), ((0., 0., 0.), 0, 0, True),
                ((0., 0., 0.), 0, 0, 256)]:
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                encode_quest_update(QuestUpdate(vector, a, b, flag), source_sha256=SOURCE_SHA256)
        value = QuestUpdate((0., 0., 0.), 0, 0, 0)
        with self.assertRaises(ValueError):
            encode_quest_update(value, source_sha256='old')
        with self.assertRaises(ValueError):
            decode_quest_update(bytes(29), source_sha256='old')
        with self.assertRaises(TypeError):
            encode_quest_update(None, source_sha256=SOURCE_SHA256)
        for size in list(range(29)) + [30]:
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_quest_update(bytes(size), source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):
            decode_quest_update(struct.pack('<fffQQB', float('nan'), 0., 0., 0, 0, 0), source_sha256=SOURCE_SHA256)

    def test_whole_native_writer_reader_and_failure_boundaries(self):
        result = subprocess.run([sys.executable, '-X', 'utf8', str(
            HERE / 'resource-tools/vampir/replay-release-quest-update.py')],
            check=True, capture_output=True, text=True, encoding='utf-8', timeout=120)
        report = json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']), 48)
        self.assertEqual([r['widths'] for r in report['writer_failures']],
            [[4, 4, 4, 8, 8, 1][:n] for n in range(1, 7)])
        self.assertEqual([r['size'] for r in report['short_prefixes']], list(range(29)))


if __name__ == '__main__':
    unittest.main()
