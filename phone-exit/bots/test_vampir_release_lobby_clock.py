"""Execute the current registered lobby packet reader and clock handler."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseLobbyClockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        tool = root / 'phone-exit/bots/resource-tools/vampir/replay-release-lobby-clock.py'
        run = subprocess.run([sys.executable, '-X', 'utf8', str(tool)], cwd=root,
            capture_output=True, text=True, encoding='utf-8', check=True)
        cls.report = json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_actual_registration_pair(self):
        self.assertEqual(self.report['source_sha256'],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(self.report['registration_key'], 2)
        self.assertEqual(self.report['packet_name'], 'PktLobbyVersionResult')
        self.assertEqual(self.report['handler_tail_target'], '0x145d5e440')
        self.assertFalse(self.report['network_used'])

    def test_reader_to_signed_clock_offset(self):
        cases = self.report['cases']
        self.assertEqual(len(cases), 18)
        self.assertEqual({c['offset_minutes'] for c in cases}, {-180, 0, 540})
        self.assertEqual({c['raw_flag'] for c in cases}, {0, 1, 255})
        self.assertEqual({c['first_bits'] for c in cases}, {0, 2000})
        for case in cases:
            self.assertEqual(case['offset_ticks'], case['offset_minutes'] * 600000000)
            self.assertEqual(case['server_ticks'], case['server_sample'] * 10000)

    def test_short_input_is_rejected(self):
        self.assertEqual(self.report['prefix_cases'],
            [dict(size=n, accepted=n == 23) for n in range(24)])


if __name__ == '__main__':
    unittest.main()
