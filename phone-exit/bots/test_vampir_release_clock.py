"""Actual current clock code: UTC epoch, signed server offset and cache separation."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseClockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        tool = root / 'phone-exit/bots/resource-tools/vampir/replay-release-clock.py'
        run = subprocess.run([sys.executable, '-X', 'utf8', str(tool)], cwd=root,
            capture_output=True, text=True, encoding='utf-8', check=True)
        cls.report = json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_epoch_and_utc_source(self):
        self.assertEqual(self.report['source_sha256'], '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(self.report['system_import']['name'], 'GetSystemTime')
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['cases']), 24)
        epoch = [c for c in self.report['cases'] if c['utc'] == '1970-01-01T00:00:00' and c['offset_minutes'] == 0]
        self.assertEqual(len(epoch), 2)
        for c in epoch:
            self.assertEqual(c['raw_ticks'], 0)
            self.assertEqual(c['ping_clock_ms'], 0)

    def test_reference_first_ping_and_signed_minutes(self):
        for c in self.report['cases']:
            self.assertEqual(c['raw_ticks'], (c['unix_ms']+c['offset_minutes']*60000)*10000)
            if c['utc'] == '2026-10-21T16:29:02.863000' and c['offset_minutes'] == 540:
                self.assertEqual(c['ping_clock_ms'], 1792632542863)
            self.assertEqual(c['system_time_calls'], 2)

    def test_local_and_server_samples_stay_separate(self):
        for c in self.report['cases']:
            self.assertEqual(c['local_ticks'], (c['unix_ms']+c['local_minutes']*60000)*10000)
            self.assertEqual(c['server_ticks'], (c['unix_ms']+12345)*10000)
        for utc in {c['utc'] for c in self.report['cases']}:
            for offset in (-720, 0, 540, 840):
                pair = [c for c in self.report['cases'] if c['utc'] == utc and c['offset_minutes'] == offset]
                self.assertEqual(len(pair), 2)
                self.assertEqual(pair[0]['raw_ticks'], pair[1]['raw_ticks'])


if __name__ == '__main__':
    unittest.main()
