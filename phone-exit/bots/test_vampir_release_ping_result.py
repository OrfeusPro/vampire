"""Current whole ID17 reader and heartbeat receiver native evidence."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent


class ReleasePingResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run=subprocess.run([sys.executable,'-X','utf8',str(HERE/'resource-tools/vampir/replay-release-ping-result.py')],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=120)
        cls.report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_current_whole_reader_handler_receiver(self):
        r=self.report
        self.assertEqual(r['source_sha256'],'98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertTrue(r['native_execution']);self.assertFalse(r['network_used'])
        self.assertEqual(len(r['cases']),36)
        self.assertEqual({c['result_bits'] for c in r['cases']},{0,16,0xffffffff})
        self.assertEqual({c['value_bits'] for c in r['cases']},{0,2**64-1})
        self.assertTrue(all(c['outstanding_after']==0 and c['tracking_index_after']==0 for c in r['cases']))

    def test_elapsed_clock_and_recovery_flag(self):
        for c in self.report['cases']:
            self.assertEqual(c['elapsed'],25)
            self.assertEqual(c['recovery_calls'],int(bool(c['flags']&1024)))

    def test_short_inputs_do_not_reach_handler(self):
        self.assertEqual([c['size'] for c in self.report['short']],list(range(12)))
        self.assertTrue(all(c['consumed']<=c['size'] for c in self.report['short']))


if __name__=='__main__':unittest.main()
