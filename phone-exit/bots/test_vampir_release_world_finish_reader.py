"""Current whole ID206 reader, empty collections and actual heading math."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent


class ReleaseWorldFinishReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool=(HERE/'resource-tools/vampir/replay-release-world-finish-reader.py').resolve()
        run=subprocess.run([sys.executable,'-X','utf8',str(tool)],cwd=HERE.parents[1],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=120)
        cls.report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_current_whole_reader_and_constructor_execute_with_empty_arrays(self):
        self.assertEqual(self.report['source_sha256'],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(self.report['packet_id'],206)
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['cases']),18)
        self.assertEqual({c['fields']['0x10'] for c in self.report['cases']},{0,16,0xffffffff})
        self.assertTrue(all(c['text_matches'] for c in self.report['cases']))

    def test_all_short_prefixes_are_rejected_without_overconsumption(self):
        self.assertEqual([c['size'] for c in self.report['short']],list(range(81)))
        for case in self.report['short']:self.assertLessEqual(case['consumed'],case['size'])

    def test_all_heading_bytes_pass_through_current_native_math(self):
        self.assertEqual([c['wire'] for c in self.report['heading']],list(range(256)))
        self.assertEqual(set(self.report['math_imports']),{'atan2','fmod'})
        self.assertEqual({r['name'] for r in self.report['math_ranges']},
            {'ReleaseMath_GuardedRemainder','ReleaseMath_GuardedAtan2','ReleaseMath_SSE2SinCos'})


if __name__=='__main__':unittest.main()
