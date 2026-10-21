"""Native current ID205 request policy with explicit engine fixtures, no IO."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent


class ReleaseWorldFinishRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool=(HERE/'resource-tools/vampir/replay-release-world-finish-request.py').resolve()
        run=subprocess.run([sys.executable,'-X','utf8',str(tool)],cwd=HERE.parents[1],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=60)
        cls.report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_current_source_and_explicit_execution_scope(self):
        self.assertEqual(self.report['source_sha256'],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_used'])
        self.assertEqual(self.report['packet_id'],205)
        self.assertEqual(len(self.report['cases']),48)
        self.assertEqual(self.report['start_binding']['packet_id'],204)
        self.assertEqual(self.report['start_binding']['receiver'],'0x145dae5a0')

    def test_only_states_two_three_four_reach_the_send_boundary(self):
        for case in self.report['cases']:
            expected=not case['relocating'] and case['status'] in (2,3,4)
            self.assertEqual(case['accepted'],expected)
            sent=[e for e in case['events'] if e['action']=='send_boundary_fixture']
            self.assertEqual(sent,[dict(action='send_boundary_fixture',packet_id=205,body_size=0)] if expected else [])
            self.assertEqual(case['state_after'],5 if expected else case['status'])
            self.assertEqual(case['timer_active'],int(expected))
            self.assertEqual(case['timer_field150'],0 if expected else 0x12345678)

    def test_relocation_branch_requests_load_without_sending_or_claiming_ready(self):
        for case in self.report['cases']:
            loads=[e for e in case['events'] if e['action']=='load_fixture']
            self.assertEqual(loads,[dict(action='load_fixture',target=41)] if case['relocating'] else [])
            if case['accepted']:
                self.assertEqual(case['delay'],max(float(case['interval']),self.report['minimum_interval']))


if __name__=='__main__':unittest.main()
