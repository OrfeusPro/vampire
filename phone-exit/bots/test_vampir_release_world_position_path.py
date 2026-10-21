"""Current callback and actor-position forwarding with explicit engine fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).parent


class ReleaseWorldPositionPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool=(HERE/'resource-tools/vampir/replay-release-world-position-path.py').resolve()
        run=subprocess.run([sys.executable,'-X','utf8',str(tool)],cwd=HERE.parents[1],
            capture_output=True,text=True,encoding='utf-8',check=True,timeout=60)
        cls.report=json.loads(Path(json.loads(run.stdout)['report']).read_text('utf-8'))

    def test_current_source_and_explicit_native_scope(self):
        self.assertEqual(self.report['source_sha256'],
            '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['network_used'])
        self.assertEqual(len(self.report['callback_cases']),8)
        self.assertEqual(len(self.report['move_cases']),36)
        self.assertEqual([row['text'] for row in self.report['class_literals']],
            ['NnWaitingForWorldPartitionStreamingActor','NnCharacterPC'])
        self.assertEqual(self.report['finish_packet_id'],206)
        self.assertEqual([row['reader'] for row in self.report['nested_finish_bindings']],
            ['0x1458233c0','0x145788d00'])

    def test_callback_world_branch_sets_four_before_waiting_for_streaming_actor(self):
        for case in self.report['callback_cases']:
            actions=[e['action'] for e in case['events']]
            if case['has_world']:
                self.assertEqual(case['state_after'],4)
                self.assertEqual(actions,['state_setter_fixture','streaming_actor_lookup_fixture'])
            else:
                self.assertEqual(case['state_after'],case['initial_state'])
                self.assertEqual(actions,['finish_slot_fixture'])

    def test_target_position_reaches_component_as_delta_with_flags_preserved(self):
        for case in self.report['move_cases']:
            event=case['event']
            self.assertEqual(event['delta'],[b-a for a,b in zip(case['current'],case['target'])])
            self.assertIn(event['teleport'],(0,1,2))
            self.assertIn(event['sweep'],(0,1))
            self.assertEqual((event['hit_result'],event['move_flags']),(0,0))
            self.assertIn(case['returned'],(0,1))


if __name__=='__main__':unittest.main()
