"""Registered ID204 handler feeds the actual environment/readiness native chain."""
import importlib.util
from pathlib import Path
import unittest


class QuestWorldHandlerTests(unittest.TestCase):
    def test_handler_gate_receiver_and_refusal_footprint(self):
        p=Path(__file__).parent/'resource-tools/vampir/replay-quest-environment-update-11316.py'
        spec=importlib.util.spec_from_file_location('quest_world_handler_replay',p)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run('quest-environment-world-handler-11316.json')
        self.assertTrue(artifact.is_file());self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['action_admitted'])
        binding=result['handler_binding'];self.assertEqual(binding['packet_id'],204)
        self.assertTrue(binding['handler_ranges_and_gate_code_prefix_checked'])
        self.assertEqual(binding['handler_slots'][-1],'0x1467ca790')
        self.assertEqual(binding['accepted_receiver_cases'],48)
        self.assertEqual(len(result['receiver_cases']),48);self.assertEqual(len(binding['rejected']),5)
        for case in result['receiver_cases']:
            self.assertEqual(case['pending_at_writer'],case['requested'])
            self.assertEqual(case['actual'],case['requested'] if case['guard']=='allow' else case['old'])
            self.assertEqual(case['phase_after'],3)
            self.assertEqual(case['ready_after'],case['guard']=='allow' or case['old']==case['requested'])
        for case in binding['rejected']:
            expected=['diagnostic-format','diagnostic']+([] if case['special'] else ['error'])+['rejected-tail']
            self.assertEqual(case['events'],expected)


if __name__=='__main__':unittest.main()
