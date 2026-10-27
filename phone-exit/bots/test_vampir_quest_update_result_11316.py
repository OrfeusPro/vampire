"""Current QuestUpdateResult native wire; no gameplay confirmation semantics."""
import importlib.util
from pathlib import Path
import unittest

class QuestUpdateResultTests(unittest.TestCase):
    def test_outer_nested_wire_clamp_short_inputs_and_operation_failures(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_update_result',root/'replay-quest-update-result-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file());self.assertFalse(result['network_used']);self.assertFalse(result['action_confirmation_admitted'])
        self.assertEqual((result['packet_id'],result['wire_bytes'],result['wire_format']),(1811,30,'<IQBBQQ'))
        self.assertEqual(len(result['cases']),900);self.assertEqual(len(result['truncated']),30);self.assertEqual(len(result['failures']),12)
        for c in result['cases']:
            expected=c['input'].copy();expected[2]=min(expected[2],6)
            self.assertEqual(c['decoded'],expected)
        self.assertEqual([c['bytes'] for c in result['truncated']],list(range(30)))
        self.assertEqual({(c['mode'],c['failed_primitive']) for c in result['failures']},{(mode,i) for mode in ('read','write') for i in range(1,7)})

if __name__=='__main__':unittest.main()
