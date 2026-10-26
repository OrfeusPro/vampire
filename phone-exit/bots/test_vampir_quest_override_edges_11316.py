"""Original duplicate/unmatched Russian rows through actual override control flow."""
import importlib.util
from pathlib import Path
import unittest


class QuestOverrideEdgesTests(unittest.TestCase):
    def test_duplicate_last_row_wins_and_missing_ids_do_not_insert(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_override_edges',root/'replay-quest-loader-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-override-edges-11316.json')
        self.assertTrue(target.is_file()); self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        forward,reverse=result['runs']
        for run in result['runs']:
            self.assertEqual(run['records'],8); self.assertEqual(run['group_count'],3)
            self.assertEqual(run['bytes_read'],1841); self.assertEqual(run['override_bytes_read'],663)
            self.assertEqual(run['missing_translation_ids'],['60000070024'])
            self.assertEqual(run['override_ids'].count('50000090011'),2)
            self.assertNotIn('110110010',run['task_ids'])
            self.assertEqual(run['callbacks']['missing_id_diagnostic'],1)
            self.assertEqual(run['callbacks']['task_name_store'],8)
            self.assertEqual(run['callbacks']['split_untranslated'],2)
            self.assertTrue(run['group_order_matches_records'])
        self.assertEqual(forward['russian_task_names'][-1],'2026-06-16 Registered')
        self.assertEqual(reverse['russian_task_names'][0],'2026-05-12 Registered')
        self.assertEqual(forward['russian_task_names'][-2],'')
        self.assertEqual(reverse['russian_task_names'][1],'')


if __name__=='__main__': unittest.main()
