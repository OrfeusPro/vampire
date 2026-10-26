"""Native main/ru override loaders and localization transform in one bounded run."""
import importlib.util
from pathlib import Path
import unittest


class QuestLoaderOverrideTests(unittest.TestCase):
    def test_russian_names_apply_without_changing_param_or_task_order(self):
        root=Path(__file__).parent/'resource-tools/vampir'
        spec=importlib.util.spec_from_file_location('quest_loader_override',root/'replay-quest-loader-11316.py')
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run(root/'knowledge/native-contexts/quest-loader-override-11316.json')
        self.assertTrue(target.is_file()); self.assertTrue(result['native_override']); self.assertTrue(result['native_scalars'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['runs']),2)
        forward,reverse=result['runs']
        self.assertEqual(reverse['russian_task_names'],list(reversed(forward['russian_task_names'])))
        for run in result['runs']:
            self.assertEqual(run['records'],6); self.assertEqual(run['group_count'],1)
            self.assertEqual(run['bytes_read'],1220); self.assertEqual(run['override_bytes_read'],423)
            self.assertTrue(run['group_order_matches_records'])
            self.assertEqual(run['callbacks']['column'],19)
            self.assertEqual(run['callbacks']['untranslated'],6)
            self.assertEqual(run['callbacks']['task_name_store'],6)
            self.assertNotIn('override_fixture',run['callbacks'])
            self.assertEqual(run['scalar_import_calls'],dict(atoi=48,_atoi64=24,strtoul=12,pow=24))
        self.assertEqual(forward['russian_task_names'],['Идите ко входу']*3+['Подойдите к связанному']*2+['Преследуйте врага'])


if __name__=='__main__': unittest.main()
