"""Named current PAK localization join and source-bound native override fields."""
import importlib.util
from pathlib import Path
import unittest


class QuestOverrideDataTests(unittest.TestCase):
    def test_russian_catalog_and_optional_param_are_explicit(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-quest-override-data-11316.py'
        spec=importlib.util.spec_from_file_location('quest_override_data',path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file()); self.assertFalse(result['native_execution'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(result['presentation_locale'],'ru')
        self.assertEqual(len(result['records']),16)
        self.assertTrue(all(not r['param_column_present'] for r in result['records']))
        ru=next(r for r in result['records'] if r['locale']=='ru')
        self.assertEqual((ru['rows'],ru['matched_base_ids'],ru['absent_base_ids'],ru['missing_base_ids'],ru['duplicate_ids']),
                         (8461,5943,2470,1,48))
        self.assertEqual(ru['selected_tasks'][0]['task_name'],'Идите ко входу')
        self.assertEqual(ru['selected_tasks'][3]['task_name'],'Подойдите к связанному')
        catalog=result['russian_catalog']
        self.assertFalse(catalog['runtime_admitted'])
        self.assertEqual(len(catalog['names'])+len(catalog['duplicate_rows'])+len(catalog['missing_ids']),5944)
        self.assertTrue(set(catalog['names']).isdisjoint(catalog['duplicate_rows']))
        self.assertEqual(catalog['names']['110120070']['task_name'],'Преследуйте врага')


if __name__=='__main__': unittest.main()
