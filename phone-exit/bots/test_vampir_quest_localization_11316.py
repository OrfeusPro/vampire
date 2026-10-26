"""Native localization decisions on Russian source labels and synthetic flags."""
from collections import Counter
import importlib.util
from pathlib import Path
import unittest


class QuestLocalizationTests(unittest.TestCase):
    def test_flags_untranslated_prefix_fallback_and_string_ownership(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-localization-11316.py'
        spec=importlib.util.spec_from_file_location('quest_localization',path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file()); self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertEqual(len(result['cases']),336)
        self.assertEqual(Counter(c['origin'] for c in result['cases']),dict(current_ru=96,lexical=240))
        self.assertEqual({c['reason'] for c in result['cases']},{'retained','untranslated_hidden','prefix_hidden','fallback'})
        source=[c for c in result['cases'] if c['origin']=='current_ru' and not c['untranslated']]
        self.assertEqual({c['result'] for c in source},{'Идите ко входу','Подойдите к связанному','Преследуйте врага'})
        self.assertTrue(all(c['result']=='Запасной текст' for c in result['cases'] if c['reason']=='fallback'))


if __name__=='__main__': unittest.main()
