"""Exact current client records and reproducible Russian runtime data."""
import importlib.util
from pathlib import Path
import unittest


class RussianQuestNamesTests(unittest.TestCase):
    def test_current_pak_and_native_key_binding_reproduce_catalog(self):
        path=Path(__file__).parent/'resource-tools/vampir/build-quest-names-ru-11316.py'
        spec=importlib.util.spec_from_file_location('quest_names_ru_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,report=module.run()
        self.assertFalse(report['network_used'])
        self.assertEqual(report['source_sha256'],module.SHA)
        self.assertEqual(report['installed_archive']['sha256'],module.PAK)
        self.assertEqual(report['names'],1341)
        self.assertEqual(report['names']+len(report['skipped']),report['tables']['Quest']['rows'])
        self.assertEqual(len(report['ambiguous_name_ids']),12)
        self.assertNotIn('110120',[r['id'] for r in report['skipped']])
        self.assertEqual(report['tables']['QuestNamesRu']['entry'],2355)
        self.assertEqual(len(report['exports']),2)
        self.assertTrue(saved.is_file())


if __name__=='__main__':unittest.main()
