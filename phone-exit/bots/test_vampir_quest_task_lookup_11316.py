"""Current native task map lookup chained with whole progress projection."""
import importlib.util
from pathlib import Path
import unittest


class QuestTaskLookupTests(unittest.TestCase):
    def test_native_lookup_collision_and_array_value_projection(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-progress-11316.py'
        spec=importlib.util.spec_from_file_location('task_lookup_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,report=module.run(native_lookup=True)
        self.assertTrue(saved.is_file())
        self.assertTrue(report['native_lookup'])
        self.assertFalse(report['network_used'])
        self.assertEqual(len(report['exports']),2)
        self.assertEqual(len(report['cases']),324)
        self.assertEqual({c['lookup_storage'] for c in report['cases']},{'inline','external'})
        self.assertTrue(any(c['index']==255 and c['found'] for c in report['cases']))


if __name__=='__main__':unittest.main()
