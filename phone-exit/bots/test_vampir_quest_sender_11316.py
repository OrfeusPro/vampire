"""Whole synthetic model sender; no credentials, game process or sockets."""
import importlib.util
from pathlib import Path
import unittest


class QuestSenderTests(unittest.TestCase):
    def test_whole_sender_and_collision_lookup(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-sender-11316.py'
        spec=importlib.util.spec_from_file_location('quest_sender_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,report=module.run()
        self.assertTrue(report['native_execution']);self.assertFalse(report['network_used'])
        self.assertEqual(len(report['cases']),640)
        self.assertEqual(sum(c['sent'] for c in report['cases']),160)
        self.assertEqual({c['lookup'] for c in report['cases'] if c['sent']},{'found'})
        self.assertEqual({c['position'] for c in report['cases']},{'current','no_component','no_actor','no_manager'})
        self.assertEqual({c['storage'] for c in report['cases']},{'inline','external'})
        self.assertEqual(len(report['exports']),2)
        self.assertTrue(saved.is_file())


if __name__=='__main__':unittest.main()
