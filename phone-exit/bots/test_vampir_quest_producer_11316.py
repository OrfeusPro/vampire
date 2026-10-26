"""Static source-bound producer validation, no network or game actions."""
import importlib.util
import json
from pathlib import Path
import unittest


class QuestProducerTests(unittest.TestCase):
    def test_named_inputs_and_current_sender_are_bound_to_full_source(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-quest-update-producer-11316.py'
        spec=importlib.util.spec_from_file_location('quest_producer_static',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,report=module.run()
        self.assertEqual(report['source_sha256'],module.SHA)
        self.assertFalse(report['network_used'])
        self.assertEqual(report['named_fields'],{'0x28':'TargetId','0x30':'QuestInfoId','0x38':'QuestTaskIndex'})
        self.assertEqual({f['address'] for f in report['functions']},{'0x145d85360','0x145d6f9b0','0x145837030'})
        self.assertEqual(report['packet']['id'],1810)
        self.assertEqual(json.loads(saved.read_text('utf-8'))['named_fields'],report['named_fields'])


if __name__=='__main__':unittest.main()
