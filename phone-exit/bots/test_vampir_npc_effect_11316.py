"""Whole current NPC effect reader; every prefix, no authorization or game commands."""
import importlib.util
from pathlib import Path
import unittest


class NpcEffectTests(unittest.TestCase):
    def test_whole_native_effect_and_optional_vector(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-npc-effect-11316.py'
        spec=importlib.util.spec_from_file_location('npc_effect_replay_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.verify()['cases'],7656)


if __name__=='__main__':unittest.main()
