"""Current EXE/export binding only; not native execution or a game action test."""
import importlib.util
import json
from pathlib import Path
import unittest


class QuestModelBindingTests(unittest.TestCase):
    def test_model_writers_vtable_and_state_route_match_current_source(self):
        path=Path(__file__).parent/'resource-tools/vampir/inspect-quest-model-singleton-11316.py'
        spec=importlib.util.spec_from_file_location('quest_model_binding',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        saved,result=module.run()
        self.assertEqual(result['source_sha256'],module.SOURCE)
        self.assertFalse(result['network_used'])
        writes=[r for r in result['references'] if r.get('access')=='write']
        self.assertEqual({r['root'] for r in writes},{'0x1455ab3c0','0x1455ac490','0x1455b2ce0'})
        self.assertTrue(all(r['boundary']=='whole_unwind_fragment' for r in writes))
        self.assertEqual(result['binding']['virtual_48'],'0x1455b4d40')
        self.assertEqual(result['binding']['apply_progress'],'0x1455fd350')
        self.assertEqual(result['binding']['state_byte_offset'],'0x28')
        self.assertEqual(sum(len(e['roots']) for e in result['exports']),6)
        self.assertEqual(json.loads(saved.read_text('utf-8'))['binding'],result['binding'])


if __name__=='__main__':unittest.main()
