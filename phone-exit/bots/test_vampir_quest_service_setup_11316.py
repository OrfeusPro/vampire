"""Service setter dirty/ready flags and region lookup/fallback paths."""
import importlib.util
from pathlib import Path
import unittest


class QuestServiceSetupTests(unittest.TestCase):
    def test_lookup_fallback_change_flags_and_selected_server_binding(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-quest-service-setup-11316.py'
        spec=importlib.util.spec_from_file_location('quest_service_setup',path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        target,result=module.run()
        self.assertTrue(target.is_file()); self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']); self.assertFalse(result['order_admitted'])
        self.assertFalse(result['active_region_verified'])
        self.assertEqual(len(result['cases']),144)
        self.assertEqual(sum(c['lookup_found'] for c in result['cases']),72)
        self.assertTrue(all(c['dirty']==int(bool(c['initial_dirty'] or not c['same_region'] or not c['same_server'])) for c in result['cases']))


if __name__=='__main__': unittest.main()
