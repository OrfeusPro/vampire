"""Derived environment getters must not be confused with base world-ID getter."""
import importlib.util
from pathlib import Path
import unittest


class DerivedEnvironmentTests(unittest.TestCase):
    def test_factory_virtual_bindings_and_record_projection(self):
        p=Path(__file__).parent/'resource-tools/vampir/replay-quest-derived-environment-11316.py'
        spec=importlib.util.spec_from_file_location('derived_environment_replay',p)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertTrue(result['native_execution'])
        self.assertFalse(result['network_used']);self.assertFalse(result['action_admitted'])
        self.assertEqual(result['source_sha256'],module.SHA)
        self.assertEqual(result['derived_vtable'],'0x149a3dac0')
        self.assertEqual(result['slots'],{'0xa8':'0x145db0150','0xb0':'0x1418af880',
            '0xb8':'0x145da1d40','0xc8':'0x145db5480'})
        self.assertTrue(result['allocation_failure_checked']);self.assertEqual(len(result['exports']),2)
        self.assertEqual(len(result['names']),10)
        self.assertEqual([n['result'] for n in result['names']],[False]*6+[True]*4)
        for row in result['names']:
            self.assertEqual(row['lookups'],[10012,10020])
            self.assertEqual(row['calls'].count('record-text'),2)
            self.assertEqual(row['calls'].count('copy-string'),2)
        self.assertEqual(len(result['kinds']),8)
        for row in result['kinds']:
            self.assertEqual(row['result'],row['record_field_0c'] if row['record_present'] else 0)
            self.assertEqual(row['world_id'],10012)
            self.assertNotEqual(row['result'],row['world_id'])


if __name__=='__main__':unittest.main()
