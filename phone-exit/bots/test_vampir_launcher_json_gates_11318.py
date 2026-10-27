"""Whole native JSON gates and sparse traversal retain explicit writer boundaries."""
import importlib.util
from pathlib import Path
import unittest


class LauncherJsonGateTests(unittest.TestCase):
    def test_sparse_fields_and_serialization_failure_cleanup(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-launcher-json-gates-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_json_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertEqual(result['source_sha256'],module.SHA)
        self.assertTrue(result['native_execution']);self.assertFalse(result['network_used'])
        self.assertFalse(result['profile_activation']);self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(result['coverage'],{'0x144474430':195,'0x144489150':33,
            '0x14142e6f0':42,'0x144492b40':304})
        self.assertEqual([t['captured'] for t in result['traversals']],
            [[],[0,1,2],[0,2,31],[31,32,65],[0,127,128,129]])
        self.assertTrue(result['traversals'][-1]['external_bits'])
        self.assertEqual(len(result['cases']),18)
        for case in result['cases']:
            gate=case['gate'];expected=[]
            if gate not in ('null-value','wrong-type'):expected+=['get-object']
            if gate in ('writer-false','opening-false','closing-false','success'):
                expected+=['writer-factory','wrap-object','writer-'+str(case['mode'])]
                if gate!='writer-false':expected+=['postprocess','postprocess','opening']
                if gate in ('closing-false','success'):expected+=['closing']
                if gate!='success':expected+=['free-output']
            self.assertEqual(case['events'],expected)
            self.assertEqual(case['success'],gate=='success')


if __name__=='__main__':unittest.main()
