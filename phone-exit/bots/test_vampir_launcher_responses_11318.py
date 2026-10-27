"""Response shape compatibility preserves IAT identity and its explicit limitations."""
import importlib.util
from pathlib import Path
import unittest


class LauncherResponseTests(unittest.TestCase):
    def test_full_shapes_import_and_dispatch_references(self):
        path=Path(__file__).parent/'resource-tools/vampir/audit-launcher-responses-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_response_audit',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertFalse(result['network_used'])
        self.assertFalse(result['native_execution']);self.assertFalse(result['profile_activation'])
        self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual([p['instructions'] for p in result['pairs']],[551,762])
        self.assertEqual([p['dispatcher'] for p in result['pairs']],['0x1444e57f0','0x1444e6ac0'])
        for pair in result['pairs']:
            self.assertTrue(pair['shape_equal']);self.assertEqual(len(pair['imports']),2)
            for imported in pair['imports']:
                self.assertEqual(len(imported),1)
                self.assertEqual(imported[0]['identity']['name'],'_wtoi')
                self.assertEqual(imported[0]['identity']['dll'].lower(),'api-ms-win-crt-convert-l1-1-0.dll')
            self.assertEqual(pair['key_global_references'],['0x14b563da0','0x14b563df0'])


if __name__=='__main__':unittest.main()
