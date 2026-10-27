"""Full source shape comparison preserves native ranges and local edges."""
import importlib.util
from pathlib import Path
import unittest


class LauncherShapeTests(unittest.TestCase):
    def test_complete_functions_and_routes(self):
        path = Path(__file__).parent/'resource-tools/vampir/audit-launcher-shape-11318.py'
        spec = importlib.util.spec_from_file_location('launcher_shape', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        artifact, result = module.run()
        self.assertTrue(artifact.is_file())
        self.assertFalse(result['network_used']); self.assertFalse(result['profile_activation'])
        self.assertEqual(result['compatibility'], 'not_established')
        self.assertEqual([(p['route'],p['instructions']) for p in result['pairs']],
            [('launcher/token',652),('launcher/sign-in',679)])
        for pair in result['pairs']:
            self.assertTrue(pair['equal_shape'])
            self.assertTrue(pair['external_calls']); self.assertTrue(pair['data_references'])
            self.assertEqual(len(pair['route_references']),2)
            self.assertTrue(any(p['old']['target']!=p['current']['target'] for p in pair['external_calls']))


if __name__=='__main__':unittest.main()
