"""Source key identity and callback/transport references remain separate from auth readiness."""
import importlib.util
from pathlib import Path
import unittest


class LauncherReferenceTests(unittest.TestCase):
    def test_request_keys_and_callbacks(self):
        path=Path(__file__).parent/'resource-tools/vampir/audit-launcher-references-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_refs',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertFalse(result['network_used'])
        self.assertFalse(result['profile_activation']);self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(len(result['keys']),8)
        token,signin=result['requests']
        self.assertEqual(token['route'],'launcher/token');self.assertEqual(signin['route'],'launcher/sign-in')
        self.assertEqual(set(token['key_references']),{'nmDeviceKey','deviceKey','countryCode','os','gameCode','buildCode','credential'})
        self.assertEqual(set(signin['key_references']),{'nmDeviceKey','deviceKey','countryCode','os','launcherToken'})
        self.assertEqual(token['callback_target'],'0x1444cc4b0')
        self.assertEqual(signin['callback_target'],'0x1444d3a30')
        self.assertEqual([token['transport'],signin['transport']],['0x144522f90','0x144523110'])


if __name__=='__main__':unittest.main()
