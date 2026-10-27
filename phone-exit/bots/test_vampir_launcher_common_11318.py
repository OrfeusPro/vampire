"""Current common transport executes offline; HTTP and SDK boundaries stay explicit."""
import importlib.util
from pathlib import Path
import unittest


class LauncherCommonTests(unittest.TestCase):
    def test_header_initializers_and_complete_success_path(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-launcher-common-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_common_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertEqual(result['source_sha256'],module.SHA)
        self.assertTrue(result['native_execution']);self.assertFalse(result['network_used'])
        self.assertFalse(result['profile_activation']);self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(result['instructions'],997);self.assertEqual(len(result['exports']),2)
        self.assertEqual({k['name'] for k in result['header_keys']},
            {'Accept','Content-Type','gameCode','buildCode','accessToken','authToken'})
        self.assertEqual(len(result['cases']),4)
        for case in result['cases']:
            headers=[['header','Content-Type','application/json'],['header','Accept','application/json'],
                ['header','gameCode','fixture-game-code'],['header','buildCode','fixture-build-code']]
            if case['auth_present']:
                headers+=[['header','accessToken','fixture-auth'],['header','authToken','fixture-auth']]
            self.assertEqual(case['events'],['create','url']+headers+[['method','POST']]+
                (['body'] if case['body_present'] else [])+
                ['bind','send','holder-destroy','container-cleanup'])


if __name__=='__main__':unittest.main()
