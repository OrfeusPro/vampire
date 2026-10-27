"""Current result getters preserve root/type gates and conversion boundaries."""
import importlib.util
from pathlib import Path
import unittest


class LauncherResultGetterTests(unittest.TestCase):
    def test_root_type_lookup_and_conversion_paths(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-launcher-result-getters-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_getter_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertEqual(result['source_sha256'],module.SHA)
        self.assertTrue(result['native_execution']);self.assertFalse(result['network_used'])
        self.assertFalse(result['profile_activation']);self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(result['keys'],['errorCode','resultData']);self.assertEqual(len(result['coverage']),7)
        self.assertEqual(len(result['exports']),2);self.assertEqual(len(result['cases']),120)
        for case in result['cases']:
            expected=[]
            if case['gate'] not in ('null-root','wrong-root-type'):expected+=['get-object']
            if case['gate']=='ready':expected+=['lookup']
            if case['kind']=='string' and case['gate']=='ready' and case['found']:
                if case['field_type']==2:expected+=['string']
                if case['field_type']==3:expected+=['number-string']
            self.assertEqual(case['events'],expected)
        self.assertEqual(len(result['conversions']),12)
        for case in result['conversions']:
            expected=['string'] if case['field_type']==2 else []
            if case['field_type']==3:
                expected=['number-string']+([] if case['numeric_string'] else ['free-partial','format-number'])
            self.assertEqual(case['events'],expected)


if __name__=='__main__':unittest.main()
