"""Current whole caller captures agree with the portable planner on supported inputs."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.nid_sdk_credential import NidSdkCredential
from vampir_core.sdk_launcher_auth import LauncherToken,plan_nid_launcher_token,plan_launcher_sign_in


class LauncherCallerFieldTests(unittest.TestCase):
    def test_native_fields_build_codes_and_portable_policy(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-launcher-caller-fields-11318.py'
        spec=importlib.util.spec_from_file_location('launcher_caller_replay',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        artifact,result=module.run()
        self.assertTrue(artifact.is_file());self.assertEqual(result['source_sha256'],module.SHA)
        self.assertTrue(result['native_execution']);self.assertFalse(result['network_used'])
        self.assertFalse(result['profile_activation']);self.assertEqual(result['compatibility'],'not_established')
        self.assertEqual(len(result['coverage']),14);self.assertEqual(len(result['exports']),4)
        self.assertEqual(result['coverage']['0x1444eecd0'],652)
        self.assertEqual(result['coverage']['0x144503e10'],679)
        self.assertEqual(result['copy_import']['name'],'memcpy')
        self.assertEqual(result['copy_import']['dll'].lower(),'vcruntime140.dll')
        self.assertEqual(len(result['build_cases']),256)
        self.assertEqual([c['value'] for c in result['build_cases']],['A','B','C']+['A']*253)
        matched=rejected=0
        self.assertEqual(len(result['cases']),8)
        for case in result['cases']:
            f=case['fixture'];self.assertEqual(case['serializer_mode'],1)
            args=dict(constants={'authUrl':'https://offline.invalid/'},game_code=f['gameCode'],
                build_code=f['buildByte'],nm_device_key=f['nmDeviceKey'],device_key=f['deviceKey'],
                country_code=f['countryCode'],os_type=f['os'])
            if case['kind']=='token':
                credential=NidSdkCredential(f['credentialObject'].get('channelAccessToken','fixture-provider-B'))
                args['credential']=credential if case['credential_present'] else None
                planner=plan_nid_launcher_token
                expected_headers={}
            else:
                token=case['headers']['launcherToken'];args['launcher_token']=LauncherToken(token)
                planner=plan_launcher_sign_in;expected_headers={'launcherToken':token}
            allowed=f['countryCode']=='UA' and case['credential_present'] and (
                case['kind']=='token' or not case['launcher_token_empty'])
            if not allowed:
                with self.assertRaises(ValueError):planner(**args)
                rejected+=1;continue
            plan=planner(**args);matched+=1
            self.assertEqual(plan.url,case['url']);self.assertEqual(plan.method,'POST')
            self.assertEqual(json.loads(plan.body),case['body'])
            self.assertEqual({k:v for k,v in plan.headers if k=='launcherToken'},expected_headers)
            self.assertEqual(dict(plan.headers)['buildCode'],f['buildCode'])
        self.assertEqual((matched,rejected),(2,6))


if __name__=='__main__':unittest.main()
