"""SDK sign-in body/header evidence and offline plan, no authentication POST."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.gmc2_response import decode_gmc2_configuration
from vampir_core.nid_sdk_credential import NidSdkCredential
from vampir_core.sdk_sign_in import plan_nid_sdk_sign_in
from vampir_core.sdk_config import append_sdk_path


class SdkSignInTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('sdk_sign_in_test',HERE/'resource-tools/vampir/replay-sdk-sign-in-body.py')
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.config.native.ROOT/'code-clues/sdk-sign-in-body-replay.json').read_text('utf-8'))

    def plan(self,**changes):
        args=dict(constants={'authUrl':'https://auth.example.invalid/base'},credential=NidSdkCredential('provider-token-fixture'),
            game_code='thered',build_code=0,nm_device_key='nm-fixture',device_key='device-fixture',country_code='UA',os_type='pc')
        args.update(changes)
        return plan_nid_sdk_sign_in(**args)

    def test_reproduce_body_and_auth_constructor_factory_chain(self):
        self.assertEqual(self.tool.build(),self.report)
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x14451111f]['operands'],'rcx, [rdi + 0x150]')
        self.assertEqual(rows[0x144511126]['direct_target'],0x1444bc1d0)
        self.assertEqual(rows[0x1444bc21b]['direct_target'],0x1444bc380)
        self.assertEqual(rows[0x1444fb79e]['direct_target'],0x1444fb800)
        self.assertTrue(any(r['text']=='playerId' for r in self.report['constructor_literals']))
        leaf=self.report['constructor_leaf'];data=bytes.fromhex(leaf['bytes'])
        self.assertEqual(raw[leaf['file_offset']:leaf['file_offset']+len(data)],data)
        self.assertFalse(self.report['network_ready'])

    def test_complete_email_json_object_matches_native_caller_pairs(self):
        self.assertEqual(len(self.report['cases']),4)
        for case in self.report['cases']:
            fixture=case['fixture']
            self.assertEqual(case['optional_key'],'playerId')
            if fixture['credential'] is None:
                self.assertNotIn('credential',case['body'])
                continue  # Anonymous/no-credential branch is outside this email-only planner.
            plan=self.plan(player_id=fixture['playerId'])
            self.assertEqual(json.loads(plan.body),case['body'])
            self.assertEqual(plan.url,'https://auth.example.invalid/base/v1/sign-in')
            self.assertNotIn('provider-token',repr(plan))
        self.assertEqual(json.loads(self.plan().body)['credential']['channelCode'],33)

    def test_post_headers_and_build_selection_match_native_slices(self):
        self.assertEqual(len(self.report['headers']),8)
        for case in self.report['headers']:
            plan=self.plan(build_code=case['build_byte'],existing_sdk_token=case['account_field_78'])
            self.assertEqual([dict(name=k,value=v) for k,v in plan.headers],case['headers'])
            self.assertEqual(plan.method,case['method'])
        self.assertNotIn('accessToken',dict(self.plan().headers))
        self.assertNotIn('authToken',dict(self.plan().headers))

    def test_real_public_config_binding_and_strict_local_input_policy(self):
        identity='b18141355f468fda8e654da37927f9323bf59ee5018f1fd00b1326eed6aae1f1'
        folder=self.tool.config.native.ROOT/'public-gmc2-snapshots'/identity
        raw=(folder/'manifest.json').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),identity)
        manifest=json.loads(raw);body=(folder/'body.bin').read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(),manifest['body_sha256'])
        config=decode_gmc2_configuration(body,manifest['transport']['headers'])
        plan=self.plan(constants=dict(config.constants))
        self.assertEqual(plan.url,append_sdk_path(config.constants['authUrl'],'v1/sign-in'))
        invalid=[dict(build_code=True),dict(build_code=256),dict(device_key=''),dict(os_type=''),
            dict(nm_device_key=''),dict(country_code='ua'),dict(player_id='x\nprivate'),
            dict(credential=NidSdkCredential('bad\0private')),dict(existing_sdk_token='x'*8193),
            dict(constants={}),dict(constants={'authUrl':'http://auth.invalid'}),
            dict(constants={'authUrl':'https://user:secret@auth.invalid'}),
            dict(constants={'authUrl':'https://auth.invalid:0'}),dict(constants={'authUrl':'https://auth.invalid?q=x'})]
        for changes in invalid:
            with self.assertRaises(ValueError) as error:self.plan(**changes)
            self.assertNotIn('private',str(error.exception));self.assertNotIn('secret',str(error.exception))


if __name__=='__main__':unittest.main()
