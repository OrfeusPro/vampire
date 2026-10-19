"""Native provider-to-SDK credential channel distinction and payload evidence."""
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.nid_result import NidEmailCredential, parse_nid_email_callback
from vampir_core.nid_sdk_credential import build_nid_sdk_credential


class NidCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('nid_credential_test',HERE/'resource-tools/vampir/replay-nid-credential-adoption.py')
        cls.tool=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.config.native.ROOT/'code-clues/nid-credential-adoption-replay.json').read_text('utf-8'))

    def test_native_continuation_reproduces_with_source_vtable_and_literals(self):
        self.assertEqual(self.tool.build(),self.report)
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for row in [self.report['vtable'],*self.report['literals']]:
            data=bytes.fromhex(row['bytes'])
            self.assertEqual(raw[row['file_offset']:row['file_offset']+len(data)],data)
        self.assertEqual({r['text'] for r in self.report['literals']},{'channelCode','channelAccessToken'})
        self.assertTrue(all(r['encoding']=='ascii' for r in self.report['literals']))
        self.assertFalse(self.report['network_ready'])

    def test_save_return_is_ignored_and_credentials_clear_before_registration(self):
        self.assertEqual(len(self.report['cases']),4)
        for case in self.report['cases']:
            self.assertEqual(case['outcome'],'credential_registration_reached')
            kinds=[e['kind'] for e in case['events']]
            self.assertLess(kinds.index('Save_return_fixture'),kinds.index('RemoveAllCredentials_capture'))
            self.assertLess(kinds.index('RemoveAllCredentials_capture'),kinds.index('credential_map_insert_capture'))
            self.assertEqual(case['sdk_channel'],33)
            self.assertEqual(case['provider_channel'],20)
            self.assertFalse(case['native_setters_or_storage_executed'])

    def test_portable_credential_payload_matches_native_field_captures(self):
        for case in self.report['cases']:
            fields=case['fields']
            email=NidEmailCredential(fields['accessToken'],fields['refreshToken'],fields['netmarbleId'],fields['joinedCountryCode'])
            credential=build_nid_sdk_credential(email)
            self.assertEqual(credential.as_object(),case['payload'])
            self.assertEqual(credential.channel_code,33)
            self.assertEqual(email.channel_type,20)
            self.assertNotIn(fields['accessToken'],repr(credential))
            self.assertNotIn('refresh-fixture',str(credential.as_object()))
            changed=credential.as_object()
            changed['channelCode']=20
            self.assertEqual(credential.as_object()['channelCode'],33)

    def test_callback_to_sdk_object_and_invalid_manually_built_inputs(self):
        callback='nmthered://nmidprovider/result?resultCode=0&accessToken=fixture%2Btoken%3D&refreshToken=&channelKey=mailUserKey&netmarbleId=id-fixture&joinedCountryCode=UA'
        email=parse_nid_email_callback(callback,expected_game_code='thered')
        credential=build_nid_sdk_credential(email)
        self.assertEqual(credential.as_object(),dict(channelCode=33,channelAccessToken='fixture+token='))
        with self.assertRaises(FrozenInstanceError):credential.channel_code=20
        for value in (None,dict(channelAccessToken='token'),NidEmailCredential('','','id','UA'),
                      NidEmailCredential('token','','id','UA',channel_type=33),
                      NidEmailCredential('token\nprivate','','id','UA')):
            with self.assertRaises(ValueError) as error:build_nid_sdk_credential(value)
            self.assertNotIn('private',str(error.exception))


if __name__=='__main__':unittest.main()
