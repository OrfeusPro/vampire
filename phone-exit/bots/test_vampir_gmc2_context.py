"""Offline geo policy, source isolation, expiry and no sensitive repr output."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.gmc2_context import (decode_gmc2_geo, Gmc2Geo, SdkInputs,
    SOURCE_SHA256, MAX_CONTEXT_AGE)
from vampir_core.socks_route import SocksRoute


class Gmc2ContextTests(unittest.TestCase):
    def body(self, **geo):
        values = dict(clientIp='1.1.1.1',geoLocation='JP',isoCountry='HK')
        values.update(geo)
        return json.dumps(dict(errorCode=0,resultData=dict(geoIp=values))).encode()

    def test_native_field_sources_do_not_substitute_joined_or_iso_country(self):
        value = decode_gmc2_geo(self.body(),source_sha256=SOURCE_SHA256)
        self.assertEqual(value.metadata(previous_country=''),dict(I_ConnectIP='1.1.1.1',I_CountryCD='JP'))
        self.assertEqual(value.iso_country,'HK')
        self.assertEqual(len(value.body_sha256),64)
        for text in ('1.1.1.1',"'JP'","'HK'"): self.assertNotIn(text,repr(value))

    def test_A1_preserves_only_nonempty_bot_owned_previous_country(self):
        value = decode_gmc2_geo(self.body(geoLocation='A1'),source_sha256=SOURCE_SHA256)
        self.assertEqual(value.metadata(previous_country='')['I_CountryCD'],'A1')
        self.assertEqual(value.metadata(previous_country='KR')['I_CountryCD'],'KR')
        ordinary = decode_gmc2_geo(self.body(),source_sha256=SOURCE_SHA256)
        self.assertEqual(ordinary.metadata(previous_country='KR')['I_CountryCD'],'JP')

    def test_missing_non_string_empty_and_unsafe_fields_reject_without_value_in_error(self):
        for key in ('clientIp','geoLocation','isoCountry'):
            for value in (None,False,1,{},[],'','x\0y','x"y','x\\y','x\ny'):
                with self.subTest(key=key,value_type=type(value).__name__):
                    with self.assertRaisesRegex(ValueError,'^Invalid GMC2 geo context$'):
                        decode_gmc2_geo(self.body(**{key:value}),source_sha256=SOURCE_SHA256)
            doc=json.loads(self.body()); del doc['resultData']['geoIp'][key]
            with self.assertRaises(ValueError):
                decode_gmc2_geo(json.dumps(doc).encode(),source_sha256=SOURCE_SHA256)

    def test_local_ipv4_policy_rejects_private_ipv6_and_noncanonical_country(self):
        for ip in ('127.0.0.1','10.0.0.1','169.254.0.1','224.0.0.1','::1','1.1.1.01'):
            with self.assertRaises(ValueError): decode_gmc2_geo(self.body(clientIp=ip),source_sha256=SOURCE_SHA256)
        for iso in ('hk','A1','HKG','JP\0'):
            with self.assertRaises(ValueError): decode_gmc2_geo(self.body(isoCountry=iso),source_sha256=SOURCE_SHA256)

    def test_wrong_source_duplicate_keys_and_bad_envelopes_reject(self):
        with self.assertRaisesRegex(ValueError,'not verified'):
            decode_gmc2_geo(self.body(),source_sha256='old')
        for body in (b'[]',b'{"errorCode":0,"errorCode":0}',b'{"errorCode":true}',
                     b'{"errorCode":0,"resultData":[]}',b'\xff',b'{"errorCode":0,"resultData":{"geoIp":null}}'):
            with self.assertRaises(ValueError): decode_gmc2_geo(body,source_sha256=SOURCE_SHA256)

    def inputs(self):
        geo = Gmc2Geo('1.1.1.1','JP','HK','body-sha')
        return SdkInputs('fixture@example.invalid','device-fixture',{'game_code':'thered'},
            {'key':'secret-fixture'},'recovered-release',17948,SOURCE_SHA256,geo,100)

    def test_context_rejects_expired_future_account_profile_and_route_mismatch(self):
        inputs=self.inputs()
        args=dict(email='fixture@example.invalid',selected_profile='recovered-release',route=SocksRoute(17948))
        for now in (100,100+MAX_CONTEXT_AGE): inputs.check_usage(**args,now=now)
        for now in (99,101+MAX_CONTEXT_AGE,float('nan')):
            with self.assertRaisesRegex(ValueError,'expired'): inputs.check_usage(**args,now=now)
        for change in (dict(email='other@example.invalid'),dict(selected_profile='recovered-base'),
                       dict(route=None),dict(route=SocksRoute(17949))):
            with self.assertRaisesRegex(ValueError,'differs'): inputs.check_usage(**{**args,**change},now=100)
        for text in ('fixture@example.invalid','device-fixture','secret-fixture','1.1.1.1'):
            self.assertNotIn(text,repr(inputs))


if __name__ == '__main__': unittest.main()
