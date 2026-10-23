import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.gmc2_context import decode_gmc2_geo,Gmc2Geo,SdkInputs,CURRENT_SOURCE_SHA256,SOURCE_SHA256


class Gmc2Geo11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('geo_11316_test',HERE/'replay-gmc2-geo-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def body(self,**changes):
        fields=dict(clientIp='1.1.1.1',geoLocation='JP',isoCountry='HK');fields.update(changes)
        return json.dumps(dict(errorCode=0,resultData=dict(geoIp=fields))).encode()

    def test_native_field_bindings_and_country_match_current_policy(self):
        report=self.tool().replay()
        self.assertEqual(len(report['cases']),672)
        self.assertFalse(report['network_ready']);self.assertEqual(len(report['links']),4)
        self.assertEqual(list(report['keys'].values()),['geoIp','clientIp','geoLocation','isoCountry'])
        for case in report['cases']:
            self.assertTrue(case['canaries_unchanged'])
            if not case['incoming_country']:continue # Strict local policy rejects empty native values.
            geo=decode_gmc2_geo(self.body(geoLocation=case['incoming_country']),source_sha256=CURRENT_SOURCE_SHA256)
            self.assertEqual(geo.metadata(previous_country=case['old_country'] or '')['I_CountryCD'],case['country'])
        for country in ('A1','a1'):
            geo=decode_gmc2_geo(self.body(geoLocation=country),source_sha256=CURRENT_SOURCE_SHA256)
            self.assertEqual(geo.metadata(previous_country='HK')['I_CountryCD'],'HK')
            self.assertEqual(geo.metadata(previous_country='')['I_CountryCD'],country)
            self.assertEqual(geo.source_sha256,CURRENT_SOURCE_SHA256)

    def test_source_route_account_and_age_guards_remain(self):
        geo=decode_gmc2_geo(self.body(),source_sha256=CURRENT_SOURCE_SHA256)
        inputs=SdkInputs('fixture@example.invalid',None,{}, {},'recovered-release',None,CURRENT_SOURCE_SHA256,geo,100)
        args=dict(email='fixture@example.invalid',selected_profile='recovered-release',route=None)
        inputs.check_usage(**args,now=100)
        for changes in (dict(email='other@example.invalid'),dict(selected_profile='recovered-base')):
            with self.assertRaisesRegex(ValueError,'differs'):inputs.check_usage(**{**args,**changes},now=100)
        with self.assertRaisesRegex(ValueError,'expired'):inputs.check_usage(**args,now=401)
        historical=Gmc2Geo('1.1.1.1','JP','HK','fixture-sha')
        mismatched=SdkInputs('fixture@example.invalid',None,{}, {},'recovered-release',None,CURRENT_SOURCE_SHA256,historical,100)
        with self.assertRaisesRegex(ValueError,'differs'):mismatched.check_usage(**args,now=100)
        for source in ('unknown','0'*64,None,1,[],{}):
            with self.assertRaisesRegex(ValueError,'not verified'):decode_gmc2_geo(self.body(),source_sha256=source)
        self.assertEqual(historical.source_sha256,SOURCE_SHA256)

    def test_invalid_current_geo_values_are_not_coerced(self):
        for key in ('clientIp','geoLocation','isoCountry'):
            for value in (None,False,1,{},[],'','x\0y'):
                with self.assertRaises(ValueError):decode_gmc2_geo(self.body(**{key:value}),source_sha256=CURRENT_SOURCE_SHA256)
        for ip in ('127.0.0.1','10.0.0.1','::1'):
            with self.assertRaises(ValueError):decode_gmc2_geo(self.body(clientIp=ip),source_sha256=CURRENT_SOURCE_SHA256)

    def test_corrupted_geo_export_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.parent.name=='run-c7fac48d96a1' and path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):self.tool().replay()


if __name__=='__main__':unittest.main()
