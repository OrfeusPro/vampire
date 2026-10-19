"""Fresh SDK response extraction and strict local policy, no live sign-in."""
import dataclasses
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sdk_sign_in_response import parse_sdk_sign_in_response


class SdkResponseParserTests(unittest.TestCase):
    def body(self):
        return dict(errorCode=0,resultData=dict(accessToken='sdk-token-fixture',playerInfo=dict(
            player=dict(playerId='player-fixture',gameRegion='region-fixture',joinedCountryCode='UA'),
            idpInfo=[dict(channelCode=33)])))

    def parse(self,value,status=200):
        return parse_sdk_sign_in_response(status=status,body=json.dumps(value).encode('utf-8'))

    def test_extracts_fresh_data_without_provider_details_or_secret_repr(self):
        value=self.body();result=self.parse(value)
        self.assertEqual(result.access_token,'sdk-token-fixture')
        self.assertEqual(result.player_id,'player-fixture')
        self.assertEqual(result.game_region,'region-fixture')
        self.assertEqual(result.joined_country_code,'UA')
        self.assertEqual(result.idp_info_count,1)
        self.assertNotIn('sdk-token-fixture',repr(result))
        self.assertNotIn('player-fixture',repr(result))
        with self.assertRaises(dataclasses.FrozenInstanceError):result.access_token='replacement'
        value['errorCode']='0'
        self.assertEqual(self.parse(value,status=206),result)

    def test_optional_fields_never_fall_back_to_previous_account(self):
        value=self.body();player=value['resultData']['playerInfo']['player']
        del player['gameRegion'];del player['joinedCountryCode'];del value['resultData']['playerInfo']['idpInfo']
        parsed=self.parse(value)
        self.assertIsNone(parsed.game_region);self.assertIsNone(parsed.joined_country_code)
        self.assertIsNone(parsed.idp_info_count)
        for path in ('accessToken','playerId'):
            value=self.body()
            if path=='accessToken':del value['resultData'][path]
            else:del value['resultData']['playerInfo']['player'][path]
            with self.assertRaises(ValueError):self.parse(value)

    def test_canonical_error_and_structure_policy(self):
        for code in (None,False,True,0.0,1,'','oops','0abc',' 0','0.0'):
            value=self.body();value['errorCode']=code
            with self.assertRaises(ValueError):self.parse(value)
        value=self.body();del value['errorCode']
        with self.assertRaises(ValueError):self.parse(value)
        for status in (True,199,207,500):
            with self.assertRaises(ValueError):self.parse(self.body(),status)
        for value in ({'errorCode':0},[],None):
            with self.assertRaises(ValueError):self.parse(value)

    def test_json_duplicates_budgets_and_field_types(self):
        for body in (b'{"errorCode":0,"errorCode":1}',b'{"nested":{"a":1,"a":2}}',b'{"x":NaN}',b'\xff',b'['*1100,b' '*65537):
            with self.assertRaises(ValueError):parse_sdk_sign_in_response(status=200,body=body)
        for token in ('',False,'x'*8193,'token\nfixture','токен'):
            value=self.body();value['resultData']['accessToken']=token
            with self.assertRaises(ValueError):self.parse(value)
        value=self.body();value['resultData']['playerInfo']['idpInfo']={}
        with self.assertRaises(ValueError):self.parse(value)


if __name__=='__main__':
    unittest.main()
