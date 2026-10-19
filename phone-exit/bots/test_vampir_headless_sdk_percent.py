"""Native percent loop evidence and explicit local callback policy."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import quote

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.sdk_percent import decode_sdk_percent_ascii
from vampir_core.nid_result import parse_nid_email_callback


class SdkPercentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('sdk_percent_test',HERE/'resource-tools/vampir/replay-sdk-percent-decode.py')
        cls.tool=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.config.native.ROOT/'code-clues/sdk-percent-decode-replay.json').read_text('utf-8'))

    def test_native_loop_reproduction_and_boundary_cases(self):
        self.assertEqual(self.tool.build(),self.report)
        cases={c['input']:c for c in self.report['cases']}
        self.assertEqual(len(self.report['cases']),147)
        for text,output in [('a+b',b'a+b'),('%2B',b'+'),('%20',b' '),('%2526',b'%26'),
                            ('%',b''),('%2',b'2'),('%GG',b'\0'),('%1G',b'\x10')]:
            self.assertEqual(bytes.fromhex(cases[text]['output_bytes']),output)
        self.assertEqual(bytes.fromhex(cases['before%00after']['visible_bytes']),b'before')
        self.assertTrue(all(c['guards_unchanged'] for c in self.report['cases']))
        self.assertFalse(self.report['network_ready'])

    def test_strict_common_ascii_subset_matches_native_bytes(self):
        cases={c['input']:c for c in self.report['cases']}
        for value in range(128):
            text='%'+format(value,'02X')
            if 32<=value<=126:
                self.assertEqual(decode_sdk_percent_ascii(text),bytes.fromhex(cases[text]['visible_bytes']).decode('ascii'))
            else:
                with self.assertRaises(ValueError):decode_sdk_percent_ascii(text)
        for text in ('','a+b','%2526','plain_ASCII-._~','a'*1024):
            self.assertEqual(decode_sdk_percent_ascii(text),bytes.fromhex(cases[text]['visible_bytes']).decode('ascii'))
        for bad in (None,'%','%2','%GG','%u0041','%U0041','é','a\0b','a'*32769):
            with self.assertRaises(ValueError):decode_sdk_percent_ascii(bad)

    def callback(self, **changes):
        fields=dict(resultCode='0',accessToken='token+value=',refreshToken='',channelKey='mailUserKey',
                    netmarbleId='user-fixture',joinedCountryCode='UA')
        fields.update(changes)
        return 'nmthered://nmidprovider/result?'+'&'.join(k+'='+quote(v,safe='') for k,v in fields.items())

    def test_callback_scope_and_exactly_one_decode_preserve_tokens(self):
        result=parse_nid_email_callback(self.callback(),expected_game_code='thered')
        self.assertEqual(result.access_token,'token+value=')
        self.assertEqual(result.refresh_token,'')
        self.assertEqual(result.channel_type,20)
        self.assertNotIn('token+value',repr(result))
        encoded=self.callback(accessToken='%26literal')
        self.assertEqual(parse_nid_email_callback(encoded,expected_game_code='thered').access_token,'%26literal')
        literal=self.callback().replace('token%2Bvalue%3D','token+value=')
        self.assertEqual(parse_nid_email_callback(literal,expected_game_code='thered'),result)

    def test_malformed_or_ambiguous_callback_is_rejected_without_values(self):
        good=self.callback()
        invalid=[good.replace('nmthered:','nmother:'),good.replace('nmidprovider','other'),
            good.replace('/result?','/signin?'),good+'#',good+'#fragment',good+'&resultCode=0',
            good+'&',good+'&unknown=x',good.replace('resultCode=0','resultCode=%GG'),
            good.replace('refreshToken=','noRefresh='),self.callback(accessToken='a&evil=1'),
            self.callback(accessToken='a&easyLoginToken=injected'),
            self.callback(resultCode='0abc'),good.replace('nmidprovider','user@nmidprovider'),
            good.replace('nmidprovider','nmidprovider:443'),good.replace('nmidprovider','nmidprovider\\evil')]
        for url in invalid:
            with self.assertRaises(ValueError) as error:parse_nid_email_callback(url,expected_game_code='thered')
            self.assertNotIn('token+value',str(error.exception))
        with self.assertRaises(ValueError):parse_nid_email_callback(good,expected_game_code='thered/other')


if __name__=='__main__':unittest.main()
