import copy
from pathlib import Path
import unittest

from test_vampir_update_contracts import load

ROOT=Path('F:/PhoneExit Resources/Vampir')


class SdkProfile11318Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=load('build-sdk-profile-11318')
        cls.batch=load('run-sdk-batch-11318').run(ROOT)[1]

    def test_current_native_assembly_is_repeatable_and_runtime_disabled(self):
        first=self.builder.build(ROOT);self.assertEqual(first,self.builder.build(ROOT))
        self.assertEqual(first['source_sha256'],'d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c')
        self.assertEqual(first['evidence']['batch']['cases'],3667)
        self.assertEqual(first['nid']['profile']['client_id'],'18e6xn1vuR1lGrvR')
        self.assertFalse(first['runtime_enabled'] or first['network_ready'] or first['game_protocol_verified'])

    def test_native_constructor_start_and_url_must_agree(self):
        aliases=dict(defaults='replay-sdk-defaults-11318',override='replay-sdk-overrides-11318',
            platform='replay-sdk-platform-11318',start='replay-gmc2-base-11318',
            url='replay-gmc2-url-11318',headers='replay-gmc2-headers-11318')
        base={key:self.batch['reports'][name] for key,name in aliases.items()}
        assemble=load('build-sdk-profile-11316').assemble
        self.assertEqual(assemble(base),self.batch['profile_candidate'])
        for failure in ('start','version','missing_platform','duplicate_override','missing_capture'):
            reports=copy.deepcopy(base)
            if failure=='start':reports['start']['cases'][0]['active_base']='https://wrong.invalid'
            elif failure=='version':next(c for c in reports['defaults']['cases'] if c['kind']=='sdk_version')['values']['0x0']='0.0'
            elif failure=='missing_platform':reports['platform']['cases']=[]
            elif failure=='duplicate_override':reports['override']['cases'].append(reports['override']['cases'][0])
            else:reports['headers']['cases']=[]
            with self.subTest(failure=failure),self.assertRaises(ValueError):assemble(reports)


if __name__=='__main__':unittest.main()
