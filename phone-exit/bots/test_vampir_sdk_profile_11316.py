import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'
ROOT=Path('F:/PhoneExit Resources/Vampir')


class SdkProfile11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('sdk_profile_test',HERE/'build-sdk-profile-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def reports(self,tool):
        return {name:json.loads((ROOT/'code-clues'/folder/sha/'manifest.json').read_text('utf-8'))
                for name,(folder,sha,_) in tool.REPORTS.items()}

    def test_source_bound_profile_is_repeatable_and_keeps_runtime_disabled(self):
        tool=self.tool();first=tool.build()
        self.assertEqual(first,tool.build())
        self.assertEqual(len(first['evidence']),6)
        self.assertEqual(sum(e['cases'] for e in first['evidence'].values()),739)
        self.assertFalse(first['runtime_enabled'])
        self.assertFalse(first['network_ready'])
        self.assertFalse(first['active_runtime_settings_verified'])
        self.assertEqual(first['nid']['profile']['client_id'],'18e6xn1vuR1lGrvR')
        self.assertEqual(first['public_gmc2']['profile'],dict(base='https://apis.netmarble.com/gc2',
            group='netmarbles-v5',sdk_version='5.2.11',build_code=0,market='nmp',game_code='thered',service_code='netmarbles'))
        self.assertEqual(len(first['public_gmc2']['request']['headers']),6)

    def test_constructor_start_or_version_disagreement_is_rejected(self):
        tool=self.tool();base=self.reports(tool)
        for failure in ('start','version','missing_platform','duplicate_override','missing_capture'):
            reports=copy.deepcopy(base)
            if failure=='start':reports['start']['cases'][0]['active_base']='https://wrong.invalid'
            elif failure=='version':
                next(c for c in reports['defaults']['cases'] if c['kind']=='sdk_version')['values']['0x0']='0.0'
            elif failure=='missing_platform':reports['platform']['cases']=[]
            elif failure=='duplicate_override':reports['override']['cases'].append(reports['override']['cases'][0])
            else:reports['headers']['cases']=[]
            with self.subTest(failure=failure),self.assertRaises(ValueError):tool.assemble(reports)

    def test_corrupted_native_report_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.name=='manifest.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'native report changed'):self.tool().build()

    def test_changed_dependency_requires_new_replay(self):
        tool=self.tool();original=tool.digest
        def digest(path):
            return '0'*64 if path.name=='native-request-harness-11316.py' else original(path)
        with patch.object(tool,'digest',digest):
            with self.assertRaisesRegex(ValueError,'replay dependency changed'):tool.build()


class GmcBase11316Tests(unittest.TestCase):
    def test_all_zone_flag_pairs_match_constructed_bases(self):
        spec=importlib.util.spec_from_file_location('gmc_base_test',HERE/'replay-gmc2-base-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        report=module.replay()
        self.assertEqual(len(report['cases']),512)
        for case in report['cases']:
            prefix={0:'alpha-',2:'',3:'dr-'}.get(case['zone'],'dev-')
            self.assertEqual(case['active_base'],'https://'+prefix+'apis.netmarble.com/gc2')
            self.assertEqual(case['source_offset'],{0:'0x150',2:'0x170',3:'0x180'}.get(case['zone'],'0x160'))
            self.assertEqual(case['destination_offset'],'0x1e8')


if __name__=='__main__':unittest.main()
