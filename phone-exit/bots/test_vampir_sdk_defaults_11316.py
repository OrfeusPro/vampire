import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'


class SdkDefaults11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('sdk_defaults_11316_test',HERE/'replay-sdk-defaults-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

    def test_source_bound_constructors_prefix_and_version(self):
        result=self.tool().replay()
        self.assertEqual(len(result['cases']),9)
        expected=dict(market='',game_code='thered',sdk_type='Global',client_ids=['']*4,build_code=0,sdk_zone=1)
        bases={'0x150':'https://alpha-apis.netmarble.com/gc2',
            '0x160':'https://dev-apis.netmarble.com/gc2','0x170':'https://apis.netmarble.com/gc2',
            '0x180':'https://dr-apis.netmarble.com/gc2','0x190':'netmarbles','0x1c8':'netmarbles-v5'}
        for case in result['cases']:
            if case['kind']=='settings_prefix':self.assertEqual(case['values'],expected)
            elif case['kind']=='gmc_constructor':self.assertEqual(case['values'],bases)
            else:self.assertEqual(case['values'],{'0x0':'5.2.11'})
        self.assertEqual({c['poison'] for c in result['cases'] if 'poison' in c},{0,85,170,255})
        self.assertEqual(len(result['evidence']),2)
        self.assertIn('No game overrides',result['limits'][-1])

    def test_corrupted_source_rejected_before_execution(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):self.tool().replay()

    def test_corrupted_export_rejected_before_execution(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export changed'):self.tool().replay()


if __name__=='__main__':unittest.main()
