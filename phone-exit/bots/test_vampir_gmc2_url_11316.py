import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class Gmc2Url11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('gmc2_url_test',HERE/'replay-gmc2-url-11316.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_actual_builder_and_dependencies_match_portable_urls(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']),27)
        self.assertTrue(report['native_execution'])
        self.assertFalse(report['network_ready'])
        self.assertEqual(report['copy_import']['name'],'memcpy')
        self.assertEqual(report['cases'][-1]['actual'],
            'https://apis.netmarble.com/gc2/template-groups/netmarbles-v5/5.2.11?game=v5&country=G9&build=A&engine=unreal&market=nmp')
        for case in report['cases']:
            self.assertTrue(case['end_canary_unchanged'])
            self.assertEqual([e['value'] for e in case['events']],['A','B','C','5.2.11'])
            build = {0:'A',1:'B',2:'C'}.get(case['build_code'],'A')
            self.assertIn('&build='+build+'&engine=unreal&market='+case['market'],case['actual'])
        self.assertIn('a/b/5.2.11',report['cases'][-2]['actual'])
        self.assertTrue(report['cases'][-2]['actual'].endswith('market=a b&c=1'))

    def test_corrupt_source_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):
                self.tool().replay()

    def test_corrupt_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):
                self.tool().replay()

    def test_unreviewed_entry_in_mapped_code_is_rejected(self):
        tool = self.tool()
        harness = tool.load('url_harness_guard_test',HERE/'native-request-harness-11316.py')
        h = harness.make_harness(tool.EXPORTS,{0x14452ac30})
        with self.assertRaisesRegex(ValueError,'Unreviewed request target'):
            h.call(0x14452ac31)


if __name__=='__main__':
    unittest.main()
