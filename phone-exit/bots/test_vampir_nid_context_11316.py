import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'resource-tools/vampir'


class NidContext11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('nid_context_test',HERE/'replay-nid-context-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_current_base_pairs_and_getter_bindings(self):
        tool=self.tool();report=tool.replay()
        self.assertEqual(len(report['cases']),32)
        self.assertIn('FNetmarbleIDContent::CheckPossibleToOpen(',report['caller_diagnostic'])
        self.assertFalse(report['network_ready'])
        for case in report['cases']:
            self.assertEqual([key for key,value in case['pairs']],list(tool.KEYS))
            fields=dict(case['pairs'])
            self.assertEqual(fields['nidV'],'3')
            self.assertEqual(fields['buildCode'],{0:'A',1:'B',2:'C'}.get(case['build_code'],'A'))
            for key in ('gameCode','clientId','countryCode','language','os','nmDeviceKey','deviceKey','osVersion'):
                self.assertEqual(bool(fields[key]),not case['empty'])
            self.assertEqual([e['key'] for e in case['events']],list(tool.KEYS[2:8]))
            self.assertTrue(case['canaries_unchanged'])

    def test_corrupted_source_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):self.tool().replay()

    def test_corrupted_export_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):self.tool().replay()


if __name__=='__main__':unittest.main()
