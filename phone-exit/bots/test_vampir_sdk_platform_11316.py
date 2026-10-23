import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class SdkPlatform11316Tests(unittest.TestCase):
    def tool(self):
        spec=importlib.util.spec_from_file_location('sdk_platform_test',HERE/'replay-sdk-platform-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_actual_initializer_switch_table_and_pc_branch(self):
        report=self.tool().replay()
        self.assertEqual(len(report['cases']),12)
        self.assertEqual(report['getter_instruction_count'],75)
        self.assertEqual(len(report['decompiler_block_starts']),11)
        self.assertEqual({c['poison'] for c in report['cases']},{0,85,170,255})
        for case in report['cases']:
            self.assertEqual(case['actual'],'PC' if case['platform_byte']==3 else '')
            self.assertTrue(case['canaries_unchanged'])
        self.assertFalse(report['network_ready'])

    def test_changed_source_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):
                self.tool().replay()

    def test_changed_export_is_rejected(self):
        original=Path.read_bytes
        def read(path):
            data=original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):
                self.tool().replay()


if __name__=='__main__':unittest.main()
