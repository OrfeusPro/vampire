import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class Gmc2Request11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('gmc2_request_test', HERE/'audit-gmc2-request-11316.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_whole_source_coverage_and_scoped_instruction_alignment(self):
        result = self.tool().audit()
        self.assertFalse(result['native_execution'])
        self.assertEqual(result['compatibility'], 'not_established')
        expected = [('url','0x1444fa180','0x1444fa308','0x1444fa61d',172,456),
                    ('headers','0x1444fbbc0','0x1444fbe00','0x1444fc051',139,433)]
        for row, values in zip(result['slices'], expected):
            self.assertEqual(tuple(row[k] for k in ('kind','new_root','start','stop','slice_instruction_count','whole_instruction_count')), values)
            self.assertFalse(row['whole_shape_differences'])
            self.assertFalse(row['external_targets_verified'])
            self.assertEqual(len(row['instructions']), row['slice_instruction_count'])

    def test_corrupted_source_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.suffix=='.exe' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'source SHA changed'):
                self.tool().audit()

    def test_corrupted_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name=='details.json' else data
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'export SHA changed'):
                self.tool().audit()


if __name__ == '__main__':
    unittest.main()
