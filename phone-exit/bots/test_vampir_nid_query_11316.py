import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent/'resource-tools/vampir'


class NidQuery11316Tests(unittest.TestCase):
    def tool(self):
        spec = importlib.util.spec_from_file_location('nid_query_test', HERE/'replay-nid-query-11316.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_ascii_encoding_and_url_owner_bindings(self):
        report = self.tool().replay()
        self.assertEqual(len(report['cases']), 396)
        self.assertEqual(len(report['url_cases']), 48)
        self.assertFalse(report['network_ready'])
        self.assertEqual(len(report['verified_links']), 2)
        cases = {c['value']:c['encoded'] for c in report['cases']}
        self.assertEqual(cases[' '], '%20'); self.assertEqual(cases['+'], '%2B')
        self.assertEqual(cases['&'], '%26'); self.assertEqual(cases['='], '%3D')
        self.assertEqual(cases['~'], '~'); self.assertEqual(cases[''], '')
        for case in report['url_cases']:
            expected = case['base']+'?'+case['synthetic_query']
            self.assertEqual(case['owner_writes'], [[0x48, expected], [0x58, expected]])

    def test_unreviewed_leaf_is_rejected(self):
        tool = self.tool(); size, sha = tool.LEAVES[0x141c0c360]
        tool.LEAVES[0x141c0c360] = (size, '0'*64)
        with self.assertRaisesRegex(ValueError, 'leaf SHA changed'): tool.replay()

    def test_corrupted_export_is_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data+b'changed' if path.name == 'details.json' else data
        with patch.object(Path, 'read_bytes', read):
            with self.assertRaisesRegex(ValueError, 'export SHA changed'): self.tool().replay()


if __name__ == '__main__': unittest.main()
