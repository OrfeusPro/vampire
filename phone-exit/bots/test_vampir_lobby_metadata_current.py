"""Source-bound metadata decisions; synthetic timezone providers stay explicit."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PATH = HERE / 'resource-tools/vampir/verify-lobby-metadata-current.py'


class LobbyMetadataCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('lobby_metadata_current_test', PATH)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.outcome = cls.tool.verify()
        cls.report = json.loads(Path(cls.outcome['report']).read_bytes())

    def test_signed_offsets_and_both_provider_results_gate_acceptance(self):
        rows = self.report['validation_cases']
        self.assertEqual(len(rows), 362)
        matrix = [row for row in rows if 'failure' in row]
        self.assertEqual(len(matrix), 350)
        self.assertEqual({row['left'] for row in matrix}, {-2147483648, -3600, 0, 3600, 2147483647})
        self.assertEqual({row['right'] for row in matrix}, {row['left'] for row in matrix})
        for row in matrix:
            self.assertEqual(row['accepted'], row['failure'] == 'none')
            expected_calls = {'provider': 0, 'format': 0, 'first': 1}.get(row['failure'], 2)
            self.assertEqual(row['offset_calls'], expected_calls)
        self.assertTrue(all(row['accepted'] for row in rows if 'time' in row or row.get('empty')))

    def test_native_apply_only_invalidates_caches_when_zone_changes(self):
        rows = self.report['apply_cases']
        self.assertEqual(len(rows), 48)
        for row in rows:
            self.assertEqual(row['changed'], row['previous'] != row['text'])
            expected = int(row['changed'] and bool(row['text'])) * 2
            self.assertEqual(row['offset_calls'], expected)
            if row['changed']:
                self.assertIn('narrow_assign', row['events'])
            else:
                self.assertNotIn('narrow_assign', row['events'])
        self.assertTrue(self.report['native_execution'])
        self.assertFalse(self.report['runtime_admitted'])
        self.assertFalse(self.report['network_used'])
        self.assertTrue(any('synthetic' in value for value in self.report['limits']))

    def test_corrupt_export_or_source_literal_cannot_publish_proof(self):
        original = json.loads(self.tool.CONTEXT.read_bytes())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'context.json'
            for variant in ('export', 'literal', 'source'):
                changed = json.loads(json.dumps(original))
                if variant == 'export':
                    changed['exports'][next(iter(changed['exports']))] = '0' * 64
                elif variant == 'literal':
                    changed['literals'][0]['bytes'] = '00' + changed['literals'][0]['bytes'][2:]
                else:
                    changed['source_sha256'] = '0' * 64
                path.write_text(json.dumps(changed), encoding='utf-8')
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    self.tool.verify(path)


if __name__ == '__main__':
    unittest.main()
