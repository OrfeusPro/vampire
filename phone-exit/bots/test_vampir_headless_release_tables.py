"""Current release CSV discovery and conservative historical matching."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).parent / 'resource-tools/vampir/extract-release-tables.py'
SPEC = importlib.util.spec_from_file_location('vampir_release_tables', PATH)
TABLES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TABLES)


class ReleaseTableTests(unittest.TestCase):
    def test_row_diff_requires_observed_unique_keys_and_preserves_fields(self):
        diff = TABLES.compare_unique_rows(b'Id,Group\n1,a\n2,b\n', b'Id,Group\n1,c\n3,d\n')
        self.assertEqual(diff['added_rows'], 1)
        self.assertEqual(diff['removed_rows'], 1)
        self.assertEqual(diff['changed_rows'], 1)
        self.assertEqual(diff['changed_fields'], {'Group': 1})
        self.assertEqual(TABLES.compare_unique_rows(b'Id,V\n1,a\n1,b\n', b'Id,V\n1,a\n')['status'],
                         'duplicate_first_column')
        self.assertEqual(TABLES.compare_unique_rows(b'Id,V\n1,a,x\n', b'Id,V\n1,a\n')['status'],
                         'unsupported_row_shape')

    def test_bom_and_quoted_multiline_csv(self):
        self.assertIsNone(TABLES.parse_csv(b'Key,Value\n1,2'))
        self.assertIsNone(TABLES.parse_csv(b'\xef\xbb\xbfOneColumn\nvalue'))
        self.assertEqual(TABLES.parse_csv(b'\xef\xbb\xbfKey,Value\n1,"a\nb"\n2,c\n'), (['Key', 'Value'], 2))
        with self.assertRaises(UnicodeError):
            TABLES.parse_csv(b'\xef\xbb\xbfKey,Value\n1,\xff')

    def test_equal_content_and_unique_schema_are_different_evidence(self):
        previous = [dict(file='old-10.csv', sha256='aaa', header=['Id', 'Value']),
                    dict(file='old-20.csv', sha256='bbb', header=['Key', 'Text']),
                    dict(file='old-30.csv', sha256='ccc', header=['Key', 'Text'])]
        current = [dict(file='new-777.csv', sha256='aaa', header=['Id', 'Value']),
                   dict(file='new-20.csv', sha256='ddd', header=['Key', 'Text'])]
        result = TABLES.compare_tables(previous, current)
        self.assertEqual(result['exact_content_matches'], 1)
        self.assertEqual(current[0]['identical_previous_files'], ['old-10.csv'])
        self.assertEqual(current[0]['unique_schema_candidate'], 'old-10.csv')
        self.assertIsNone(current[1]['unique_schema_candidate'])
        self.assertFalse(current[0]['identity_proven_by_schema'])
        self.assertFalse(result['table_identity_by_entry_assumed'])
        duplicated = [dict(file='a', sha256='ddd', header=['Id', 'Value']),
                      dict(file='b', sha256='eee', header=['Id', 'Value'])]
        TABLES.compare_tables(previous, duplicated)
        self.assertTrue(all(r['unique_schema_candidate'] is None for r in duplicated))


if __name__ == '__main__':
    unittest.main()
