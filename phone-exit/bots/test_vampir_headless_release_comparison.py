import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('release_comparison', Path(__file__).parent / 'resource-tools/vampir/compare-release-snapshots.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ASSET_SPEC = importlib.util.spec_from_file_location('asset_comparison', Path(__file__).parent / 'resource-tools/vampir/compare-release-assets.py')
ASSETS = importlib.util.module_from_spec(ASSET_SPEC)
ASSET_SPEC.loader.exec_module(ASSETS)


class ReleaseComparisonTests(unittest.TestCase):
    def test_asset_match_ignores_old_offsets_and_preserves_duplicate_matches(self):
        previous = [dict(previous_entry=7, sha256='same'), dict(previous_entry=8, sha256='missing')]
        entries = [dict(entry=1, decode_status='decoded', decoded_sha256='same'),
                   dict(entry=2, decode_status='decoded', decoded_sha256='same'),
                   dict(entry=8, decode_status='encrypted_skipped')]
        rows = ASSETS.match_blobs(previous, entries)
        self.assertEqual(rows[0]['matching_new_entries'], [1, 2])
        self.assertEqual(rows[1]['status'], 'not_observed')
        self.assertEqual(rows[1]['matching_new_entries'], [])

    def test_samples_never_establish_content_equality(self):
        a = dict(size=10, modified_ns=1, sample_sha256='sample')
        self.assertEqual(MODULE.compare_file(a, dict(a)), 'sample_equal_content_unverified')
        self.assertEqual(MODULE.compare_file(dict(a, sha256='old'), dict(a, sha256='new')), 'content_changed')
        self.assertEqual(MODULE.compare_file(dict(a, sha256='same'), dict(a, sha256='same')), 'full_hash_equal')
        self.assertEqual(MODULE.compare_file(a, dict(a, modified_ns=2)), 'metadata_changed_content_unverified')
        self.assertEqual(MODULE.compare_file(a, dict(a, size=11)), 'content_changed')

    def test_compare_current_release_instead_of_embedded_original_baseline(self):
        a = dict(size=10, modified_ns=1, sample_sha256='sample', sha256='same')
        def report(rows):
            return dict(exe=dict(sha256='exe'), files=rows)
        old = report([dict(path='C:/Game/A.pak', baseline=None, current=a)])
        new = report([dict(path='c:\\game\\a.pak', baseline=dict(a, sha256='ancient'), current=a),
                      dict(path='C:/Game/B.pak', current=a)])
        result = MODULE.compare(old, new)
        self.assertEqual(result['counts'], dict(full_hash_equal=1, added=1))
        self.assertTrue(result['exe']['full_hash_equal'])
        self.assertEqual(MODULE.compare(new, old)['counts']['removed'], 1)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            MODULE.compare(old, report(new['files'] + new['files']))


if __name__ == '__main__':
    unittest.main()
