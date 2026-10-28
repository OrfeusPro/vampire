"""A full inventory does not certify that required resource extraction ran."""
import unittest
from test_vampir_update_contracts import load


class ArchiveSelectionTests(unittest.TestCase):
    def setUp(self):self.tool=load('index-release-archives')

    def test_explicit_full_sha_allows_missing_artifacts_for_equal_inventory(self):
        row=dict(status='sample_matches_unverified',current=dict(pak_version=11,sha256='a'*64))
        self.assertFalse(self.tool.selected_archive(row,None))
        self.assertTrue(self.tool.selected_archive(row,'a'*64))
        self.assertFalse(self.tool.selected_archive(row,'b'*64))

    def test_sample_or_partial_digest_cannot_select_an_archive(self):
        row=dict(status='sample_matches_unverified',current=dict(pak_version=11,sample_sha256='a'*64))
        self.assertFalse(self.tool.selected_archive(row,'a'*64))
        with self.assertRaisesRegex(ValueError,'full SHA256'):
            self.tool.selected_archive(row,'a'*12)


if __name__=='__main__':unittest.main()
