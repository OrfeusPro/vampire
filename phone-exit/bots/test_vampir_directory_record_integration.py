"""Only missing-index selected records may use the direct header proof."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_selected_hash_integration import SelectedHashContextTests


class DirectRecordContextTests(SelectedHashContextTests):
    def setUp(self):
        super().setUp()
        (self.knowledge/'resource-directory-record.json').write_text('{}')
        self.direct_hook=SimpleNamespace(rules=dict(direct_fixture='d'*64),runtime=dict(fixture=True),
            metrics=dict(unique_records=1),resolve=Mock(return_value=dict(state='hashed',sha256='e'*64,
                method='directory-record-header-v1',proof=dict(path=str(self.root/'direct'),sha256='f'*64))))
        self.modules['resource-directory-record-v1']=SimpleNamespace(scope=lambda *a:self.direct_hook)
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/QuestEmpty.bin',uncompressed=0,decoded_sha256=None)]

    def test_missing_index_supplement_uses_exact_directory_pointer_and_preserves_proof(self):
        self.supplement.resolve.return_value=dict(state='blocked',reason='selected_record_missing_from_index')
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],True)
        row,pointer,entry=self.direct_hook.resolve.call_args.args
        self.assertEqual(pointer,self.current_pointer)
        self.assertEqual(entry['canonical_path'],self.unknown_entries[0]['canonical_path'])
        evidence=scope.contexts['quests']['proof'][0]['selected_record_hashes'][0]
        self.assertEqual(evidence['method'],'directory-record-header-v1')
        scope.prepare();receipt=scope.publish(self.owner.finish())
        self.assertEqual(receipt['directory_records'],dict(unique_records=1))

    def test_normal_indexed_hash_does_not_reach_direct_reader(self):
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],True)
        self.direct_hook.resolve.assert_not_called()

    def test_other_layout_or_budget_blocker_is_not_retried_by_direct_rule(self):
        self.supplement.resolve.return_value=dict(state='blocked',reason='selected_record_size_budget')
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],False)
        self.direct_hook.resolve.assert_not_called()

    def test_direct_rule_blocker_preserves_full_archive_fallback(self):
        self.supplement.resolve.return_value=dict(state='blocked',reason='selected_record_missing_from_index')
        self.direct_hook.resolve.return_value=dict(state='blocked',reason='direct_record_size_budget')
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],False)
        evidence=scope.contexts['quests']['proof'][0]['selected_record_hashes'][0]
        self.assertEqual(evidence['reason'],'direct_record_size_budget')


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(DirectRecordContextTests(n) for n in sorted(DirectRecordContextTests.__dict__)
        if n.startswith('test_'))


if __name__=='__main__':unittest.main()
