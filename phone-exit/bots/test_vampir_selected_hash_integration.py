"""Supplementary decoded hashes refine partial inputs without rewriting proofs."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from test_vampir_resource_context_keys_v1 import ResourceContextKeysTests


class SelectedHashContextTests(ResourceContextKeysTests):
    def setUp(self):
        super().setUp()
        (self.knowledge/'resource-selected-hashes.json').write_text('{}')
        self.supplement=SimpleNamespace(rules={'fixture': 'a'*64},runtime=dict(fixture=True),
            resolve=Mock(return_value=dict(state='hashed',sha256='b'*64,
                proof=dict(path=str(self.root/'fixture'),sha256='c'*64))),metrics=dict(decodes=1))
        self.modules['resource-selected-hashes-v1']=SimpleNamespace(scope=lambda *a:self.supplement)

    def test_exact_supplementary_hash_closes_unknown_and_preserves_directory_bytes(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/Quest.uasset',uncompressed=10,decoded_sha256=None)]
        scope,values=self.collect()
        before=Path(self.current_pointer['path']).read_bytes()
        self.assertIs(values[0]['logical_paths_verified'],True)
        self.assertEqual(next(v for v in values[0]['entries'] if v['path'].endswith('.uasset'))['sha256'],'b'*64)
        self.assertEqual(Path(self.current_pointer['path']).read_bytes(),before)
        proof=scope.contexts['quests']['proof'][0]['selected_record_hashes']
        self.assertEqual(proof[0]['state'],'hashed')
        pointer=scope.prepare();body=json.loads(Path(pointer['path']).read_bytes())
        self.assertEqual(body['selected_hash_metrics'],dict(decodes=1))
        self.assertIs(body['profile_activated'],False)
        receipt=scope.publish(self.owner.finish())
        self.assertEqual(receipt['selected_hashes'],dict(decodes=1))

    def test_missing_index_blocker_keeps_full_archive_and_explicit_reason(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/Quest.uasset',uncompressed=10,decoded_sha256=None)]
        self.supplement.resolve.return_value=dict(state='blocked',reason='selected_record_missing_from_index')
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],False)
        self.assertEqual(scope.contexts['quests']['proof'][0]['selected_record_hashes'][0]['reason'],
            'selected_record_missing_from_index')

    def test_known_and_unmatched_hashes_never_request_decoding(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/Unrelated.uasset',uncompressed=10,decoded_sha256=None)]
        scope,values=self.collect()
        self.assertIs(values[0]['logical_paths_verified'],True)
        self.supplement.resolve.assert_not_called()

    def test_multiple_patterns_share_one_supplementary_scope(self):
        self.unknown_entries=[dict(canonical_path='ProjectRED/Content/Quest.uasset',uncompressed=10,decoded_sha256=None)]
        scope,values=self.collect();new=copy.deepcopy(self.contract);new['id']='other'
        # Both consumers may request one record; the supplementary owner owns deduplication.
        from test_vampir_resource_context_keys_v1 import KEYS
        scope.rule['contracts']['other']=KEYS.contract_key(scope.workflow,new)
        scope.inputs(new,[self.row]);self.assertEqual(self.supplement.resolve.call_count,2)
        self.assertIs(scope.hashes,self.supplement)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(SelectedHashContextTests(n) for n in sorted(SelectedHashContextTests.__dict__)
        if n.startswith('test_'))


if __name__=='__main__':unittest.main()
