"""One real owner barrier for provisional selected scopes; no native execution."""
import copy
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load
import test_vampir_knowledge_scope_v2 as fixtures


OWNER = load('update-owner-scope-v3')


class UpdateOwnerScopeV3Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.KnowledgeScopeV2()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.index = load('knowledge-index').api()
        self.store = load('update-bindings').SourceStore(self.index, self.fixture.root)
        self.args = SimpleNamespace(root=self.fixture.root, knowledge=self.fixture.knowledge,
            source_store=self.store)

    def scope(self):
        scope = self.fixture.scope(source_store=self.store)
        scope.select([self.fixture.hint])
        return scope

    def owner(self, index=None):
        return OWNER.Owner(index or self.index, self.args, self.store)

    def late_source(self):
        raw = self.fixture.raw + b'late-source'
        sha = hashlib.sha256(raw).hexdigest()
        path = self.fixture.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        path.parent.mkdir(parents=True); path.write_bytes(raw)
        self.store.source(sha)
        return sha, path

    @staticmethod
    def corrupt_same_stat(path):
        stamp = path.stat()
        raw = path.read_bytes()
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert path.stat().st_size == stamp.st_size
        assert path.stat().st_mtime_ns == stamp.st_mtime_ns

    def test_two_batches_have_no_source_barrier_until_single_owner_finish(self):
        first, second = self.scope(), self.scope()
        owner = self.owner()
        with patch.object(self.store, 'validate', wraps=self.store.validate) as validate, \
                patch.object(first, 'finish_barrier', side_effect=AssertionError('Per-batch barrier')), \
                patch.object(second, 'finish_barrier', side_effect=AssertionError('Per-batch barrier')):
            one, two = owner.retain(first), owner.retain(second)
            validate.assert_not_called()
            for declaration in (one, two):
                self.assertEqual(declaration['state'], 'provisional')
                self.assertTrue(declaration['pending_owner'])
                self.assertFalse(declaration['source_barrier_completed'])
                self.assertFalse(declaration['admission_completed'])
                self.assertNotIn('validation_sha256', declaration)
            self.assertFalse(owner.closed)
            result = owner.finish()
            validate.assert_called_once_with()
        self.assertTrue(owner.closed); self.assertTrue(owner.finished)
        self.assertEqual(result['scopes'], 2)
        self.assertEqual(result['metrics']['source_barriers'], 1)
        self.assertEqual(result['metrics']['barrier_digest_reads'], result['metrics']['unique_files'])
        self.assertTrue(result['admission_completed']); self.assertTrue(result['source_barrier_completed'])
        self.assertFalse(result['pending_owner']); self.assertFalse(result['global_history_verified'])
        self.assertEqual(result['inputs'][str(self.fixture.source.resolve())], self.fixture.source_sha)
        self.assertEqual(self.store.metrics['source_reads'], 1)

    def test_provisional_copies_cannot_poison_the_owners_verified_union(self):
        owner = self.owner(); scope = self.scope(); declaration = owner.retain(scope)
        declaration['inputs'][str(self.fixture.pseudo.resolve())] = '0'*64
        declaration['helper_guard'].clear()
        declaration['selected_functions'].clear()
        declaration['metrics']['sha_reads'] = -1
        scope._files.clear(); scope.functions.clear()
        result = owner.finish()
        self.assertEqual(result['inputs'][str(self.fixture.pseudo.resolve())],
            self.index.digest(self.fixture.pseudo))
        self.assertTrue(result['helper_guard'])

    def test_sources_added_after_last_batch_enter_the_final_source_barrier(self):
        scope = self.scope(); owner = self.owner(); owner.retain(scope)
        late_sha, late_path = self.late_source()
        original = self.store.validate
        observed = []
        def validate():
            observed.extend(self.store._sources)
            return original()
        with patch.object(self.store, 'validate', side_effect=validate) as check:
            result = owner.finish()
            check.assert_called_once_with()
        self.assertIn(late_sha, observed)
        self.assertEqual(result['inputs'][str(late_path.resolve())], late_sha)
        self.assertEqual(set(result['source_identities']), {self.fixture.source_sha, late_sha})

    def test_late_source_corruption_with_same_size_mtime_blocks_finish(self):
        owner = self.owner(); owner.retain(self.scope())
        _, path = self.late_source(); self.corrupt_same_stat(path)
        with self.assertRaisesRegex(ValueError, 'source SHA changed'):
            owner.finish()
        self.assertTrue(owner.closed); self.assertFalse(owner.finished)

    def test_retained_and_initial_sources_cannot_disappear_from_store(self):
        for retained in (False, True):
            with self.subTest(retained=retained):
                self.setUp(); scope = self.scope(); owner = self.owner()
                if retained: owner.retain(scope)
                self.store._sources.pop(self.fixture.source_sha)
                with patch.object(self.store, 'validate', wraps=self.store.validate) as validate:
                    with self.assertRaisesRegex(ValueError, 'retained source disappeared'):
                        owner.finish()
                    validate.assert_not_called()

    def test_same_bytes_source_path_retarget_is_not_a_valid_identity(self):
        scope = self.scope(); owner = self.owner(); owner.retain(scope)
        original = Path.resolve
        alias = self.fixture.source.parent/'same-bytes.exe'; alias.write_bytes(self.fixture.raw)
        alias, source = original(alias), original(self.fixture.source)
        def resolve(path, *args, **kwargs):
            actual = original(path, *args, **kwargs)
            return alias if actual == source else actual
        with patch.object(Path, 'resolve', resolve):
            with self.assertRaisesRegex(ValueError, 'source path alias changed'):
                owner.finish()

    def test_source_path_retarget_during_source_barrier_is_rejected(self):
        scope = self.scope(); owner = self.owner(); owner.retain(scope)
        original_resolve = Path.resolve
        alias = self.fixture.source.parent/'same-bytes.exe'; alias.write_bytes(self.fixture.raw)
        alias, source = original_resolve(alias), original_resolve(self.fixture.source)
        switched = False
        def resolve(path, *args, **kwargs):
            actual = original_resolve(path, *args, **kwargs)
            return alias if switched and actual == source else actual
        original_validate = self.store.validate
        def validate():
            nonlocal switched
            value = original_validate(); switched = True
            return value
        with patch.object(Path, 'resolve', resolve), patch.object(self.store, 'validate', side_effect=validate):
            with self.assertRaisesRegex(ValueError, 'source path alias changed'):
                owner.finish()

    def test_new_source_during_the_final_barrier_requires_a_fresh_owner(self):
        owner = self.owner(); owner.retain(self.scope())
        original = self.store.validate
        def validate():
            result = original(); self.late_source(); return result
        with patch.object(self.store, 'validate', side_effect=validate):
            with self.assertRaisesRegex(ValueError, 'source set changed'):
                owner.finish()
        self.assertTrue(owner.closed)
        with self.assertRaisesRegex(ValueError, 'Owner is closed'): owner.finish()

    def test_selected_file_tool_and_runtime_same_stat_corruption_are_rejected(self):
        for kind in ('pseudocode', 'tool', 'runtime'):
            with self.subTest(kind=kind):
                self.setUp(); scope = self.scope()
                if kind == 'pseudocode': path = self.fixture.pseudo
                else:
                    path = self.fixture.knowledge/(kind+'.bin'); path.write_bytes(b'first-value')
                    scope.pin(path, kind=kind)
                owner = self.owner(); owner.retain(scope); self.corrupt_same_stat(path)
                with self.assertRaisesRegex(ValueError, 'Owner input SHA changed'): owner.finish()

    def test_helper_guard_is_in_provisional_and_freshly_verified_even_without_scopes(self):
        helper = self.fixture.knowledge/'owner-helper.py'; helper.write_bytes(b'helper-code-v3')
        with patch.object(OWNER, '__file__', str(helper)):
            owner = self.owner()
        self.assertEqual(owner.helper_guard, {str(helper.resolve()): self.index.digest(helper)})
        self.corrupt_same_stat(helper)
        with self.assertRaisesRegex(ValueError, 'Owner input SHA changed'): owner.finish()

    def test_conflicting_checked_batches_do_not_partly_extend_the_union(self):
        first = self.scope(); owner = self.owner(); owner.retain(first)
        before = copy.deepcopy(owner.metrics)
        self.fixture.pseudo.write_text('int f(){ return 43; }', 'utf-8')
        self.fixture.publish(); changed = self.scope()
        with self.assertRaisesRegex(ValueError, 'Conflicting SHA between Owner batches'): owner.retain(changed)
        self.assertEqual(owner.metrics, before)

    def test_tampered_in_memory_scope_bytes_are_not_a_verified_declaration(self):
        scope = self.scope(); owner = self.owner()
        scope._files[self.fixture.pseudo.resolve()]['raw'] = b'forged'
        with self.assertRaisesRegex(ValueError, 'retained bytes'): owner.retain(scope)
        self.assertEqual(owner.metrics['retained_scopes'], 0)

    def test_scope_must_use_exact_same_store_even_when_root_is_equal(self):
        scope = self.scope(); owner = self.owner()
        scope.source_store = load('update-bindings').SourceStore(self.index, self.fixture.root)
        with self.assertRaisesRegex(ValueError, 'another Owner root or SourceStore'): owner.retain(scope)

    def test_root_knowledge_or_store_identity_changes_are_rejected(self):
        for field in ('root', 'knowledge', 'store'):
            with self.subTest(field=field):
                self.setUp(); scope = self.scope(); owner = self.owner(); owner.retain(scope)
                if field == 'store': self.args.source_store = object()
                else: setattr(self.args, field, self.fixture.root/'another')
                with self.assertRaisesRegex(ValueError, 'identity changed'): owner.finish()

    def test_source_path_must_stay_inside_its_snapshot_prefix(self):
        self.scope()
        original = Path.resolve
        outside = self.fixture.root/'outside.exe'; outside.write_bytes(self.fixture.raw)
        outside, source = original(outside), original(self.fixture.source)
        def resolve(path, *args, **kwargs):
            actual = original(path, *args, **kwargs)
            return outside if actual == source else actual
        with patch.object(Path, 'resolve', resolve):
            with self.assertRaisesRegex(ValueError, 'escapes the source snapshot prefix'): self.owner()

    def test_cached_store_digest_cannot_be_used_as_the_owners_final_digest(self):
        with self.assertRaisesRegex(ValueError, 'original uncached digest'):
            self.owner(SimpleNamespace(digest=self.store.digest))

    def test_successful_owner_is_single_use_and_final_hash_matches_admission(self):
        owner = self.owner(); owner.retain(self.scope()); result = owner.finish()
        admission = {key: value for key, value in result.items()
            if key not in ('validation_sha256', 'metrics', 'source_store')}
        self.assertEqual(result['validation_sha256'], hashlib.sha256(OWNER.canonical(admission)).hexdigest())
        with self.assertRaisesRegex(ValueError, 'Owner is closed'): owner.finish()
        with self.assertRaisesRegex(ValueError, 'Owner is closed'): owner.retain(self.scope())


if __name__ == '__main__':
    unittest.main()
