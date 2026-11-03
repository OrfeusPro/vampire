"""Explicit immutable legacy-hash import, resume, activation and consumption."""
from collections import Counter
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent/'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ResourceReferenceV3Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.args = SimpleNamespace(root=self.root)
        self.module, self.workflow = load('resource-reference-v3'), load('research-workflow')
        self.calls = Counter()
        self.hash_hook = None
        def hash_file(path):
            path = Path(path).resolve()
            self.calls[path] += 1
            if self.hash_hook:
                self.hash_hook(path, self.calls[path])
            return digest(path)
        self.index = SimpleNamespace(digest=hash_file,
            extension=lambda name: self.workflow if name == 'research-workflow' else load(name))
        self.archive_a, self.archive_b = self.root/'installed/a.pak', self.root/'installed/b.pak'
        self.write(self.archive_a, b'current A'); self.write(self.archive_b, b'current B')
        self.rows = [dict(path=str(self.archive_a)), dict(path=str(self.archive_b))]
        self.entries_a, self.entries_b = self.root/'pak-extracted/a/entries.json', self.root/'pak-extracted/b/entries.json'
        self.blob_a, self.blob_b = self.entries_a.parent/'one.bin', self.entries_b.parent/'two.bin'
        self.write(self.blob_a, b'blob A'); self.write(self.blob_b, b'blob B')
        self.metadata_a = [dict(entry=4, saved=str(self.blob_a), paths=['/Game/A']),
            dict(entry=7, saved=str(self.blob_a), paths=[]), dict(entry=9)]
        self.metadata_b = [dict(entry=3, saved=str(self.blob_b), paths=['/Game/B'])]
        self.write_json(self.entries_a, self.metadata_a); self.write_json(self.entries_b, self.metadata_b)
        self.current = self.root/'knowledge/resource-reference-v3/current.json'

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def write_json(self, path, value):
        self.write(path, self.module.canonical(value))

    def import_(self, rows=None, **kwargs):
        return self.module.import_legacy(self.index, self.args, self.rows if rows is None else rows, **kwargs)

    def snapshot(self, pointer):
        return self.module.open_snapshot(self.index, self.args, pointer)

    def read(self, path):
        return json.loads(Path(path).read_text('utf-8-sig'))

    def same_stat_change(self, path, replacement):
        before = path.stat(); self.assertEqual(len(path.read_bytes()), len(replacement))
        path.write_bytes(replacement); os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

    def test_import_captures_exact_legacy_hashes_without_resource_identity_claim(self):
        pointer = self.import_(); active = self.read(self.current)
        self.assertEqual(set(pointer), {'path', 'sha256'})
        self.assertEqual(digest(pointer['path']), pointer['sha256'])
        self.assertEqual(set(active), {'schema', 'snapshot', 'activation'})
        self.assertEqual(active['snapshot'], pointer)
        activation = self.read(active['activation']['path'])
        self.assertTrue(activation['final_barrier_passed'])
        value = self.read(pointer['path'])
        self.assertEqual(activation['input_closure_sha256'], value['input_closure_sha256'])
        self.assertEqual(activation['generation'], value['generation'])
        snapshot = self.snapshot(pointer); selected = snapshot.select(self.rows[0])
        self.assertEqual(selected['state'], 'available')
        self.assertEqual(selected['blobs'], [dict(previous_entry=row['entry'], file=str(self.blob_a),
            sha256=digest(self.blob_a), observed_paths=row.get('paths', [])) for row in self.metadata_a if row.get('saved')])
        self.assertIsNone(selected['client_version'])
        self.assertFalse(selected['resource_identity_proven'])
        self.assertEqual(selected['compatibility'], 'not_established')
        self.assertEqual(snapshot.finish_barrier()['legacy_files_rehashed'], 0)
        # Shared saved paths are hashed once initially, then once by the final
        # fresh import barrier; duplicated rows preserve their original order.
        self.assertEqual((self.calls[self.blob_a], self.calls[self.blob_b]), (2, 2))

    def test_missing_metadata_and_unimported_archive_are_different_explicit_states(self):
        self.entries_b.unlink()
        pointer = self.import_(); snapshot = self.snapshot(pointer)
        selected = snapshot.select(self.rows[1])
        self.assertEqual((selected['state'], selected['entries'], selected['blobs']), ('missing', None, []))
        other = snapshot.select(dict(path=str(self.root/'installed/new.pak')))
        self.assertEqual((other['state'], other['entries'], other['blobs']), ('not_imported', None, []))
        snapshot.finish_barrier()

    def test_warm_selection_never_reads_old_metadata_or_blob_bytes(self):
        pointer = self.import_()
        self.entries_a.unlink(); self.blob_a.unlink(); self.blob_b.write_bytes(b'legacy now changed')
        original = self.index.digest
        def no_legacy(path):
            if Path(path).resolve().is_relative_to(self.root/'pak-extracted'):
                raise AssertionError('Warm reference must not read old mutable data')
            return original(path)
        self.index.digest = no_legacy
        snapshot = self.module.open_active(self.index, self.args)
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.select(self.rows[0])['blobs'][0]['sha256'], hashlib.sha256(b'blob A').hexdigest())
        snapshot.finish_barrier()
        self.assertEqual(self.module.active_pointer(self.index, self.args), pointer)

    def test_select_returns_copies_and_unrelated_archive_does_not_change_projection_key(self):
        first = self.import_(); snapshot = self.snapshot(first)
        before = snapshot.select(self.rows[0]); poisoned = snapshot.select(self.rows[0]); poisoned['blobs'][0]['observed_paths'].append('poison')
        self.assertEqual(snapshot.select(self.rows[0]), before)
        snapshot.finish_barrier()
        self.blob_b.write_bytes(b'changed B')
        self.metadata_b[0]['paths'].append('/Game/B2'); self.write_json(self.entries_b, self.metadata_b)
        second = self.import_(); self.assertNotEqual(first, second)
        fresh = self.snapshot(second)
        self.assertEqual(fresh.select(self.rows[0])['projection_sha256'], before['projection_sha256'])
        self.assertNotEqual(fresh.select(self.rows[1])['blobs'][0]['sha256'], hashlib.sha256(b'blob B').hexdigest())
        fresh.finish_barrier()

    def test_interruption_reuses_completed_archive_hashes_but_rechecks_full_final_union(self):
        archives = self.root/'knowledge/resource-reference-v3/imports'
        def stop_after_a():
            return bool(list(archives.glob('*/archives/*.json')))
        with self.assertRaises(self.module.ReferenceInterrupted):
            self.import_(stop_requested=stop_after_a)
        self.assertFalse(self.current.exists())
        self.calls.clear(); pointer = self.import_()
        self.assertEqual((self.calls[self.blob_a], self.calls[self.blob_b]), (1, 2))
        self.snapshot(pointer).finish_barrier()

    def test_mid_archive_hash_checkpoint_is_resumable_without_rehashing_finished_work(self):
        third = self.entries_a.parent/'three.bin'; self.write(third, b'blob C')
        self.metadata_a = [dict(entry=n, saved=str(path), paths=[]) for n, path in enumerate((self.blob_a, third, self.blob_a))]
        self.write_json(self.entries_a, self.metadata_a)
        def stop():
            return self.calls[self.blob_a] >= 1 and self.calls[third] >= 1
        with patch.object(self.module, 'CHECKPOINT_INTERVAL', 2):
            with self.assertRaises(self.module.ReferenceInterrupted):
                self.import_([self.rows[0]], stop_requested=stop)
        self.assertFalse(self.current.exists())
        self.calls.clear(); pointer = self.import_([self.rows[0]])
        self.assertEqual((self.calls[self.blob_a], self.calls[third]), (1, 1))
        self.assertEqual(len(self.snapshot(pointer).select(self.rows[0])['blobs']), 3)

    def test_resumed_checkpoint_corruption_blocks_activation_and_requires_new_generation(self):
        imports = self.root/'knowledge/resource-reference-v3/imports'
        with self.assertRaises(self.module.ReferenceInterrupted):
            self.import_(stop_requested=lambda: bool(list(imports.glob('*/archives/*.json'))))
        self.same_stat_change(self.blob_a, b'blob Z')
        with self.assertRaisesRegex(ValueError, 'SHA changed'):
            self.import_()
        self.assertFalse(self.current.exists())
        failed = [self.read(path) for path in imports.glob('*/status.json') if self.read(path)['state'] == 'failed']
        self.assertEqual(len(failed), 1)
        pointer = self.import_(); value = self.read(pointer['path'])
        self.assertNotEqual(value['generation'], failed[0]['generation'])
        self.assertEqual(self.snapshot(pointer).select(self.rows[0])['blobs'][0]['sha256'], digest(self.blob_a))

    def test_changed_metadata_or_tool_guard_creates_a_new_import_generation(self):
        first = self.import_(); old = self.read(first['path'])
        self.metadata_a[0]['paths'].append('/Game/New'); self.write_json(self.entries_a, self.metadata_a)
        second = self.import_(); self.assertNotEqual(self.read(second['path'])['generation'], old['generation'])
        extra = self.root/'reviewed-tool.py'; self.write(extra, b'tool change')
        original = self.module._tools
        def changed(index):
            value = original(index); value['files'][str(extra)] = digest(extra); return value
        with patch.object(self.module, '_tools', side_effect=changed):
            third = self.import_()
        self.assertNotEqual(self.read(third['path'])['generation'], self.read(second['path'])['generation'])

    def test_same_stat_blob_mutation_in_final_barrier_preserves_previous_active_snapshot(self):
        first = self.import_(); current_before = self.current.read_bytes(); self.calls.clear()
        def mutation(path, count):
            if path == self.blob_a and count == 1:
                self.same_stat_change(path, b'blob X')
        self.hash_hook = mutation
        with self.assertRaisesRegex(ValueError, 'SHA changed'):
            self.import_()
        self.assertEqual(self.current.read_bytes(), current_before)
        self.hash_hook = None
        self.assertEqual(self.module.active_pointer(self.index, self.args), first)

    def test_mutation_while_writing_snapshot_is_caught_before_activation(self):
        original = self.workflow.snapshot
        def write(root, category, value):
            result = original(root, category, value)
            if category == self.module.CATEGORY:
                self.same_stat_change(self.blob_a, b'blob X')
            return result
        with patch.object(self.workflow, 'snapshot', side_effect=write):
            with self.assertRaisesRegex(ValueError, 'SHA changed'):
                self.import_()
        self.assertFalse(self.current.exists())

    def test_missing_metadata_appearing_after_snapshot_creation_is_not_activated(self):
        self.entries_b.unlink(); original = self.workflow.snapshot
        def write(root, category, value):
            result = original(root, category, value)
            if category == self.module.CATEGORY:
                self.write_json(self.entries_b, self.metadata_b)
            return result
        with patch.object(self.workflow, 'snapshot', side_effect=write):
            with self.assertRaisesRegex(ValueError, 'appeared'):
                self.import_()
        self.assertFalse(self.current.exists())

    def test_blob_escapes_and_missing_saved_blob_are_concrete_failures(self):
        outside = self.root/'outside.bin'; self.write(outside, b'outside')
        for saved, message in ((str(outside), 'escapes'), (str(self.entries_a.parent/'absent.bin'), 'missing')):
            with self.subTest(saved=saved):
                self.write_json(self.entries_a, [dict(entry=1, saved=saved, paths=[])])
                with self.assertRaisesRegex(ValueError, message):
                    self.import_()
                self.assertFalse(self.current.exists())

    def test_same_content_blob_alias_retarget_is_rejected_without_symlink_privilege(self):
        alias = self.entries_a.parent/'alias.bin'; other = self.entries_a.parent/'other.bin'
        self.write(other, b'blob A'); self.write_json(self.entries_a, [dict(entry=1, saved=str(alias), paths=[])])
        changed = False; original_resolve = Path.resolve
        def resolve(path, *args, **kwargs):
            if Path(path).absolute() == alias.absolute():
                return other if changed else self.blob_a
            return original_resolve(path, *args, **kwargs)
        def mutation(path, count):
            nonlocal changed
            if path == self.blob_a:
                changed = True
        self.hash_hook = mutation
        with patch.object(Path, 'resolve', resolve):
            with self.assertRaisesRegex(ValueError, 'alias changed'):
                self.import_()
        self.assertFalse(self.current.exists())

    def test_unactivated_snapshot_cannot_be_admitted_via_a_plain_current_pointer(self):
        category = self.root/'knowledge'/self.module.CATEGORY
        with self.assertRaises(self.module.ReferenceInterrupted):
            self.import_(stop_requested=lambda: bool(list(category.glob('*/manifest.json'))))
        path = next(category.glob('*/manifest.json')); pointer = dict(path=str(path), sha256=path.parent.name)
        with self.assertRaisesRegex(ValueError, 'activation'):
            self.snapshot(pointer)
        self.write_json(self.current, pointer)
        with self.assertRaisesRegex(ValueError, 'active baseline'):
            self.snapshot(pointer)
        with self.assertRaisesRegex(ValueError, 'schema'):
            self.module.open_active(self.index, self.args)

    def test_interruption_after_activation_receipt_still_does_not_assign_current(self):
        category = self.root/'knowledge'/self.module.ACTIVATION_CATEGORY
        with self.assertRaises(self.module.ReferenceInterrupted):
            self.import_(stop_requested=lambda: bool(list(category.glob('*/manifest.json'))))
        self.assertFalse(self.current.exists())
        self.assertIsNone(self.module.open_active(self.index, self.args))
        pointer = self.import_()
        self.assertEqual(self.module.active_pointer(self.index, self.args), pointer)

    def test_foreign_or_incomplete_activation_receipt_is_rejected(self):
        pointer = self.import_(); active = self.read(self.current); original = self.read(active['activation']['path'])
        for update in (dict(final_barrier_passed=False), dict(generation='e'*64), dict(input_closure_sha256='e'*64),
                dict(snapshot=dict(pointer, sha256='e'*64))):
            with self.subTest(update=update):
                receipt = self.workflow.snapshot(self.root, self.module.ACTIVATION_CATEGORY, dict(original, **update))
                value = dict(active, activation=dict(path=str(receipt), sha256=receipt.parent.name))
                self.write_json(self.current, value)
                with self.assertRaisesRegex(ValueError, 'activation'):
                    self.snapshot(pointer)

    def test_consumer_barrier_rejects_snapshot_activation_pointer_and_tool_mutation(self):
        pointer = self.import_(); active = self.read(self.current)
        for name in ('snapshot', 'activation', 'current', 'tool'):
            with self.subTest(name=name):
                snapshot = self.snapshot(pointer)
                if name == 'tool':
                    original = self.module._tools
                    with patch.object(self.module, '_tools', side_effect=lambda index: dict(original(index), runtime={'python':'changed'})):
                        with self.assertRaisesRegex(ValueError, 'changed'):
                            snapshot.finish_barrier()
                    continue
                path = {'snapshot': Path(pointer['path']), 'activation': Path(active['activation']['path']), 'current': self.current}[name]
                raw = path.read_bytes()
                self.same_stat_change(path, raw.replace(b'\n', b' ', 1))
                try:
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        snapshot.finish_barrier()
                finally:
                    path.write_bytes(raw)

    def test_existing_active_reference_does_not_follow_mutable_legacy_changes_implicitly(self):
        pointer = self.import_(); current = self.current.read_bytes()
        self.write_json(self.entries_a, []); self.blob_a.write_bytes(b'replaced')
        opened = self.module.open_active(self.index, self.args)
        self.assertEqual(opened.pointer, pointer)
        self.assertEqual(opened.select(self.rows[0])['blobs'][0]['sha256'], hashlib.sha256(b'blob A').hexdigest())
        opened.finish_barrier(); self.assertEqual(self.current.read_bytes(), current)

    def test_new_consumer_guard_does_not_silently_reimport_historical_reference(self):
        pointer = self.import_(); original = self.module._tools
        extra = self.root/'reviewed-consumer-dependency.py'; self.write(extra, b'consumer version update')
        def changed(index):
            guard = original(index); guard['files'][str(extra)] = digest(extra); return guard
        self.entries_a.unlink(); self.blob_a.unlink()
        with patch.object(self.module, '_tools', side_effect=changed):
            snapshot = self.snapshot(pointer)
            self.assertNotEqual(snapshot.guard, self.read(pointer['path'])['import_guard'])
            self.assertEqual(snapshot.select(self.rows[0])['blobs'][0]['sha256'], hashlib.sha256(b'blob A').hexdigest())
            snapshot.finish_barrier()
        self.assertEqual(self.read(self.current)['snapshot'], pointer)

    def test_malformed_historical_guard_is_not_a_supported_reference_format(self):
        pointer = self.import_(); value = self.read(pointer['path']); active = self.read(self.current)
        admitted = self.read(active['activation']['path'])
        value['import_guard'] = {'files': {}, 'runtime': {}}
        target = self.workflow.snapshot(self.root, self.module.CATEGORY, value)
        altered = dict(path=str(target), sha256=target.parent.name)
        admitted.update(snapshot=altered, import_guard=value['import_guard'])
        activation = self.workflow.snapshot(self.root, self.module.ACTIVATION_CATEGORY, admitted)
        self.write_json(self.current, dict(schema=3, snapshot=altered,
            activation=dict(path=str(activation), sha256=activation.parent.name)))
        with self.assertRaisesRegex(ValueError, 'historical import guard'):
            self.snapshot(altered)

    def test_unknown_legacy_row_layout_does_not_invent_reference_records(self):
        for record in (dict(saved=str(self.blob_a)), dict(entry=1, saved=str(self.blob_a), paths='not a list')):
            with self.subTest(record=record):
                self.write_json(self.entries_a, [record])
                with self.assertRaises(ValueError):
                    self.import_()
                self.assertFalse(self.current.exists())

    def test_budgets_unknown_format_and_cached_digest_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'budget'):
            self.import_([])
        with patch.object(self.module, 'METADATA_LIMIT', 4):
            with self.assertRaisesRegex(ValueError, 'budget'):
                self.import_()
        source_store = self.index.extension('update-bindings').SourceStore(self.index, self.root)
        cached = SimpleNamespace(digest=source_store.digest, extension=self.index.extension)
        with self.assertRaisesRegex(ValueError, 'uncached'):
            self.module.import_legacy(cached, self.args, self.rows)

    def test_case_alias_archive_lookup_retains_native_path_equality(self):
        pointer = self.import_(); snapshot = self.snapshot(pointer)
        row = dict(path=str(self.archive_a).upper())
        if Path('Case') == Path('case'):
            self.assertEqual(snapshot.select(row)['state'], 'available')
        else:
            self.assertEqual(snapshot.select(row)['state'], 'not_imported')
        snapshot.finish_barrier()

    def test_snapshot_consumer_is_single_use_after_its_barrier(self):
        pointer = self.import_(); snapshot = self.snapshot(pointer); snapshot.finish_barrier()
        with self.assertRaisesRegex(ValueError, 'closed'):
            snapshot.select(self.rows[0])
        with self.assertRaisesRegex(ValueError, 'closed'):
            snapshot.finish_barrier()


if __name__ == '__main__':
    unittest.main()
