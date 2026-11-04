"""Изолированные SHA/cache проверки owner ресурсов без обработки игры."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch


TOOLS = Path(__file__).parent/'resource-tools/vampir'
SPEC = importlib.util.spec_from_file_location('resource_owner_v4_tests', TOOLS/'resource-owner-v4.py')
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class ResourceOwnerV4Tests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.knowledge = self.root/'registry'
        self.knowledge.mkdir()
        self.selector = self.knowledge/'resource-owner-engine.json'
        self.selector.write_bytes(canonical(dict(schema=4, recipe=OWNER.RECIPE)))
        self.calls = []
        self.snapshots = []
        self.workflow = SimpleNamespace(canonical=canonical, snapshot=self.snapshot)
        self.index = SimpleNamespace(digest=self.digest,
            read_json=lambda path:json.loads(Path(path).read_bytes()),
            extension=lambda name:self.workflow if name=='research-workflow' else self.fail(name))
        self.args = SimpleNamespace(root=self.root, knowledge=self.knowledge)
        self.source = self.root/'source.pak'
        self.source.write_bytes(b'bounded current archive')
        self.cache = self.root/'knowledge/resource-csv-v3-cache/fixture.json'

    def digest(self, path):
        path = Path(path)
        self.calls.append(path)
        return sha(path.read_bytes())

    def snapshot(self, root, category, value):
        self.snapshots.append(copy.deepcopy(value))
        raw = canonical(value)
        path = root/'knowledge'/category/sha(raw)/'manifest.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def pointer(self, value=None):
        raw = canonical(dict(result='bounded report') if value is None else value)
        path = self.root/'knowledge/reports'/sha(raw)/'manifest.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return dict(path=str(path), sha256=sha(raw))

    def begin(self):
        return OWNER.begin(self.index, self.args)

    def write_cache(self, value):
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        self.cache.write_bytes(canonical(value))

    def mutate_same_stat(self, path):
        path = Path(path)
        before = path.stat()
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1])+raw[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(path.stat().st_size, before.st_size)
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_selector_is_explicit_and_unknown_recipe_is_rejected(self):
        self.assertTrue(OWNER.enabled(self.index, self.args))
        self.selector.write_bytes(canonical(dict(schema=4, recipe='unknown')))
        with self.assertRaises(ValueError):
            OWNER.enabled(self.index, self.args)
        self.selector.unlink()
        self.assertFalse(OWNER.enabled(self.index, self.args))

    def test_begin_pins_module_selector_and_rejects_second_live_owner(self):
        owner = self.begin()
        self.assertIn(Path(OWNER.__file__).resolve(), owner.files)
        self.assertEqual(owner.files[self.selector], sha(self.selector.read_bytes()))
        self.assertIs(self.args.resource_owner, owner)
        with self.assertRaisesRegex(ValueError, 'уже открыт'):
            self.begin()

    def test_failed_begin_closes_owner_and_allows_retry_with_fixed_selector(self):
        self.selector.write_bytes(b'{invalid JSON')
        with self.assertRaises(ValueError):
            self.begin()
        failed = self.args.resource_owner
        self.assertTrue(failed.closed)
        self.selector.write_bytes(canonical(dict(schema=4, recipe=OWNER.RECIPE)))
        resumed = self.begin()
        self.assertFalse(resumed.closed)
        self.assertNotEqual(resumed.epoch, failed.epoch)
        resumed.finish()

    def test_one_initial_sha_memo_hits_and_one_fresh_final_read(self):
        owner = self.begin()
        expected = sha(self.source.read_bytes())
        self.assertEqual(owner.digest(self.source), expected)
        self.assertEqual(owner.expect(self.source, expected), expected)
        self.assertEqual(owner.digest(self.source), expected)
        self.assertEqual(self.calls.count(self.source), 1)
        result = owner.finish()
        self.assertEqual(self.calls.count(self.source), 2)
        self.assertTrue(result['barrier_completed'])
        self.assertFalse(result['resource_identity_proven'])
        self.assertEqual(result['metrics']['barrier_reads'], len(owner.files))

    def test_remember_reuses_bytes_and_final_barrier_reads_file(self):
        owner = self.begin()
        raw = self.source.read_bytes()
        self.assertEqual(owner.remember(self.source, raw), sha(raw))
        self.assertEqual(owner.digest(self.source), sha(raw))
        self.assertEqual(self.calls.count(self.source), 0)
        owner.finish()
        self.assertEqual(self.calls.count(self.source), 1)

    def test_same_stat_source_mutation_prevents_cache_assignment(self):
        owner = self.begin()
        owner.digest(self.source)
        owner.defer(self.cache, self.pointer())
        self.mutate_same_stat(self.source)
        with self.assertRaisesRegex(ValueError, 'input изменился'):
            owner.finish()
        self.assertEqual(owner.state, 'failed')
        self.assertFalse(self.cache.exists())
        self.assertEqual(self.snapshots, [])

    def test_output_mutation_prevents_deferred_cache_assignment(self):
        owner = self.begin()
        pointer = self.pointer()
        owner.defer(self.cache, pointer)
        self.mutate_same_stat(pointer['path'])
        with self.assertRaisesRegex(ValueError, 'input изменился'):
            owner.finish()
        self.assertFalse(self.cache.exists())

    def test_expected_and_remembered_sha_conflicts_close_owner(self):
        for operation in ('expected', 'remembered'):
            with self.subTest(operation=operation):
                owner = self.begin()
                owner.digest(self.source)
                with self.assertRaises(ValueError):
                    if operation=='expected':
                        owner.expect(self.source, '0'*64)
                    else:
                        owner.remember(self.source, b'another content')
                self.assertTrue(owner.closed)

    def test_pending_cache_is_visible_copied_and_repeated_without_assignment(self):
        owner = self.begin()
        pointer = self.pointer()
        owner.defer(self.cache, pointer)
        cached = owner.cached(self.cache)
        self.assertEqual(cached, pointer)
        cached['sha256'] = '0'*64
        owner.defer(self.cache, pointer)
        self.assertEqual(owner.cached(self.cache), pointer)
        self.assertEqual(owner.metrics['pending_caches'], 1)
        self.assertFalse(self.cache.exists())
        result = owner.finish()
        self.assertEqual(json.loads(self.cache.read_bytes()), pointer)
        self.assertEqual(result['metrics']['assigned_caches'], 1)
        self.assertTrue(self.snapshots[-1]['cache_assignment_pending'])

    def test_conflicting_pending_pointer_is_rejected(self):
        owner = self.begin()
        owner.defer(self.cache, self.pointer())
        with self.assertRaisesRegex(ValueError, 'другой результат|конфликтует'):
            owner.defer(self.cache, self.pointer(dict(result='different')))
        self.assertFalse(self.cache.exists())

    def test_existing_equal_cache_is_validated_without_overwriting(self):
        pointer = self.pointer()
        self.write_cache(pointer)
        before = self.cache.stat().st_mtime_ns
        owner = self.begin()
        self.assertEqual(owner.cached(self.cache), pointer)
        owner.defer(self.cache, pointer)
        self.assertEqual(owner.finish()['metrics']['assigned_caches'], 0)
        self.assertEqual(self.cache.stat().st_mtime_ns, before)

    def test_existing_different_cache_is_not_overwritten(self):
        previous = self.pointer(dict(result='old'))
        self.write_cache(previous)
        owner = self.begin()
        with self.assertRaisesRegex(ValueError, 'другой результат'):
            owner.defer(self.cache, self.pointer(dict(result='new')))
        self.assertEqual(json.loads(self.cache.read_bytes()), previous)

    def test_late_cache_creation_and_cache_corruption_are_rejected(self):
        pointer = self.pointer()
        owner = self.begin()
        self.assertIsNone(owner.cached(self.cache))
        self.write_cache(pointer)
        with self.assertRaisesRegex(ValueError, 'optional input'):
            owner.finish()
        owner = self.begin()
        owner.cached(self.cache)
        self.mutate_same_stat(self.cache)
        with self.assertRaisesRegex(ValueError, 'input изменился'):
            owner.finish()

    def test_cache_budget_and_paths_outside_allowed_namespace_are_rejected(self):
        owner = self.begin()
        self.cache.parent.mkdir(parents=True)
        self.cache.write_bytes(b' '*4097)
        with self.assertRaisesRegex(ValueError, 'бюджет'):
            owner.cached(self.cache)
        owner = self.begin()
        with self.assertRaisesRegex(ValueError, 'разрешённого каталога'):
            owner.cached(self.root/'arbitrary.json')

    def test_alias_retarget_is_detected_before_assignment(self):
        first = self.source
        second = self.root/'second.pak'
        second.write_bytes(first.read_bytes())
        lexical = self.root/'alias.pak'
        target = [first]
        resolve = Path.resolve
        def resolve_alias(path, *args, **kwargs):
            return resolve(target[0] if path==lexical else path, *args, **kwargs)
        with patch.object(Path, 'resolve', resolve_alias):
            owner = self.begin()
            owner.digest(lexical)
            owner.defer(self.cache, self.pointer())
            target[0] = second
            with self.assertRaisesRegex(ValueError, 'alias'):
                owner.finish()
        self.assertFalse(self.cache.exists())

    def test_bind_aliases_rejects_an_expected_different_target(self):
        owner = self.begin()
        with self.assertRaisesRegex(ValueError, 'alias'):
            owner.bind_aliases({str(self.source):self.root/'other.pak'})

    def test_optional_presence_is_checked_and_conflicting_watch_is_rejected(self):
        optional = self.root/'optional.json'
        owner = self.begin()
        owner.watch(optional, False)
        optional.write_bytes(b'appeared')
        with self.assertRaisesRegex(ValueError, 'optional input'):
            owner.finish()
        owner = self.begin()
        owner.watch(optional, True)
        with self.assertRaisesRegex(ValueError, 'optional input'):
            owner.watch(optional, False)

    def test_foreign_args_root_knowledge_index_and_digest_fail_identity(self):
        for changed in ('args', 'root', 'knowledge', 'index', 'digest', 'owner'):
            with self.subTest(changed=changed):
                owner = self.begin()
                other = SimpleNamespace(**vars(self.args))
                index = self.index
                restore = None
                if changed=='root':
                    self.args.root = self.root/'another'
                    restore = lambda:setattr(self.args, 'root', self.root)
                elif changed=='knowledge':
                    self.args.knowledge = self.knowledge/'another'
                    restore = lambda:setattr(self.args, 'knowledge', self.knowledge)
                elif changed=='index':
                    index = SimpleNamespace(**vars(self.index))
                elif changed=='digest':
                    digest = self.index.digest
                    self.index.digest = lambda path:sha(Path(path).read_bytes())
                    restore = lambda:setattr(self.index, 'digest', digest)
                elif changed=='owner':
                    self.args.resource_owner = None
                try:
                    with self.assertRaisesRegex(ValueError, 'identity'):
                        owner.check(index, other if changed=='args' else self.args)
                finally:
                    if restore is not None:restore()

    def test_source_store_identity_is_pinned_and_memo_digest_is_rejected(self):
        store = SimpleNamespace(index=self.index)
        self.args.source_store = store
        owner = self.begin()
        self.args.source_store = SimpleNamespace(index=self.index)
        with self.assertRaisesRegex(ValueError, 'identity'):
            owner.digest(self.source)
        class Store:
            def digest(self, path):
                return sha(Path(path).read_bytes())
        bad_store = Store()
        bad_store.index = SimpleNamespace(digest=bad_store.digest)
        self.args.source_store = bad_store
        with self.assertRaisesRegex(ValueError, 'исходный digest'):
            self.begin()

    def test_closed_owner_rejects_new_reads_and_pending_work(self):
        owner = self.begin()
        owner.finish()
        for operation in (lambda:owner.digest(self.source), lambda:owner.cached(self.cache),
                lambda:owner.final_check(lambda:None), lambda:owner.finish()):
            with self.assertRaisesRegex(ValueError, 'закрыт'):
                operation()

    def test_abort_drops_admission_and_resume_hashes_inputs_again(self):
        pointer = self.pointer()
        owner = self.begin()
        owner.digest(self.source)
        owner.defer(self.cache, pointer)
        owner.abort()
        self.assertFalse(self.cache.exists())
        next_owner = self.begin()
        self.assertNotEqual(next_owner.epoch, owner.epoch)
        self.assertIsNone(next_owner.cached(self.cache))
        next_owner.digest(self.source)
        self.assertEqual(self.calls.count(self.source), 2)
        next_owner.defer(self.cache, pointer)
        next_owner.finish()
        self.assertEqual(json.loads(self.cache.read_bytes()), pointer)

    def test_final_callbacks_run_twice_and_failure_prevents_cache_assignment(self):
        owner = self.begin()
        events = []
        owner.final_check(lambda:events.append('checked'))
        owner.finish()
        self.assertEqual(events, ['checked', 'checked'])
        owner = self.begin()
        owner.defer(self.cache, self.pointer())
        def reject():
            raise ValueError('inventory changed')
        owner.final_check(reject)
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            owner.finish()
        self.assertFalse(self.cache.exists())

    def test_concurrent_reads_share_one_first_hash(self):
        owner = self.begin()
        start = threading.Barrier(8)
        def read(_):
            start.wait(timeout=10)
            return owner.digest(self.source)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(read, range(8)))
        self.assertEqual(results, [sha(self.source.read_bytes())]*8)
        self.assertEqual(self.calls.count(self.source), 1)
        owner.finish()
        self.assertEqual(self.calls.count(self.source), 2)

    def test_assignment_race_does_not_overwrite_different_pointer(self):
        owner = self.begin()
        owner.defer(self.cache, self.pointer())
        competing = canonical(self.pointer(dict(result='competing writer')))
        link = os.link
        def create_before_link(source, destination):
            Path(destination).write_bytes(competing)
            return link(source, destination)
        with patch.object(OWNER.os, 'link', create_before_link):
            with self.assertRaisesRegex(ValueError, 'назначении'):
                owner.finish()
        self.assertEqual(self.cache.read_bytes(), competing)
        self.assertFalse(list(self.cache.parent.glob('.resource-owner-*')))


if __name__=='__main__':
    unittest.main()
