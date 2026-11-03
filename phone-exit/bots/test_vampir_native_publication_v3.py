"""Memo reuse keeps exact v2 proofs and earns v3 receipts only after fresh barriers."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load
import test_vampir_native_publication_v2 as fixtures


V3 = load('native-publication-v3')


class PublicationMemoV3Tests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.f = fixtures.Fixture(directory.name)

    def session(self):
        self.f.new_args()
        return V3.begin(self.f.index, self.f.args, self.f.sha)

    def seed_v2(self):
        self.f.populate()
        self.assertEqual(self.f.publish_count, 1)

    def lookup_files(self):
        return list((self.f.root/'knowledge/native-publication-cache-v3').glob('*.json'))

    def v2_files(self):
        return {str(path.relative_to(self.f.root)): path.read_bytes()
            for directory in ('native-publication-cache-v2', fixtures.CACHE.CATEGORY)
            for path in (self.f.root/'knowledge'/directory).rglob('*') if path.is_file()}

    def seed_v3(self):
        self.seed_v2()
        session = self.session()
        self.assertEqual(self.f.call(session), 'reused')
        result = session.finish()
        self.assertEqual(result['v2_bridges'], 1)
        return result

    @staticmethod
    def corrupt_same_stat(path):
        path = Path(path)
        before = path.stat()
        raw = path.read_bytes()
        assert raw
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert path.stat().st_size == before.st_size
        assert path.stat().st_mtime_ns == before.st_mtime_ns

    def add_unrelated_row(self):
        f = self.f
        other_sha = f.source(b'other bounded fixture release')
        export = f.root/'ghidra/request-exports'/other_sha/'run-fixture/details.json'
        export.parent.mkdir(parents=True)
        export.write_bytes(f.export.read_bytes())
        context = fixtures.COMMON.receipt(f.root, 'generated-native-contexts',
            dict(f.context_value, source_sha256=other_sha, source=f.source_path(other_sha)))
        report = fixtures.COMMON.receipt(f.root, 'native-adapter-checks',
            dict(f.report_value, source_sha256=other_sha, context_sha256=context['sha256']))
        row = dict(context=context, check=report, order=2)
        f.write_index([f.row(), row])
        return row

    def test_existing_v2_proof_bridges_without_republishing_or_rewriting_history(self):
        self.seed_v2()
        original_v2 = self.v2_files()
        session = self.session()
        self.assertEqual(self.f.call(session), 'reused')
        self.assertEqual(self.f.publish_count, 1)
        self.assertEqual(self.lookup_files(), [])
        self.assertEqual(session.metrics['receipts_written'], 0)
        result = session.finish()
        self.assertEqual((result['v2_bridges'], result['v3_hits'], result['receipts_written']), (1, 0, 1))
        self.assertEqual(len(self.lookup_files()), 1)
        self.assertEqual(self.v2_files(), original_v2)
        self.f.store.validate.assert_called_once()

    def test_next_invocation_uses_the_explicit_v3_receipt(self):
        self.seed_v3()
        before = {str(p): p.read_bytes() for p in self.lookup_files()}
        session = self.session()
        self.assertEqual(self.f.call(session), 'reused')
        result = session.finish()
        self.assertEqual((result['v3_hits'], result['v2_bridges'], result['receipts_written']), (1, 0, 0))
        self.assertEqual(self.f.publish_count, 1)
        self.assertEqual({str(p): p.read_bytes() for p in self.lookup_files()}, before)
        self.f.store.validate.assert_called_once()

    def test_original_snapshot_is_exact_while_the_memo_guard_is_separate(self):
        self.seed_v2()
        f = self.f
        f.new_args()
        original = f.session()
        expected, eligible = original._snapshot(f.spec, f.tool, f.declaration, f.outcome)
        self.assertTrue(eligible)
        session = self.session()
        actual, eligible = session._snapshot(f.spec, f.tool, f.declaration, f.outcome)
        self.assertTrue(eligible)
        self.assertEqual(actual, expected)
        self.assertNotIn('memo_guard', actual)
        self.assertTrue(session.memo_guard)
        self.assertEqual(f.call(session), 'reused')
        session.finish()
        pointer = json.loads(self.lookup_files()[0].read_text('utf-8'))
        receipt = fixtures.COMMON.checked(f.root, pointer, V3.CATEGORY)
        self.assertEqual(receipt['inputs']['memo_guard'], session.memo_guard)
        self.assertEqual(receipt['inputs']['parent_snapshot'], expected)
        self.assertEqual(receipt['key'], fixtures.CACHE.fingerprint(receipt['inputs']))

    def test_repeated_snapshot_reuses_row_tools_and_digests_with_no_duplicate_oracle(self):
        self.seed_v2()
        f = self.f
        f.tool.published_contexts = Mock(wraps=f.tool.published_contexts)
        f.tool.tools = Mock(wraps=f.tool.tools)
        session = self.session()
        first, eligible = session._snapshot(f.spec, f.tool, f.declaration, f.outcome)
        self.assertTrue(eligible)
        row_calls = f.tool.published_contexts.call_count
        tool_calls = f.tool.tools.call_count
        second, eligible = session._snapshot(f.spec, f.tool, f.declaration, f.outcome)
        self.assertEqual(first, second)
        self.assertTrue(eligible)
        self.assertEqual(f.tool.published_contexts.call_count, row_calls)
        self.assertEqual(f.tool.tools.call_count, tool_calls)
        self.assertGreater(session.memo_metrics['memo_row_hits'], 0)
        self.assertGreater(session.memo_metrics['memo_tools_hits'], 0)
        self.assertGreater(session.memo_metrics['memo_digest_hits'], 0)
        self.assertEqual(f.call(session), 'reused')
        session.finish()
        self.assertGreater(f.tool.tools.call_count, tool_calls)

    def test_row_and_tools_returns_are_copies_that_cannot_poison_memo(self):
        self.seed_v2()
        f = self.f
        session = self.session()
        first = session._row('version-result', f.sha, f.tool)
        first['order'] = 1000
        first['context']['sha256'] = 'f'*64
        self.assertEqual(session._row('version-result', f.sha, f.tool), f.row())
        tools = session._tools('version-result', f.tool)
        tools[str(f.tool_file)] = 'f'*64
        self.assertEqual(session._tools('version-result', f.tool), f.tools)
        self.assertEqual(f.call(session), 'reused')
        session.finish()

    def test_same_size_mtime_corruption_after_memo_blocks_all_new_receipts(self):
        for kind in ('report', 'context', 'proof', 'baseline', 'export', 'tool', 'source', 'index'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                f = fixtures.Fixture(directory)
                f.populate(); f.new_args()
                session = V3.begin(f.index, f.args, f.sha)
                self.assertEqual(f.call(session), 'reused')
                # Populate caches more than once before the external mutation.
                session._snapshot(f.spec, f.tool, f.declaration, f.outcome)
                path = dict(report=Path(f.report['path']), context=Path(f.context['path']),
                    proof=Path(f.context_value['transfer_proof']['path']), baseline=f.baseline,
                    export=f.export, tool=f.tool_file, source=Path(f.source_path(f.sha)), index=f.path)[kind]
                self.corrupt_same_stat(path)
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    session.finish()
                self.assertEqual(session.metrics['receipts_written'], 0)
                self.assertFalse(list((f.root/'knowledge/native-publication-cache-v3').glob('*.json')))

    def test_runtime_registry_and_descriptor_changes_after_memo_are_not_admitted(self):
        for change in ('runtime', 'registry', 'descriptor'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                f = fixtures.Fixture(directory)
                f.populate(); f.new_args()
                session = V3.begin(f.index, f.args, f.sha)
                self.assertEqual(f.call(session), 'reused')
                if change == 'runtime':
                    f.runtime['unicorn']['version'] = 'changed runtime'
                elif change == 'registry':
                    value = json.loads(f.registry_path.read_text())
                    value['note'] = 'changed within invocation'
                    f.registry_path.write_text(json.dumps(value))
                else:
                    source = fixtures.CACHE.HERE/'knowledge/native-drivers-v2/archive-wire.json'
                    (f.knowledge/'native-drivers-v2/archive-wire.json').write_bytes(source.read_bytes())
                with self.assertRaises(ValueError):
                    session.finish()
                self.assertEqual(session.metrics['receipts_written'], 0)

    def test_changed_tools_map_of_same_model_is_checked_again_at_finish(self):
        self.seed_v2()
        f = self.f
        session = self.session()
        self.assertEqual(f.call(session), 'reused')
        extra = f.root/'another-tool.py'; extra.write_bytes(b'new dependency')
        f.tools[str(extra)] = fixtures.digest(extra)
        with self.assertRaises(ValueError):
            session.finish()
        self.assertEqual(session.metrics['receipts_written'], 0)

    def test_alternate_model_cannot_hide_a_different_tools_map_behind_family_memo(self):
        self.seed_v2()
        f = self.f
        extra = f.root/'another-tool.py'; extra.write_bytes(b'new dependency')
        session = self.session()
        self.assertEqual(f.call(session), 'reused')
        alternate = SimpleNamespace(tools=lambda:dict(f.tools, **{str(extra): fixtures.digest(extra)}),
            published_contexts=f.tool.published_contexts, publish=f.tool.publish)
        try:
            session._tools('version-result', alternate)
        except ValueError:
            self.assertEqual(session.metrics['receipts_written'], 0)
            return
        with self.assertRaises(ValueError):
            session.finish()
        self.assertEqual(session.metrics['receipts_written'], 0)

    def test_missing_index_owned_publish_invalidates_missing_row_memo(self):
        f = self.f
        f.write_index([])
        session = self.session()
        self.assertIsNone(session._row('version-result', f.sha, f.tool))
        self.assertEqual(f.call(session), 'validated')
        self.assertEqual(f.publish_count, 1)
        self.assertEqual(session._row('version-result', f.sha, f.tool), f.row())
        self.assertEqual(self.lookup_files(), [])
        result = session.finish()
        self.assertEqual(result['receipts_written'], 1)
        self.assertEqual(self.v2_files(), {})

    def test_owned_publish_preserves_unrelated_rows_and_never_earns_a_v2_receipt(self):
        self.seed_v2()
        f = self.f
        other = self.add_unrelated_row()
        descriptor = f.knowledge/'native-drivers-v2/version-result.json'
        value = json.loads(descriptor.read_text()); value['order'] += 1
        descriptor.write_text(json.dumps(value))
        v2_before = self.v2_files()
        session = self.session()
        self.assertEqual(f.call(session), 'validated')
        session.finish()
        self.assertEqual(f.publish_count, 2)
        self.assertIn(other, json.loads(f.path.read_text())['contexts'])
        self.assertEqual(self.v2_files(), v2_before)

    def test_owned_publish_cannot_remove_an_unrelated_row(self):
        self.seed_v2()
        f = self.f
        self.add_unrelated_row()
        descriptor = f.knowledge/'native-drivers-v2/version-result.json'
        value = json.loads(descriptor.read_text()); value['order'] += 1
        descriptor.write_text(json.dumps(value))
        f.after_publish = lambda:f.write_index([f.row()])
        session = self.session()
        with self.assertRaisesRegex(ValueError, 'unrelated'):
            f.call(session)
        self.assertEqual(self.lookup_files(), [])

    def test_changed_memo_guard_requires_a_new_v3_receipt_but_can_bridge_exact_v2_proof(self):
        self.seed_v3()
        f = self.f
        before = self.v2_files()
        extra = f.root/'reviewed-new-recipe-input.py'; extra.write_bytes(b'new reviewed recipe dependency')
        original_guard = V3.guard_inputs
        def guard(index):
            return dict(original_guard(index), **{str(extra): fixtures.digest(extra)})
        with patch.object(V3, 'guard_inputs', side_effect=guard):
            session = self.session()
            self.assertEqual(f.call(session), 'reused')
            result = session.finish()
        self.assertEqual((result['v3_hits'], result['v2_bridges'], result['receipts_written']), (0, 1, 1))
        self.assertEqual(len(self.lookup_files()), 2)
        self.assertEqual(f.publish_count, 1)
        self.assertEqual(self.v2_files(), before)

    def test_corrupt_v3_receipt_is_a_blocker_not_a_reason_to_silently_rebridge(self):
        self.seed_v3()
        lookup = self.lookup_files()[0]
        pointer = json.loads(lookup.read_text('utf-8'))
        Path(pointer['path']).write_text('{}', 'utf-8')
        session = self.session()
        with self.assertRaises(ValueError):
            self.f.call(session)
        self.assertEqual(self.f.publish_count, 1)
        self.assertEqual(session.metrics['receipts_written'], 0)

    def test_guard_change_during_invocation_cannot_earn_the_pending_v3_receipt(self):
        self.seed_v2()
        session = self.session()
        self.assertEqual(self.f.call(session), 'reused')
        extra = self.f.root/'late-recipe-input.py'; extra.write_bytes(b'late recipe input')
        original_guard = V3.guard_inputs
        with patch.object(V3, 'guard_inputs', side_effect=lambda index:
                dict(original_guard(index), **{str(extra): fixtures.digest(extra)})):
            with self.assertRaisesRegex(ValueError, 'guard changed'):
                session.finish()
        self.assertEqual(self.lookup_files(), [])
        self.assertEqual(session.metrics['receipts_written'], 0)

    def test_identical_bytes_at_retargeted_alias_do_not_preserve_input_identity(self):
        self.seed_v2()
        f = self.f
        alias = f.root/'fixture-alias.bin'
        first = f.root/'first-target.bin'; first.write_bytes(b'identical content')
        second = f.root/'second-target.bin'; second.write_bytes(first.read_bytes())
        original_resolve = Path.resolve
        target = [first]
        def resolve(path, *args, **kwargs):
            if Path(path).absolute() == alias.absolute():
                return original_resolve(target[0], *args, **kwargs)
            return original_resolve(path, *args, **kwargs)
        with patch.object(Path, 'resolve', resolve):
            session = self.session()
            self.assertEqual(f.call(session), 'reused')
            self.assertEqual(session.actual(alias), fixtures.digest(first))
            target[0] = second
            with self.assertRaisesRegex(ValueError, 'alias changed'):
                session.finish()
        self.assertEqual(self.lookup_files(), [])
        self.assertEqual(session.metrics['receipts_written'], 0)

    def test_v2_bridge_lookup_and_receipt_remain_pinned_until_finish(self):
        for selected in ('lookup', 'receipt'):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                f = fixtures.Fixture(directory)
                f.populate(); f.new_args()
                session = V3.begin(f.index, f.args, f.sha)
                self.assertEqual(f.call(session), 'reused')
                lookup = next((f.root/'knowledge/native-publication-cache-v2').glob('*.json'))
                receipt = Path(json.loads(lookup.read_text())['path'])
                (lookup if selected == 'lookup' else receipt).write_text('{}', 'utf-8')
                with self.assertRaises(ValueError):
                    session.finish()
                self.assertEqual(session.metrics['receipts_written'], 0)

    def test_warm_v3_lookup_and_receipt_remain_pinned_until_finish(self):
        for selected in ('lookup', 'receipt'):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as directory:
                f = fixtures.Fixture(directory)
                f.populate(); f.new_args()
                bridge = V3.begin(f.index, f.args, f.sha)
                f.call(bridge); bridge.finish(); f.new_args()
                session = V3.begin(f.index, f.args, f.sha)
                self.assertEqual(f.call(session), 'reused')
                lookup = next((f.root/'knowledge/native-publication-cache-v3').glob('*.json'))
                receipt = Path(json.loads(lookup.read_text())['path'])
                (lookup if selected == 'lookup' else receipt).write_text('{}', 'utf-8')
                with self.assertRaises(ValueError):
                    session.finish()
                self.assertEqual(session.metrics['receipts_written'], 0)

    def test_changed_selected_semantic_report_cannot_use_memo_as_admission(self):
        self.seed_v2()
        f = self.f
        bad = fixtures.COMMON.receipt(f.root, 'native-adapter-checks', dict(f.report_value, cases=[]))
        f.report = bad
        f.outcome.update(report=bad['path'], sha256=bad['sha256'])
        f.write_index()
        session = self.session()
        with self.assertRaises(ValueError):
            f.call(session)
        self.assertEqual(f.publish_count, 1)
        self.assertEqual(self.lookup_files(), [])

    def test_finished_session_cannot_publish_or_finish_again(self):
        self.seed_v3()
        session = self.session()
        self.f.call(session); session.finish()
        with self.assertRaises(ValueError):
            self.f.call(session)
        with self.assertRaises(ValueError):
            session.finish()


if __name__ == '__main__':
    unittest.main()
