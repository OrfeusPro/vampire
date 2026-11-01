"""Published wire selection and ordered SourceStore-local validation; no replay."""
import copy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

adapter = load('update-native-buffer-transport')


def pointer(name): return dict(path=name, sha256=hashlib.sha256(name.encode()).hexdigest())


def fixture():
    cp, check, proof = pointer('wire'), pointer('check'), pointer('proof')
    wire = dict(family='archive-wire', source_sha256='a' * 64, transfer_proof=proof, archive=dict(raw='0x1000'))
    report = dict(source_sha256='a' * 64, context_sha256=cp['sha256'], proof=proof,
        scope='bounded_native_archive_wire', method='bounded_native', network_used=False,
        profile_activated=False, runtime_activated=False, archive=wire['archive'], cases=[{}] * 45,
        wire_cases=[dict(guards=True)] * 64)
    graph = {'wire': wire, 'check': report}
    tools = {'parent.py': '1' * 64}
    api = SimpleNamespace(INDEX='generated-archive-wire', tools=lambda: dict(tools),
        report_valid=load('update-native-archive-wire').report_valid, validate=Mock())
    args = SimpleNamespace(root=Path('root'), knowledge=Path('knowledge'), source_store=SimpleNamespace(), _login_input_seed='foreign')
    baseline = dict(source_sha256='a' * 64, wire_context=cp, wire_check=check)
    return args, (api, Path('wire'), wire, check), baseline, graph, tools


def checked(graph): return lambda root, ptr, category: graph[ptr['path']]


class BufferTransportAdapterTests(unittest.TestCase):
    def test_scope_has_only_five_roots_one_leaf_and_no_allocator_native_claim(self):
        a = adapter.select()
        self.assertEqual((a.layout['executed_roots'], a.layout['leaves'], a.layout['tail_fragments']), (5, 1, 0))
        self.assertEqual((a.proofs, a.index, a.scope, a.verifier),
            ('native-buffer-transport-proofs', 'generated-buffer-transport',
             'bounded_native_buffer_transport', 'verify-buffer-transport-context'))
        for flag in ('native_resize', 'native_growth', 'native_queue_append', 'native_transport', 'native_archive_raw', 'native_set_count'):
            self.assertIs(a.layout[flag], True)
        for flag in ('native_allocator', 'native_socket', 'native_drain', 'native_backend_lifetime', 'native_writer', 'session_executed'):
            self.assertIs(a.layout[flag], False)
        with self.assertRaises(ValueError): adapter.select('frame-integrity')

    def test_publication_wins_over_seed_and_newer_unproved_reference(self):
        a = adapter.select()
        seed = (Path('seed'), dict(source_sha256='a' * 64), 22)
        published = (Path('published'), dict(source_sha256='a' * 64, transfer_proof=pointer('proof')), 22)
        later = (Path('later'), dict(source_sha256='b' * 64), 24)
        with patch.object(adapter.core.Family, 'contexts', return_value=[seed, published, later]):
            self.assertEqual(a.contexts(None), [published, later])
            self.assertEqual(a.baseline_context(None), published[:2])
        with patch.object(adapter.core.Family, 'contexts', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'No reviewed'): a.baseline_context(None)

    def test_parent_report_binding_cannot_cross_source_context_or_proof(self):
        for mode in ('source', 'context', 'proof', 'scope', 'runtime', 'unproved', 'family'):
            args, selected, _, graph, _ = fixture()
            if mode == 'source': graph['check']['source_sha256'] = 'b' * 64
            if mode == 'context': graph['check']['context_sha256'] = 'b' * 64
            if mode == 'proof': graph['check']['proof'] = pointer('foreign')
            if mode == 'scope': graph['check']['scope'] = 'tooling'
            if mode == 'runtime': graph['check']['runtime_activated'] = True
            if mode == 'unproved': graph['wire'].pop('transfer_proof')
            if mode == 'family': graph['wire']['family'] = 'frame-integrity'
            with self.subTest(mode=mode), patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                    patch.object(adapter.core, 'checked', side_effect=checked(graph)):
                with self.assertRaises(ValueError): adapter.parent_dependencies(args, selected)

    def test_exact_two_dependencies_are_copied_and_no_secondary_parent_is_selected(self):
        args, selected, _, graph, _ = fixture()
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter, 'dependency', return_value=selected) as choose:
            dependencies = adapter.select().dependencies(None, args, 'a' * 64)
        self.assertEqual(set(dependencies), adapter.DEPENDENCIES)
        choose.assert_called_once_with(args, 'a' * 64)
        dependencies['wire_check']['path'] = 'mutated'
        self.assertEqual(selected[3]['path'], 'check')
        selected[0].validate.assert_not_called()

    def test_selection_uses_published_only_and_requires_one_exact_report(self):
        args, selected, _, _, _ = fixture(); api, _, wire, check = selected
        api.published_contexts = Mock(return_value=[(Path('wire'), wire, 22)])
        registry = SimpleNamespace(read=Mock(return_value={}))
        with TemporaryDirectory() as folder:
            args.root = Path(folder); p = args.root/'knowledge'/api.INDEX/'index.json'
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps(dict(contexts=[dict(context=pointer('wire'), check=check)])), encoding='utf-8')
            with patch.object(adapter, 'load', side_effect={'update-native-archive-wire': api, 'native-release-registry': registry}.__getitem__), \
                    patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))):
                self.assertEqual(adapter.dependency(args, 'a' * 64), selected)
                for candidates in ([], [(Path('wire'), wire, 22)] * 2):
                    api.published_contexts.return_value = candidates
                    with self.assertRaisesRegex(ValueError, 'one proved'): adapter.dependency(args, 'a' * 64)
                api.published_contexts.return_value = [(Path('wire'), wire, 22)]
                p.write_text(json.dumps(dict(contexts=[])), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'exact published'): adapter.dependency(args, 'a' * 64)

    def test_parent_memo_is_ordered_tools_sensitive_and_store_local(self):
        args, selected, baseline, graph, tools = fixture()
        graph['other'] = copy.deepcopy(graph['wire']); graph['other-check'] = copy.deepcopy(graph['check'])
        graph['other-check']['context_sha256'] = pointer('other')['sha256']
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter.core, 'lineage_inputs', return_value={'material': 'a' * 64}):
            adapter.validate_parents(None, args, selected, baseline)
            adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(selected[0].validate.call_count, 1)
            isolated = selected[0].validate.call_args.args[1]
            self.assertIs(isolated.source_store, args.source_store)
            self.assertFalse(hasattr(isolated, '_login_input_seed'))
            changed = dict(baseline, wire_context=pointer('other'), wire_check=pointer('other-check'))
            adapter.validate_parents(None, args, selected, changed)
            self.assertEqual(selected[0].validate.call_count, 3)  # Ordered distinct baseline and target.
            tools['parent.py'] = '2' * 64
            adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(selected[0].validate.call_count, 4)
            args.source_store = SimpleNamespace()
            adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(selected[0].validate.call_count, 5)

    def test_damaged_lineage_precedes_memo_and_mid_validation_change_is_not_cached(self):
        args, selected, baseline, graph, _ = fixture()
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)):
            with patch.object(adapter.core, 'lineage_inputs', return_value={'material': 'a' * 64}):
                adapter.validate_parents(None, args, selected, baseline)
            with patch.object(adapter.core, 'lineage_inputs', side_effect=ValueError('damaged lineage')):
                with self.assertRaisesRegex(ValueError, 'damaged lineage'): adapter.validate_parents(None, args, selected, baseline)
            args.source_store = SimpleNamespace()
            digests = iter([{'material': 'a' * 64}] * 4 + [{'material': 'b' * 64}] * 4)
            with patch.object(adapter.core, 'lineage_inputs', side_effect=lambda *unused: next(digests)):
                with self.assertRaisesRegex(ValueError, 'changed during'): adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(args.source_store._buffer_transport_parent_validations, {})

    def test_transfer_passes_exact_wire_check_and_keeps_layout_isolated(self):
        args, selected, baseline, _, _ = fixture(); a = adapter.select()
        args.source_store.image = Mock(side_effect=['before', 'after'])
        def transfer(*values, **keywords):
            self.assertIs(values[7], selected[2])
            self.assertEqual(keywords, dict(wire_pointer=pointer('wire'), wire_check=selected[3]))
            values[6][0x10] = 0x20
            return dict(source_sha256='b' * 64), {'closed': True}
        modules = {'build-native-entry-code': 'native', 'update-bindings': 'bindings',
                   'buffer-transport-rules': SimpleNamespace(transfer=transfer)}
        with patch.object(a, 'roots', return_value=set()), patch.object(adapter, 'dependency', return_value=selected), \
                patch.object(adapter, 'validate_parents') as parents, patch.object(adapter, 'load', side_effect=modules.__getitem__), \
                patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))):
            c, detail = a.transfer(None, args, baseline, 'b' * 64)
        parents.assert_called_once_with(None, args, selected, baseline)
        self.assertEqual(detail, dict(details={'closed': True}, mapping={'0x10': '0x20'}))
        c['layout']['leaves'] = 0
        self.assertEqual(a.layout['leaves'], 1)

    def test_tool_closure_includes_parent_rules_contracts_and_adapter(self):
        modules = {name: SimpleNamespace(tools=lambda value=value: value) for name, value in (
            ('update-native-archive-wire', {'parent.py': 'a' * 64}),
            ('buffer-transport-rules', {'rules.py': 'b' * 64}),
            ('buffer-transport-case-contracts', {'contracts.py': 'c' * 64}))}
        with patch.object(adapter, 'load', side_effect=modules.__getitem__), patch.object(adapter.core, 'digest', return_value='d' * 64):
            tools = adapter.select().tools()
        self.assertTrue({'parent.py', 'rules.py', 'contracts.py'} <= set(tools))
        self.assertTrue(any(Path(p).name == 'update-native-buffer-transport.py' for p in tools))
        self.assertTrue(any(Path(p).name == 'portable-native-family.py' for p in tools))


if __name__ == '__main__': unittest.main()
