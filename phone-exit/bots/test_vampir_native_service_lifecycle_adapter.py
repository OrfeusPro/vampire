"""Exact backend publication lineage and SourceStore-local memo isolation."""
import copy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

adapter = load('update-native-service-lifecycle')


def pointer(name): return dict(path=name, sha256=hashlib.sha256(name.encode()).hexdigest())


def fixture():
    cp, check, proof = pointer('backend'), pointer('check'), pointer('proof')
    backend = dict(family='login-backend-wire', source_sha256='a' * 64, transfer_proof=proof)
    report = dict(source_sha256='a' * 64, context_sha256=cp['sha256'], proof=proof,
        scope='bounded_native_login_backend_wire', method='bounded_native', network_used=False,
        profile_activated=False, runtime_activated=False)
    graph = {'backend': backend, 'check': report}; tools = {'parent.py': '1' * 64}
    api = SimpleNamespace(index='generated-login-backend-wire', scope=report['scope'], tools=lambda: dict(tools),
        validate=Mock(), validate_report=Mock())
    api.report_valid = lambda r, c, sha: adapter.core.Family.report_valid(api, r, c, sha)
    selected = api, Path('backend'), backend, check
    args = SimpleNamespace(root=Path('root'), knowledge=Path('knowledge'), source_store=SimpleNamespace(),
        _login_input_seed='foreign', _frame_integrity_seed='foreign')
    baseline = dict(source_sha256='a' * 64, backend_context=cp, backend_check=check)
    return args, selected, baseline, graph, tools


def checked(graph): return lambda root, ptr, category: graph[ptr['path']]


class ServiceLifecycleAdapterTests(unittest.TestCase):
    def test_scope_excludes_opaque_heap_callback_vector_and_network_effects(self):
        a = adapter.select()
        self.assertEqual((a.proofs, a.index, a.scope, a.verifier), ('native-service-lifecycle-proofs',
            'generated-service-lifecycle', 'bounded_native_service_lifecycle', 'verify-service-lifecycle-context'))
        self.assertEqual((a.layout['executed_roots'], a.layout['leaves'], a.layout['tail_fragments']), (12, 1, 0))
        self.assertEqual((a.layout['service_bytes'], a.layout['backend_bytes'], a.layout['control_bytes']), (240, 800, 24))
        for flag in ('native_publisher', 'native_assignment', 'native_ref_control', 'native_backend_constructor',
                     'native_primary_destructors', 'native_base_reset', 'native_string_ring_clear'):
            self.assertIs(a.layout[flag], True)
        for flag in ('native_allocator', 'native_engine_containers', 'native_vector_storage', 'native_callback_lifetime',
                     'native_socket', 'concurrent_references', 'native_writer', 'native_sdk', 'session_executed'):
            self.assertIs(a.layout[flag], False)
        with self.assertRaises(ValueError): adapter.select('buffer-transport')

    def test_proved_baseline_supersedes_seed_without_newer_reference_override(self):
        a = adapter.select(); seed = Path('seed'), dict(source_sha256='a' * 64), 22
        published = Path('published'), dict(source_sha256='a' * 64, transfer_proof=pointer('proof')), 22
        later = Path('later'), dict(source_sha256='b' * 64), 24
        with patch.object(adapter.core.Family, 'contexts', return_value=[seed, published, later]):
            self.assertEqual(a.contexts(None), [published, later]); self.assertEqual(a.baseline_context(None), published[:2])
        with patch.object(adapter.core.Family, 'contexts', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'No reviewed'): a.baseline_context(None)

    def test_two_parent_pointers_are_bound_and_deep_copied_without_native_validation(self):
        args, selected, _, graph, _ = fixture()
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter, 'dependency', return_value=selected) as choose:
            deps = adapter.select().dependencies(None, args, 'a' * 64)
        choose.assert_called_once_with(args, 'a' * 64)
        self.assertEqual(set(deps), {'backend', 'backend_check'})
        self.assertEqual(deps['backend'], pointer('backend'))
        deps['backend_check']['path'] = 'mutated'; self.assertEqual(selected[3]['path'], 'check')
        selected[0].validate.assert_not_called(); selected[0].validate_report.assert_called_once()

    def test_wrong_source_scope_context_proof_or_unproved_parent_fail_closed(self):
        for mode in ('source', 'scope', 'context', 'proof', 'network', 'runtime', 'family', 'unproved'):
            args, selected, _, graph, _ = fixture()
            if mode == 'source': graph['check']['source_sha256'] = 'b' * 64
            if mode == 'scope': graph['check']['scope'] = 'tooling'
            if mode == 'context': graph['check']['context_sha256'] = 'b' * 64
            if mode == 'proof': graph['check']['proof'] = pointer('other-proof')
            if mode == 'network': graph['check']['network_used'] = True
            if mode == 'runtime': graph['check']['runtime_activated'] = True
            if mode == 'family': graph['backend']['family'] = 'frame-integrity'
            if mode == 'unproved': graph['backend'].pop('transfer_proof')
            with self.subTest(mode=mode), patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                    patch.object(adapter.core, 'checked', side_effect=checked(graph)):
                with self.assertRaises(ValueError): adapter.parent_dependencies(args, selected)

    def test_dependency_selection_uses_only_one_exact_backend_publication(self):
        args, selected, _, _, _ = fixture(); api, _, backend, check = selected
        api.published_contexts = Mock(return_value=[(Path('backend'), backend, 22)])
        module = SimpleNamespace(select=Mock(return_value=api)); registry = SimpleNamespace(read=Mock(return_value={}))
        with TemporaryDirectory() as folder:
            args.root = Path(folder); path = args.root/'knowledge'/api.index/'index.json'; path.parent.mkdir(parents=True)
            path.write_text(json.dumps(dict(contexts=[dict(context=pointer('backend'), check=check)])), encoding='utf-8')
            with patch.object(adapter, 'load', side_effect={'update-native-login-backend-wire': module,
                    'native-release-registry': registry}.__getitem__), \
                    patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))):
                self.assertEqual(adapter.dependency(args, 'a' * 64), selected)
                module.select.assert_called_with('login-backend-wire')
                for found in ([], [(Path('backend'), backend, 22)] * 2):
                    api.published_contexts.return_value = found
                    with self.assertRaisesRegex(ValueError, 'one proved'): adapter.dependency(args, 'a' * 64)
                api.published_contexts.return_value = [(Path('backend'), backend, 22)]
                path.write_text(json.dumps(dict(contexts=[])), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'exact published'): adapter.dependency(args, 'a' * 64)

    def test_ordered_parent_memo_is_tools_sensitive_store_local_and_isolates_args(self):
        args, selected, baseline, graph, tools = fixture()
        graph['other'] = copy.deepcopy(graph['backend']); graph['other-check'] = copy.deepcopy(graph['check'])
        graph['other-check']['context_sha256'] = pointer('other')['sha256']
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter.core, 'lineage_inputs', return_value={'material': 'a' * 64}):
            adapter.validate_parents(None, args, selected, baseline); adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(selected[0].validate.call_count, 1)
            isolated = selected[0].validate.call_args.args[1]
            self.assertIs(isolated.source_store, args.source_store)
            self.assertFalse(hasattr(isolated, '_login_input_seed')); self.assertFalse(hasattr(isolated, '_frame_integrity_seed'))
            changed = dict(baseline, backend_context=pointer('other'), backend_check=pointer('other-check'))
            adapter.validate_parents(None, args, selected, changed)
            self.assertEqual(selected[0].validate.call_count, 3)
            tools['parent.py'] = '2' * 64; adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(selected[0].validate.call_count, 4)
            args.source_store = SimpleNamespace(); adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(selected[0].validate.call_count, 5)

    def test_damaged_or_changed_lineage_cannot_hide_behind_memo(self):
        args, selected, baseline, graph, _ = fixture()
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)):
            with patch.object(adapter.core, 'lineage_inputs', return_value={'material': 'a' * 64}):
                adapter.validate_parents(None, args, selected, baseline)
            with patch.object(adapter.core, 'lineage_inputs', side_effect=ValueError('damaged')):
                with self.assertRaisesRegex(ValueError, 'damaged'): adapter.validate_parents(None, args, selected, baseline)
            args.source_store = SimpleNamespace()
            digests = iter([{'material': 'a' * 64}] * 4 + [{'material': 'b' * 64}] * 4)
            with patch.object(adapter.core, 'lineage_inputs', side_effect=lambda *args: next(digests)):
                with self.assertRaisesRegex(ValueError, 'changed during'): adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(args.source_store._service_lifecycle_parent_validations, {})

    def test_transfer_supplies_exact_backend_and_check_and_copies_layout(self):
        args, selected, baseline, _, _ = fixture(); a = adapter.select()
        args.source_store.image = Mock(side_effect=['before', 'after'])
        def transfer(*values, **kwargs):
            self.assertIs(values[7], selected[2])
            self.assertEqual(kwargs, dict(backend_pointer=pointer('backend'), backend_check=selected[3]))
            values[6][0x10] = 0x20
            return dict(source_sha256='b' * 64), {'closed': True}
        modules = {'build-native-entry-code': 'native', 'update-bindings': 'bindings',
                   'service-lifecycle-rules': SimpleNamespace(transfer=transfer)}
        with patch.object(a, 'roots', return_value=set()), patch.object(adapter, 'dependency', return_value=selected), \
                patch.object(adapter, 'validate_parents') as parents, patch.object(adapter, 'load', side_effect=modules.__getitem__), \
                patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))):
            c, detail = a.transfer(None, args, baseline, 'b' * 64)
        parents.assert_called_once_with(None, args, selected, baseline)
        self.assertEqual(detail, dict(details={'closed': True}, mapping={'0x10': '0x20'}))
        c['layout']['leaves'] = 0; self.assertEqual(a.layout['leaves'], 1)

    def test_tools_include_parent_rules_and_new_contract_closure(self):
        modules = {'update-native-login-backend-wire': SimpleNamespace(select=lambda family: SimpleNamespace(tools=lambda: {'parent': 'a'})),
            'service-lifecycle-rules': SimpleNamespace(tools=lambda: {'rules': 'b'}),
            'service-lifecycle-case-contracts': SimpleNamespace(tools=lambda: {'contracts': 'c'})}
        with patch.object(adapter, 'load', side_effect=modules.__getitem__), patch.object(adapter.core, 'digest', return_value='d' * 64):
            tools = adapter.select().tools()
        self.assertTrue({'parent', 'rules', 'contracts'} <= set(tools))
        self.assertTrue(any(Path(p).name == 'update-native-service-lifecycle.py' for p in tools))
        self.assertTrue(any(Path(p).name == 'portable-native-family.py' for p in tools))


if __name__ == '__main__': unittest.main()
