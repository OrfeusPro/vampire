"""Exact parent lineage, publication preference and memo isolation; no native run."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

adapter = load('update-native-frame-integrity')


def pointer(name):
    return dict(path=name, sha256=(name[0] * 64))


def fixture():
    context_pointer, wire_pointer = pointer('backend'), pointer('wire')
    backend_proof = pointer('proof')
    backend_check, wire_check, prepare_check = pointer('check'), pointer('vcheck'), pointer('result')
    backend = dict(source_sha256='a' * 64, transfer_proof=backend_proof, wire_context=wire_pointer)
    wire = dict(source_sha256='a' * 64, transfer_proof=pointer('xproof'))
    graph = {
        'backend': backend, 'wire': wire,
        'proof': dict(target=dict(source_sha256='a' * 64), dependencies=dict(
            wire=wire_pointer, wire_check=wire_check, prepare_check=prepare_check)),
        'check': dict(source_sha256='a' * 64, context_sha256=context_pointer['sha256'], proof=backend_proof),
        'vcheck': dict(source_sha256='a' * 64, context_sha256=wire_pointer['sha256'], proof=wire['transfer_proof']),
        'result': dict(source_sha256='a' * 64)}
    tools = {'parent.py': '1' * 64}
    api = SimpleNamespace(index='generated-login-backend-wire', tools=lambda: dict(tools), validate=Mock())
    selected = (api, Path('backend'), backend, backend_check)
    baseline = dict(source_sha256='a' * 64, backend_context=context_pointer, wire_context=wire_pointer)
    args = SimpleNamespace(root=Path('root'), knowledge=Path('knowledge'),
        source_store=SimpleNamespace(), _login_input_seed='foreign')
    return args, selected, baseline, graph, tools


def checked(graph):
    return lambda root, ptr, category: graph[ptr['path']]


class FrameIntegrityAdapterTests(unittest.TestCase):
    def test_native_scope_excludes_old_setup_and_transport(self):
        a = adapter.select()
        self.assertEqual((a.layout['executed_roots'], a.layout['leaves'], a.layout['tail_fragments']), (16, 9, 2))
        for name in ('native_backend', 'native_writer', 'native_checksum', 'native_transform'):
            self.assertIs(a.layout[name], True)
        for name in ('native_prepare', 'native_sdk', 'native_metadata', 'native_sender',
                     'native_publisher', 'native_service_getter', 'native_service_thunk',
                     'native_backend_assignment', 'native_transport', 'session_executed'):
            self.assertIs(a.layout[name], False)
        self.assertEqual((a.proofs, a.index, a.scope, a.verifier),
            ('native-frame-integrity-proofs', 'generated-frame-integrity',
             'bounded_native_frame_integrity', 'verify-frame-integrity-context'))
        with self.assertRaises(ValueError):
            adapter.select('login-backend-wire')

    def test_published_baseline_supersedes_seed_and_newer_unproved_reference(self):
        a = adapter.select()
        seed = (Path('seed'), dict(source_sha256='a' * 64), 22)
        published = (Path('published'), dict(source_sha256='a' * 64, transfer_proof=pointer('proof')), 22)
        new_seed = (Path('next'), dict(source_sha256='b' * 64), 24)
        with patch.object(adapter.core.Family, 'contexts', return_value=[seed, published, new_seed]):
            self.assertEqual(a.contexts(None), [published, new_seed])
            self.assertEqual(a.baseline_context(None), published[:2])
        with patch.object(adapter.core.Family, 'contexts', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'No reviewed'):
                a.baseline_context(None)

    def test_five_dependencies_follow_backend_proof_without_another_wire_selection(self):
        args, selected, _, graph, _ = fixture()
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter, 'dependency', return_value=selected) as choose:
            deps = adapter.select().dependencies(None, args, 'a' * 64)
        self.assertEqual(set(deps), adapter.DEPENDENCIES)
        self.assertEqual(deps['wire'], graph['proof']['dependencies']['wire'])
        self.assertEqual(deps['prepare_check'], graph['proof']['dependencies']['prepare_check'])
        choose.assert_called_once_with(args, 'a' * 64)
        deps['wire']['path'] = 'mutated'
        self.assertEqual(selected[2]['wire_context']['path'], 'wire')

    def test_refuses_cross_source_and_report_or_wire_rebinding(self):
        for mutation in ('wire-link', 'proof-source', 'report-context', 'report-proof',
                         'wire-report-context', 'wire-report-proof', 'prepare-source'):
            args, selected, _, graph, _ = fixture()
            if mutation == 'wire-link':
                graph['proof']['dependencies']['wire'] = pointer('foreign')
            elif mutation == 'proof-source':
                graph['proof']['target']['source_sha256'] = 'f' * 64
            elif mutation == 'report-context':
                graph['check']['context_sha256'] = 'f' * 64
            elif mutation == 'report-proof':
                graph['check']['proof'] = pointer('foreign')
            elif mutation == 'wire-report-context':
                graph['vcheck']['context_sha256'] = 'f' * 64
            elif mutation == 'wire-report-proof':
                graph['vcheck']['proof'] = pointer('foreign')
            else:
                graph['result']['source_sha256'] = 'f' * 64
            with self.subTest(mutation=mutation), \
                    patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                    patch.object(adapter.core, 'checked', side_effect=checked(graph)), self.assertRaises(ValueError):
                adapter.parent_dependencies(args, selected)

    def test_publication_selection_requires_one_exact_report_and_a_proof(self):
        args, selected, _, _, _ = fixture()
        api, _, context, report = selected
        api.published_contexts = Mock(return_value=[(Path('backend'), context, 22)])
        module = SimpleNamespace(select=Mock(return_value=api))
        registry = SimpleNamespace(read=Mock(return_value={}))
        with TemporaryDirectory() as folder:
            args.root = Path(folder)
            p = args.root / 'knowledge' / api.index / 'index.json'
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps(dict(contexts=[dict(context=pointer('backend'), check=report)])), encoding='utf-8')
            with patch.object(adapter, 'load', side_effect={
                    'update-native-login-backend-wire': module, 'native-release-registry': registry}.__getitem__), \
                    patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))):
                self.assertEqual(adapter.dependency(args, 'a' * 64), selected)
                module.select.assert_called_with('login-backend-wire')
                for rows in ([], [(Path('backend'), context, 22)] * 2):
                    api.published_contexts.return_value = rows
                    with self.assertRaisesRegex(ValueError, 'one proved'):
                        adapter.dependency(args, 'a' * 64)
                api.published_contexts.return_value = [(Path('backend'), context, 22)]
                p.write_text(json.dumps(dict(contexts=[])), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'exact published'):
                    adapter.dependency(args, 'a' * 64)
                del context['transfer_proof']
                with self.assertRaisesRegex(ValueError, 'published backend proof'):
                    adapter.dependency(args, 'a' * 64)

    def test_parent_memo_is_ordered_tools_sensitive_store_local_and_isolates_args(self):
        args, selected, baseline, graph, tools = fixture()
        graph['other'] = {}
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter.core, 'lineage_inputs', return_value={'material': 'a' * 64}):
            adapter.validate_parents(None, args, selected, baseline)
            adapter.validate_parents(None, args, selected, baseline)
            api = selected[0]
            self.assertEqual(api.validate.call_count, 1)
            isolated = api.validate.call_args.args[1]
            self.assertIs(isolated.source_store, args.source_store)
            self.assertFalse(hasattr(isolated, '_login_input_seed'))
            changed = copy.deepcopy(baseline)
            changed['backend_context'] = pointer('other')
            adapter.validate_parents(None, args, selected, changed)
            self.assertEqual(api.validate.call_count, 2)
            tools['parent.py'] = '2' * 64
            adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(api.validate.call_count, 3)
            args.source_store = SimpleNamespace()
            adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(api.validate.call_count, 4)

    def test_damaged_lineage_precedes_memo_hit_and_changed_inputs_do_not_cache(self):
        args, selected, baseline, graph, _ = fixture()
        with patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)):
            with patch.object(adapter.core, 'lineage_inputs', return_value={'material': 'a' * 64}):
                adapter.validate_parents(None, args, selected, baseline)
            with patch.object(adapter.core, 'lineage_inputs', side_effect=ValueError('damaged')):
                with self.assertRaisesRegex(ValueError, 'damaged'):
                    adapter.validate_parents(None, args, selected, baseline)
            args.source_store = SimpleNamespace()
            selected[0].validate.side_effect = lambda *unused: graph['result'].update(source_sha256='f' * 64)
            # A proof/report mutation changes the material digest across validation.
            digests = iter([{'material': 'a' * 64}] * 7 + [{'material': 'b' * 64}] * 7)
            with patch.object(adapter.core, 'lineage_inputs', side_effect=lambda *unused: next(digests)):
                with self.assertRaisesRegex(ValueError, 'changed during'):
                    adapter.validate_parents(None, args, selected, baseline)
            self.assertEqual(args.source_store._frame_integrity_parent_validations, {})

    def test_transfer_uses_exact_backend_and_its_wire_and_keeps_layout_isolated(self):
        args, selected, baseline, graph, _ = fixture()
        a = adapter.select()
        args.source_store.image = Mock(side_effect=['before', 'after'])
        projected = dict(source_sha256='b' * 64)
        def transfer(*values, **keywords):
            values[6][0x10] = 0x20
            self.assertIs(values[7], selected[2])
            self.assertIs(values[8], graph['wire'])
            self.assertEqual(keywords['backend_pointer'], pointer('backend'))
            self.assertEqual(keywords['wire_pointer'], pointer('wire'))
            return projected, {'closed': True}
        rules = SimpleNamespace(transfer=transfer)
        modules = {'build-native-entry-code': 'native', 'update-bindings': 'bindings', 'frame-integrity-rules': rules}
        with patch.object(a, 'roots', return_value=set()) as roots, \
                patch.object(adapter, 'dependency', return_value=selected), \
                patch.object(adapter, 'validate_parents') as parents, \
                patch.object(adapter, 'load', side_effect=modules.__getitem__), \
                patch.object(adapter.core, 'checked', side_effect=checked(graph)), \
                patch.object(adapter.core, 'pointer', side_effect=lambda p: pointer(str(p))):
            context, detail = a.transfer(None, args, baseline, 'b' * 64)
        parents.assert_called_once_with(None, args, selected, baseline)
        self.assertEqual(roots.call_count, 2)
        self.assertEqual(detail, dict(details={'closed': True}, mapping={'0x10': '0x20'}))
        self.assertEqual(context['layout'], a.layout)
        context['layout']['leaves'] = 0
        self.assertEqual(a.layout['leaves'], 9)

    def test_report_validation_uses_bound_prepared_and_backend_reports(self):
        context = dict(source=str(Path('root') / 'client-code-snapshots' / ('a' * 64) / 'client.exe'))
        dependencies = Mock(return_value=('wire', 'prepare-report', 'backend-report'))
        validate = Mock()
        modules = {'verify-frame-integrity-context': SimpleNamespace(dependencies=dependencies),
                   'frame-integrity-case-contracts': SimpleNamespace(validate_report=validate)}
        with patch.object(adapter, 'load', side_effect=modules.__getitem__):
            adapter.select().validate_report('report', context)
        dependencies.assert_called_once_with(context, Path('root'), adapter.core)
        validate.assert_called_once_with('report', context, 'prepare-report', 'backend-report')

    def test_tools_include_parent_rules_contract_oracles_and_adapter(self):
        parent = SimpleNamespace(select=lambda family: SimpleNamespace(tools=lambda: {'parent.py': 'p'}))
        modules = {'update-native-login-backend-wire': parent,
            'frame-integrity-rules': SimpleNamespace(tools=lambda: {'rules.py': 'r'}),
            'frame-integrity-case-contracts': SimpleNamespace(tools=lambda: {'frame_primitives.py': 'f', 'ping.py': 'g'})}
        with patch.object(adapter, 'load', side_effect=modules.__getitem__), \
                patch.object(adapter.core, 'digest', return_value='self'):
            tools = adapter.select().tools()
        self.assertTrue({'parent.py', 'rules.py', 'frame_primitives.py', 'ping.py'} <= tools.keys())
        self.assertIn(str(adapter.HERE / 'update-native-frame-integrity.py'), tools)
        self.assertIn(str(adapter.HERE / 'portable-native-family.py'), tools)


if __name__ == '__main__':
    unittest.main()
