"""LoginResult family scopes, dependency provenance and immutable admission."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load

TOOL = load('update-native-login-input')
CORE = TOOL.core


def context(family='login-strings-buffer'):
    value = json.loads((TOOL.HERE / 'knowledge/native-contexts' / (family + '-11320.json')).read_text('utf-8'))
    api = TOOL.select(family)
    value.update(family=family, layout=copy.deepcopy(api.layout), transfer_proof=dict(path='proof', sha256='b' * 64))
    return value


def report(c, family):
    api = TOOL.select(family)
    return dict(source_sha256=c['source_sha256'], scope=api.scope, method='bounded_native',
        network_used=False, profile_activated=False, runtime_activated=False,
        proof=c['transfer_proof'], context_sha256='c' * 64, cases=[])


def proof(c, api, baseline):
    return dict(schema=1, adapter=api.adapter, family=api.family, scope=api.scope,
        tools={}, runtime_activated=False, target=CORE.plain(c), relocation={}, dependencies={},
        baseline=dict(path=str(baseline), sha256='d' * 64))


class LoginInputScopeTests(unittest.TestCase):
    def test_families_keep_separate_indexes_and_explicit_native_scope(self):
        self.assertEqual(TOOL.FAMILIES, ('login-nested', 'login-strings-buffer'))
        apis = [TOOL.select(family) for family in TOOL.FAMILIES]
        self.assertEqual(len({api.index for api in apis}), 2)
        self.assertEqual([api.layout['executed_roots'] for api in apis], [6, 20])
        self.assertEqual([api.layout['packet_bytes'] for api in apis], [352, 352])
        self.assertEqual([api.layout['native_strings'] for api in apis], [False, True])
        self.assertEqual([api.layout['native_buffer_construction'] for api in apis], [False, True])
        for family in ('login-input', '../login-nested', 'login-strings', None, []):
            with self.assertRaises(ValueError): TOOL.select(family)

    def test_reviewed_packet_and_input_roots_are_distinct_from_returning_leaves(self):
        for family, count, leaves in zip(TOOL.FAMILIES, (6, 20), (3, 6)):
            c = context(family);roots = TOOL.select(family).roots(c)
            self.assertEqual(len(roots), count)
            self.assertEqual(len(c['leaves']), leaves)
            self.assertFalse(roots & {int(at, 16) for at in c['leaves']})

    def test_missing_or_additional_executed_roles_are_rejected(self):
        for family in TOOL.FAMILIES:
            for change in (lambda c: c['functions'].pop('period_reader'),
                    lambda c: c['functions'].update(extra='0x145000000')):
                c = context(family);change(c)
                with self.assertRaises(ValueError): TOOL.select(family).roots(c)
        for change in (lambda c: c['input']['functions'].pop('utf8_scalar'),
                lambda c: c['input']['functions'].update(extra='0x145000000')):
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)

    def test_native_scopes_and_export_budgets_cannot_be_extended(self):
        for key, value in (('input', {}), ('native_strings', True), ('function_budget', 20),
                ('native_metadata', {}), ('native_sdk', {})):
            c = context('login-nested');c[key] = value
            with self.assertRaises(ValueError): TOOL.select('login-nested').roots(c)
        for key, value in (('native_strings', False), ('function_budget', 21), ('function_budget', 20.0),
                ('budget_scope', 'all-login'), ('verify_whole_exports', False), ('native_metadata', {})):
            c = context();c[key] = value
            with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)

    def test_root_and_leaf_aliases_are_rejected(self):
        for family in TOOL.FAMILIES:
            c = context(family);c['functions']['period_reader'] = c['functions']['time_reader']
            with self.assertRaises(ValueError): TOOL.select(family).roots(c)
            c = context(family);c['functions']['reader'] = next(iter(c['leaves']))
            with self.assertRaises(ValueError): TOOL.select(family).roots(c)
        c = context();c['input']['functions']['bool'] = c['functions']['reader']
        with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)

    def test_string_reader_and_input_leaf_partitions_are_exact(self):
        c = context();c['string_reader'] = c['input']['functions']['std_string']
        with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)
        c = context();at = next(iter(c['input']['leaves']));c['input']['leaves'][at]['bytes'] = 'c3'
        with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)
        c = context();c['input']['leaves']['0x140000000'] = dict(bytes='c3')
        with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)

    def test_fixture_targets_cannot_shadow_executed_packet_input_or_leaf_code(self):
        changes = (
            lambda c: c.update(string_constructor=c['functions']['reader']),
            lambda c: c['helpers'].update(memcpy=c['input']['functions']['raw']),
            lambda c: c['input']['string_fixtures'].update(assign=c['functions']['time_reader']),
            lambda c: c['input']['string_fixtures'].update(free=next(iter(c['leaves']))),
            lambda c: c['input']['string_fixtures'].update(free=c['input']['string_fixtures']['assign']),
        )
        for change in changes:
            c = context();change(c)
            with self.assertRaises(ValueError): TOOL.select('login-strings-buffer').roots(c)

    def test_nested_source_may_be_implicit_but_cannot_contradict_outer_source(self):
        api = TOOL.select('login-strings-buffer');c = context()
        api.roots(c)
        for key, value in (('source_sha256', 'f' * 64), ('source', 'other.exe')):
            c = context();c['input'][key] = value
            with self.assertRaises(ValueError): api.roots(c)

    def test_export_parts_inherit_missing_nested_source_only(self):
        api = TOOL.select('login-strings-buffer');c = context();parts = api.export_parts(c)
        self.assertEqual(parts[0], c)
        self.assertEqual(parts[1]['source'], c['source'])
        self.assertEqual(parts[1]['source_sha256'], c['source_sha256'])
        self.assertNotIn('source', c['input'])
        c['input']['source'] = 'other.exe'
        with self.assertRaises(ValueError): api.export_coverage('root', c, None, None, None)

    def test_generated_input_source_is_a_valid_next_baseline_but_cannot_be_substituted(self):
        rules = TOOL.load('login-input-transfer-rules');c = context();c['input']['source'] = c['source']
        c['constructor_defaults'] = {'0x130': '0x1496731d0', '0x134': '0x14b197560'}
        self.assertEqual(rules.roots('login-strings-buffer', c), TOOL.select('login-strings-buffer').roots(c))
        c['input']['source'] = 'other.exe'
        with self.assertRaises(ValueError): rules.roots('login-strings-buffer', c)


class LoginInputAdmissionTests(unittest.TestCase):
    def test_common_report_checks_provenance_before_family_matrix(self):
        for family in TOOL.FAMILIES:
            api = TOOL.select(family);c = context(family);r = report(c, family)
            validate = Mock()
            with patch.object(api, 'validate_report', validate): api.report_valid(r, c, 'c' * 64)
            validate.assert_called_once_with(r, c)
            changes = [dict(source_sha256='f' * 64), dict(scope='whole-entry'), dict(method='static'),
                dict(proof={}), dict(context_sha256='f' * 64)]
            changes += [{key: value} for key in ('network_used', 'profile_activated', 'runtime_activated') for value in (True, 0, None)]
            for change in changes:
                with patch.object(api, 'validate_report', side_effect=AssertionError('No matrix admission')):
                    with self.assertRaises(ValueError): api.report_valid(dict(r, **change), c, 'c' * 64)

    def test_same_target_reuses_original_proof_without_self_transfer(self):
        api = TOOL.select('login-nested');c = context('login-nested');args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        with patch.object(CORE, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(api, 'published_contexts', return_value=[(Path('ctx'), c, 3)]), \
                patch.object(api, 'validate') as validate, patch.object(CORE, 'checked', return_value={'original': 'proof'}), \
                patch.object(api, 'planned', return_value='reused') as planned, \
                patch.object(api, 'transfer', side_effect=AssertionError('No self transfer')):
            self.assertEqual(api.discover(None, args, c['source_sha256']), 'reused')
        validate.assert_called_once_with(None, args, c);planned.assert_called_once_with(c, {'original': 'proof'})

    def test_published_source_family_layout_and_rank_are_not_interchangeable(self):
        api = TOOL.select('login-nested');c = context('login-nested');r = report(c, api.family)
        row = dict(context=dict(path='ctx', sha256='c' * 64), check=dict(path='report', sha256='d' * 64), order=1)
        registry = dict(releases=[dict(source_sha256=c['source_sha256'], order=3)])
        with patch.object(CORE, 'checked', side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r), \
                patch.object(api, 'report_valid'):
            self.assertEqual(api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))[0][2], 3)
            for value in (dict(schema=1, contexts=[row, row]), dict(schema=1, contexts=[dict(row, order=True)])):
                with self.assertRaises(ValueError): api.published_contexts('root', registry, value=value)
            for key, value in (('family', 'login-strings-buffer'), ('layout', {}), ('source_sha256', 'x')):
                with patch.object(CORE, 'checked', return_value=dict(c, **{key: value})), self.assertRaises(ValueError):
                    api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))

    def test_failed_or_wrong_source_report_does_not_replace_publication(self):
        api = TOOL.select('login-nested');c = context('login-nested');r = report(c, api.family);r['source_sha256'] = 'f' * 64
        with patch.object(CORE, 'checked', side_effect=AssertionError('No publication read')):
            with self.assertRaises(ValueError): api.publish(None, None, 'a' * 64, {}, dict(state='failed'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);path = root / 'knowledge' / api.index / 'index.json'
            path.parent.mkdir(parents=True);path.write_text('existing')
            args = SimpleNamespace(root=root, knowledge=root)
            with patch.object(api, 'validate'), patch.object(CORE, 'checked',
                    side_effect=lambda root, item, category: c if category == 'generated-native-contexts' else r):
                with self.assertRaises(ValueError):
                    api.publish(None, args, c['source_sha256'], dict(context=dict(path='ctx', sha256='c' * 64)),
                        dict(state='passed', report='report', sha256='d' * 64))
            self.assertEqual(path.read_text(), 'existing')

    def test_cross_family_execute_is_stopped_before_native(self):
        api = TOOL.select('login-nested');c = context('login-nested')
        declaration = dict(context=dict(path='ctx', sha256='c' * 64), adapter=api.adapter,
            family='login-strings-buffer', scope=api.scope, dependencies={})
        with patch.object(CORE, 'checked', return_value=c), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'validate', side_effect=AssertionError('No native')):
            with self.assertRaises(ValueError): api.execute(None, SimpleNamespace(root='root'), c['source_sha256'], declaration)

    def test_proof_cycle_and_layout_changes_stop_before_source_lookup(self):
        api = TOOL.select('login-nested');c = context('login-nested');args = SimpleNamespace(root=Path('root'))
        with patch.object(CORE, 'checked', return_value={}), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'cycle'): api.validate(None, args, c, {'b' * 64})
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, c)
        p = proof(c, api, 'baseline');bad = dict(c, layout=dict(api.layout, native_strings=True))
        with patch.object(CORE, 'checked', return_value=p), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, bad)

    def test_changed_dependency_report_is_rejected_before_transfer(self):
        api = TOOL.select('login-nested');c = context('login-nested')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);path = root / 'knowledge/generated-native-contexts/base.json'
            path.parent.mkdir(parents=True);path.write_text(json.dumps(dict(source_sha256='a' * 64)))
            p = proof(c, api, path);p['dependencies'] = dict(result_check=dict(path='report', sha256='e' * 64))
            args = SimpleNamespace(root=root, source_store=Mock())
            with patch.object(CORE, 'checked', return_value=p), patch.object(api, 'tools', return_value={}), \
                    patch.object(CORE, 'digest', return_value='d' * 64), \
                    patch.object(api, 'dependencies', return_value=dict(result_check=dict(path='report', sha256='f' * 64))), \
                    patch.object(api, 'transfer', side_effect=AssertionError('No transfer')):
                with self.assertRaisesRegex(ValueError, 'dependency proof or report'): api.validate(None, args, c)
            args.source_store.image.assert_not_called()

    def test_nested_export_hash_conflict_is_rejected_before_any_export_read(self):
        api = TOOL.select('login-strings-buffer');c = context();run = next(iter(c['exports']))
        c['input']['exports'][run] = 'f' * 64
        with patch.object(CORE, 'digest', side_effect=AssertionError('No file digest')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('No export read')):
            with self.assertRaises(ValueError): api.export_coverage('root', c, None, None, None)

    def test_dependency_proof_and_export_changes_change_plan_key_without_global_index(self):
        api = TOOL.select('login-nested');args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        baseline = dict(source_sha256='a' * 64)
        dependencies = dict(result=dict(path='target-result', sha256='b' * 64), result_check=dict(path='result-check', sha256='c' * 64))
        lineage = {'target-proof': 'd' * 64, 'target-export/details.json': 'e' * 64}
        def materials(args, path): return dict(lineage) if path == 'target-result' else {'result-check': 'c' * 64}
        with patch.object(api, 'baseline_context', return_value=(Path('baseline'), baseline)), \
                patch.object(api, 'dependencies', return_value=dependencies), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'input_materials', side_effect=lambda *args: {'baseline': 'a' * 64}), \
                patch.object(CORE, 'pointer', return_value=dict(path='baseline', sha256='a' * 64)), \
                patch.object(CORE, 'digest', return_value='f' * 64), patch.object(CORE, 'lineage_inputs', side_effect=materials):
            first = api.plan_inputs(None, args, 'f' * 64)
            lineage['target-proof'] = '1' * 64;proof_changed = api.plan_inputs(None, args, 'f' * 64)
            lineage['target-export/details.json'] = '2' * 64;export_changed = api.plan_inputs(None, args, 'f' * 64)
        self.assertNotEqual(first, proof_changed);self.assertNotEqual(proof_changed, export_changed)
        self.assertEqual(set(first['baseline_materials']), {'baseline', 'target-proof', 'target-export/details.json', 'result-check'})
        self.assertFalse(any('index.json' in path for path in first['baseline_materials']))

    def test_strings_dependencies_pin_input_and_independent_nested_reports(self):
        sha = 'a' * 64;args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        input_ = dict(path='input', sha256='b' * 64);input_check = dict(path='input-report', sha256='c' * 64)
        nested = dict(path='nested', sha256='d' * 64);nested_check = dict(path='nested-report', sha256='e' * 64)
        api = TOOL.select('login-strings-buffer');dep = Mock()
        dep.at.return_value = (Path('nested'), dict(transfer_proof=dict(path='proof', sha256='f' * 64)))
        dep.index = 'generated-login-input/login-nested'
        with patch.object(TOOL, 'result_at', return_value=(Path('input'), {})), \
                patch.object(TOOL, 'result_receipt', return_value=dict(check=input_check)), \
                patch.object(CORE, 'pointer', side_effect=lambda p: input_ if str(p) == 'input' else nested), \
                patch.object(TOOL, 'Adapter', return_value=dep), \
                patch.object(TOOL, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(Path, 'read_text', return_value=json.dumps(dict(contexts=[dict(context=nested, check=nested_check)]))):
            result = api.dependencies(None, args, sha)
        self.assertEqual(result, dict(input=input_, input_check=input_check, nested=nested, nested_check=nested_check))
        dep.published_contexts.assert_called_once_with(args.root, {})

    def test_seed_memo_tracks_nested_proofs_exports_and_report_then_copies_mapping(self):
        old = dict(transfer_proof=dict(path='old-proof', sha256='a' * 64))
        target = dict(transfer_proof=dict(path='target-proof', sha256='b' * 64))
        args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'), source_store=Mock())
        api = Mock();api.tools.return_value = {};api.plain.side_effect = lambda value: value
        api.transfer.return_value = (target, dict(mapping={'0x1': '0x2'}))
        lineage = {'target-proof': 'c' * 64, 'target-export': 'd' * 64}
        check = dict(path='check', sha256='e' * 64)
        def inputs(args, path): return {'old': 'a' * 64} if str(path) == 'old' else dict(lineage)
        with patch.object(TOOL, 'load', side_effect=lambda name: api if name == 'update-native-version-result' else Mock()), \
                patch.object(TOOL, 'result_at', side_effect=lambda args, sha: (Path('old'), old) if sha == 'old-sha' else (Path('target'), target)), \
                patch.object(TOOL, 'result_receipt', side_effect=lambda *args: dict(check=dict(check))), \
                patch.object(CORE, 'lineage_inputs', side_effect=inputs), \
                patch.object(CORE, 'pointer', side_effect=lambda path: dict(path=str(path), sha256='f' * 64)):
            result = TOOL.seed(None, args, 'old-sha', 'target-sha');result[1][1] = 100
            self.assertEqual(TOOL.seed(None, args, 'old-sha', 'target-sha')[1], {1: 2})
            self.assertEqual(api.transfer.call_count, 1)
            lineage['target-proof'] = '4' * 64
            TOOL.seed(None, args, 'old-sha', 'target-sha');self.assertEqual(api.transfer.call_count, 2)
            lineage['target-export'] = '5' * 64
            TOOL.seed(None, args, 'old-sha', 'target-sha');self.assertEqual(api.transfer.call_count, 3)
            check['sha256'] = '6' * 64
            TOOL.seed(None, args, 'old-sha', 'target-sha');self.assertEqual(api.transfer.call_count, 4)
            lineage['target-proof'] = '7' * 64;api.validate.side_effect = ValueError('Previous input proof failed')
            with self.assertRaisesRegex(ValueError, 'Previous input proof failed'): TOOL.seed(None, args, 'old-sha', 'target-sha')
            self.assertEqual(api.transfer.call_count, 4)

    def test_seed_requires_independently_equal_target_input(self):
        old = dict(source_sha256='old-sha');target = dict(source_sha256='target-sha')
        args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'), source_store=Mock())
        api = Mock();api.tools.return_value = {};api.plain.side_effect = lambda value: value
        api.transfer.return_value = (dict(source_sha256='wrong-sha'), dict(mapping={'0x1': '0x2'}))
        with patch.object(TOOL, 'load', side_effect=lambda name: api if name == 'update-native-version-result' else Mock()), \
                patch.object(TOOL, 'result_at', side_effect=lambda args, sha: (Path('old'), old) if sha == 'old-sha' else (Path('target'), target)), \
                patch.object(TOOL, 'result_receipt', return_value=dict(check=dict(path='check', sha256='e' * 64))), \
                patch.object(CORE, 'lineage_inputs', side_effect=lambda args, path: {str(path): 'f' * 64}):
            with self.assertRaisesRegex(ValueError, 'independent VersionResult proof'): TOOL.seed(None, args, 'old-sha', 'target-sha')
        self.assertEqual(args._login_input_seed['values'], {})


class LoginInputHarnessAdmissionTests(unittest.TestCase):
    def test_self_declared_family_budget_or_leaf_expansion_cannot_reach_source_admission(self):
        harness = load('verify-login-input-harness');c = context()
        roots = TOOL.select('login-strings-buffer').roots(c)
        leaves = {int(at, 16): raw for at, raw in c['leaves'].items()}
        changes = (dict(family='login-input'), dict(function_budget=20.0), dict(function_budget=21),
            dict(transfer_proof=None), dict(native_admission=True))
        with patch.object(harness, 'load', side_effect=AssertionError('No proof/source admission')):
            for change in changes:
                with self.assertRaises(ValueError): harness.admit(dict(c, **change), 'root', roots, leaves, c['exports'])
            with self.assertRaises(ValueError): harness.admit(c, 'root', roots | {0x140000000}, leaves, c['exports'])
            with self.assertRaises(ValueError): harness.admit(c, 'root', roots, leaves | {0x140000000: 'c3'}, c['exports'])
            with self.assertRaises(ValueError): harness.admit(c, 'root', roots, leaves, {})

    def test_exact_scope_still_requires_adapter_validation_and_source_integrity(self):
        harness = load('verify-login-input-harness');c = context();roots = TOOL.select('login-strings-buffer').roots(c)
        leaves = {int(at, 16): raw for at, raw in c['leaves'].items()};adapter = Mock();adapter.roots.return_value = roots
        source = Mock();index = Mock()
        def module(name, path):
            if Path(path).name == 'knowledge-index.py': return SimpleNamespace(api=lambda: index)
            if Path(path).name == 'update-native-login-input.py': return SimpleNamespace(select=lambda family: adapter)
            if Path(path).name == 'update-bindings.py': return SimpleNamespace(SourceStore=lambda *args: source)
            raise AssertionError('Unreviewed dependency')
        with patch.object(harness, 'load', side_effect=module):
            harness.admit(c, 'root', roots, leaves, c['exports'])
            adapter.validate.assert_called_once();source.validate.assert_called_once()
            adapter.validate.side_effect = ValueError('Target proof changed');source.validate.reset_mock()
            with self.assertRaisesRegex(ValueError, 'Target proof changed'): harness.admit(c, 'root', roots, leaves, c['exports'])
            source.validate.assert_not_called()


if __name__ == '__main__':
    unittest.main()
