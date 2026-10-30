"""Response-family lifecycle, typed gate boundary and source admission guards."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

TOOL = load('update-native-response')
CORE = TOOL.core
BASE = {'result-gate': 'result-gate-11320.json', 'login-post-state': 'login-post-state-11318.json'}


def context(family='result-gate'):
    c = json.loads((TOOL.HERE / 'knowledge/native-contexts' / BASE[family]).read_text('utf-8'))
    api = TOOL.select(family)
    c.update(family=family, layout=copy.deepcopy(api.layout), transfer_proof=dict(path='proof', sha256='b' * 64))
    return c


class ResponseAdapterTests(unittest.TestCase):
    def test_independent_roles_and_latest_reviewed_bases(self):
        self.assertEqual(TOOL.FAMILIES, ('result-gate', 'login-post-state'))
        apis = [TOOL.select(f) for f in TOOL.FAMILIES]
        self.assertEqual(len({a.index for a in apis}), 2)
        self.assertEqual([a.layout['executed_roots'] for a in apis], [1, 2])
        self.assertTrue(all(a.layout['full_handler'] is False for a in apis))
        self.assertNotEqual(context()['source_sha256'], context('login-post-state')['source_sha256'])
        for invalid in ('response', 'all', '../custom', None, []):
            with self.assertRaises(ValueError): TOOL.select(invalid)

    def test_explicit_root_sets_and_no_implicit_scope_expansion(self):
        for family in TOOL.FAMILIES:
            c = context(family); api = TOOL.select(family)
            self.assertEqual(len(api.roots(c)), api.layout['executed_roots'])
            c['function_budget'] = 20
            with self.assertRaises(ValueError): api.roots(c)

    def test_gate_uses_only_typed_export_coverage_not_linear_unwind_decoder(self):
        api = TOOL.select('result-gate'); c = context(); checker = Mock(return_value='typed')
        with patch.object(TOOL, 'load', return_value=SimpleNamespace(export_coverage=checker)), \
                patch.object(CORE.Family, 'export_coverage', side_effect=AssertionError('Inline data is not linear code')):
            self.assertEqual(api.export_coverage('root', c, 'native', 'bindings', 'image'), 'typed')
        checker.assert_called_once_with('root', c, 'native', 'bindings', 'image')

    def test_post_state_keeps_normal_whole_root_export_guard(self):
        api = TOOL.select('login-post-state'); c = context('login-post-state')
        with patch.object(CORE.Family, 'export_coverage', return_value='whole') as checker:
            self.assertEqual(api.export_coverage('root', c, 'native', 'bindings', 'image'), 'whole')
        checker.assert_called_once_with('root', c, 'native', 'bindings', 'image')

    def test_reports_require_exact_source_scope_proof_and_no_activation(self):
        for family in TOOL.FAMILIES:
            api = TOOL.select(family); c = context(family)
            r = dict(source_sha256=c['source_sha256'], scope=api.scope, method='bounded_native',
                proof=c['transfer_proof'], context_sha256='c' * 64,
                network_used=False, profile_activated=False, runtime_activated=False)
            with patch.object(api, 'validate_report') as validate:
                api.report_valid(r, c, 'c' * 64); validate.assert_called_once_with(r, c)
            changes = [dict(source_sha256='a' * 64), dict(scope='whole-login'), dict(method='static'), dict(proof={}), dict(context_sha256='d' * 64)]
            changes += [{key: value} for key in ('network_used', 'profile_activated', 'runtime_activated') for value in (True, 0, None)]
            for change in changes:
                with patch.object(api, 'validate_report', side_effect=AssertionError('No semantic admission')):
                    with self.assertRaises(ValueError): api.report_valid(dict(r, **change), c, 'c' * 64)

    def test_same_target_uses_original_proof_without_self_transfer(self):
        api = TOOL.select('result-gate'); c = context(); args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        with patch.object(CORE, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(api, 'published_contexts', return_value=[(Path('ctx'), c, 3)]), \
                patch.object(api, 'validate') as validate, patch.object(CORE, 'checked', return_value={'original': 'proof'}), \
                patch.object(api, 'planned', return_value='reused'), \
                patch.object(api, 'transfer', side_effect=AssertionError('No self-transfer')):
            self.assertEqual(api.discover(None, args, c['source_sha256']), 'reused')
        validate.assert_called_once_with(None, args, c)

    def test_cross_family_execute_rejected_before_native(self):
        api = TOOL.select('result-gate'); c = context()
        declaration = dict(context={}, adapter=api.adapter, family='login-post-state', scope=api.scope, dependencies={})
        with patch.object(CORE, 'checked', return_value=c), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'validate', side_effect=AssertionError('No native')):
            with self.assertRaises(ValueError): api.execute(None, SimpleNamespace(root=Path('root')), c['source_sha256'], declaration)

    def test_proof_cycles_and_changed_layout_fail_before_source_lookup(self):
        api = TOOL.select('result-gate'); c = context(); args = SimpleNamespace(root=Path('root'))
        with patch.object(CORE, 'checked', return_value={}), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'cycle'): api.validate(None, args, c, {'b' * 64})
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, c)

    def test_publication_rejects_duplicate_source_and_foreign_family_or_layout(self):
        api = TOOL.select('result-gate'); c = context()
        row = dict(context=dict(path='ctx', sha256='c' * 64), check=dict(path='report', sha256='d' * 64), order=1)
        registry = dict(releases=[dict(source_sha256=c['source_sha256'], order=3)])
        with patch.object(CORE, 'checked', return_value=c), patch.object(api, 'report_valid'):
            self.assertEqual(len(api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))), 1)
            for rows in ([row, row], [dict(row, order=True)]):
                with self.assertRaises(ValueError): api.published_contexts('root', registry, value=dict(schema=1, contexts=rows))
            for change in (dict(family='login-post-state'), dict(layout={})):
                with patch.object(CORE, 'checked', return_value=dict(c, **change)):
                    with self.assertRaises(ValueError): api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))

    def test_cache_inputs_pin_actual_baseline_lineage_without_global_index(self):
        api = TOOL.select('result-gate'); args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        files = {'gate-export': 'a' * 64}
        with patch.object(api, 'baseline_context', return_value=(Path('baseline'), {})), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'input_materials', side_effect=lambda *a: dict(files)), \
                patch.object(CORE, 'pointer', return_value=dict(path='baseline', sha256='c' * 64)), patch.object(CORE, 'digest', return_value='d' * 64):
            first = api.plan_inputs(None, args, 'f' * 64); files['gate-export'] = 'b' * 64
            second = api.plan_inputs(None, args, 'f' * 64)
        self.assertNotEqual(first, second)
        self.assertEqual(set(first['baseline_materials']), {'gate-export'})


if __name__ == '__main__': unittest.main()
