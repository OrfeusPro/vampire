"""Whole Login handler lifecycle guards, without native replay."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

TOOL = load('update-native-login-full')
CORE = TOOL.core


def context(family='login-full-handler'):
    c = json.loads((TOOL.HERE / 'knowledge/native-contexts' / (family + '-11318.json')).read_text('utf-8'))
    api = TOOL.select(family)
    c.update(family=family, layout=copy.deepcopy(api.layout), transfer_proof=dict(path='proof', sha256='b' * 64))
    return c


def report(c, api):
    return dict(source_sha256=c['source_sha256'], scope=api.scope, method='bounded_native',
        network_used=False, profile_activated=False, runtime_activated=False, proof=c['transfer_proof'], context_sha256='c' * 64)


class FullHandlerAdapterTests(unittest.TestCase):
    def test_current_handler_scope_executes_gate_and_keeps_reader_and_services_separate(self):
        self.assertEqual(TOOL.FAMILY, 'login-full-handler')
        apis = [TOOL.select(f) for f in (TOOL.FAMILY,)]
        self.assertEqual(len({a.index for a in apis}), 1)
        self.assertEqual([a.layout['executed_roots'] for a in apis], [2])
        for a in apis:
            self.assertIs(a.layout['native_gate'], True)
            self.assertIs(a.layout['native_reader'], False)
            self.assertIs(a.layout['real_services'], False)
        for name in ('login-result-handler', '../custom', None, []):
            with self.assertRaises(ValueError): TOOL.select(name)

    def test_roots_exact_and_fixture_cannot_shadow_native(self):
        for family in (TOOL.FAMILY,):
            api = TOOL.select(family); c = context(family)
            self.assertEqual(len(api.roots(c)), api.layout['executed_roots'])
            bad = copy.deepcopy(c); bad['functions']['extra'] = '0x140001000'
            with self.assertRaises(ValueError): api.roots(bad)
            bad = copy.deepcopy(c); bad['function_budget'] = 20
            with self.assertRaises(ValueError): api.roots(bad)

    def test_report_provenance_rejects_wrong_source_scope_proof_and_activations(self):
        for family in (TOOL.FAMILY,):
            api = TOOL.select(family); c = context(family); r = report(c, api)
            with patch.object(api, 'validate_report') as validator:
                api.report_valid(r, c, 'c' * 64); validator.assert_called_once_with(r, c)
            changes = [dict(source_sha256='e' * 64), dict(scope='full-entry'), dict(method='static'),
                dict(proof={}), dict(context_sha256='d' * 64)]
            changes += [{key: value} for key in ('network_used', 'profile_activated', 'runtime_activated') for value in (True, 0, None)]
            for change in changes:
                with patch.object(api, 'validate_report', side_effect=AssertionError('No semantic admission')):
                    with self.assertRaises(ValueError): api.report_valid(dict(r, **change), c, 'c' * 64)

    def test_same_source_discovery_retains_original_transfer_proof(self):
        api = TOOL.select('login-full-handler'); c = context(); args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        with patch.object(CORE, 'load', return_value=SimpleNamespace(read=lambda _: {})), \
                patch.object(api, 'published_contexts', return_value=[(Path('ctx'), c, 3)]), \
                patch.object(api, 'validate') as validate, patch.object(CORE, 'checked', return_value={'original': 'proof'}), \
                patch.object(api, 'planned', return_value='cached'), \
                patch.object(api, 'transfer', side_effect=AssertionError('No self-transfer')):
            self.assertEqual(api.discover(None, args, c['source_sha256']), 'cached')
        validate.assert_called_once_with(None, args, c)

    def test_cross_family_execute_rejected_before_native(self):
        api = TOOL.select('login-full-handler'); c = context()
        declaration = dict(context={}, family='foreign-handler', adapter=api.adapter, scope=api.scope, dependencies={})
        with patch.object(CORE, 'checked', return_value=c), patch.object(api, 'tools', return_value={}), \
                patch.object(api, 'validate', side_effect=AssertionError('No native')):
            with self.assertRaises(ValueError): api.execute(None, SimpleNamespace(root=Path('root')), c['source_sha256'], declaration)

    def test_proof_cycle_and_layout_change_rejected_before_source_lookup(self):
        api = TOOL.select('login-full-handler'); c = context(); args = SimpleNamespace(root=Path('root'))
        with patch.object(CORE, 'checked', return_value={}), patch.object(api, 'tools', return_value={}):
            with self.assertRaisesRegex(ValueError, 'cycle'): api.validate(None, args, c, {'b' * 64})
            with self.assertRaisesRegex(ValueError, 'tools/fields/layout'): api.validate(None, args, c)

    def test_publication_rejects_bad_schema_duplicate_source_or_wrong_scope(self):
        api = TOOL.select('login-full-handler'); c = context(); r = report(c, api)
        row = dict(context=dict(path='ctx', sha256='c' * 64), check=dict(path='report', sha256='d' * 64), order=1)
        registry = dict(releases=[dict(source_sha256=c['source_sha256'], order=3)])
        with patch.object(CORE, 'checked', side_effect=lambda root, p, cat: c if cat == 'generated-native-contexts' else r), \
                patch.object(api, 'report_valid'):
            self.assertEqual(len(api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))), 1)
            for value in (dict(schema=2, contexts=[row]), dict(schema=1, contexts=[row, row]), dict(schema=1, contexts=[dict(row, order=True)])):
                with self.assertRaises(ValueError): api.published_contexts('root', registry, value=value)
            with patch.object(CORE, 'checked', return_value=dict(c, family='foreign-handler')):
                with self.assertRaises(ValueError): api.published_contexts('root', registry, value=dict(schema=1, contexts=[row]))

    def test_failed_semantic_report_cannot_overwrite_index(self):
        api = TOOL.select('login-full-handler')
        with patch.object(CORE, 'checked', side_effect=AssertionError('No publication read')):
            with self.assertRaises(ValueError): api.publish(None, None, 'a' * 64, {}, dict(state='failed'))

    def test_export_provenance_is_a_single_explicit_part(self):
        for family in (TOOL.FAMILY,):
            c = context(family); self.assertEqual(TOOL.select(family).export_parts(c), [c])

    def test_changed_baseline_export_changes_plan_inputs(self):
        api = TOOL.select('login-full-handler'); args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        materials = {'baseline-export': 'd' * 64}
        with patch.object(api, 'dependencies', return_value={}), patch.object(api, 'baseline_context', return_value=(Path('baseline'), {'source_sha256': 'a' * 64})), \
                patch.object(api, 'tools', return_value={}), patch.object(api, 'input_materials', side_effect=lambda *a: dict(materials)), \
                patch.object(CORE, 'pointer', return_value=dict(path='baseline', sha256='c' * 64)), patch.object(CORE, 'digest', return_value='e' * 64):
            first = api.plan_inputs(None, args, 'f' * 64); materials['baseline-export'] = '1' * 64
            second = api.plan_inputs(None, args, 'f' * 64)
        self.assertNotEqual(first, second)

    def test_unsupported_dependencies_are_rejected_before_any_read(self):
        with patch.object(TOOL, 'load', side_effect=AssertionError('No arbitrary module')):
            with self.assertRaises(ValueError): TOOL.dependency(None, 'unknown', 'a' * 64)

    def test_target_dependencies_require_proof_and_semantic_publication(self):
        tool = Mock(); tool.at.return_value = (Path('context'), {})
        with patch.object(TOOL, 'load', return_value=SimpleNamespace(select=lambda _: tool)):
            with self.assertRaisesRegex(ValueError, 'target proof'):
                TOOL.dependency(SimpleNamespace(root=Path('root'), knowledge=Path('defs')), 'result-gate', 'a' * 64)
        c = dict(transfer_proof=dict(path='proof', sha256='b' * 64)); tool.at.return_value = (Path('context'), c)
        tool.index = 'generated-responses/result-gate'
        def module(name):
            return SimpleNamespace(select=lambda _: tool) if name == 'update-native-response' else SimpleNamespace(read=lambda _: {})
        with patch.object(TOOL, 'load', side_effect=module), patch.object(CORE, 'pointer', return_value={'path': 'context', 'sha256': 'c' * 64}), \
                patch.object(Path, 'read_text', return_value=json.dumps(dict(contexts=[]))):
            with self.assertRaisesRegex(ValueError, 'published report'):
                TOOL.dependency(SimpleNamespace(root=Path('root'), knowledge=Path('defs')), 'result-gate', 'a' * 64)


if __name__ == '__main__': unittest.main()
