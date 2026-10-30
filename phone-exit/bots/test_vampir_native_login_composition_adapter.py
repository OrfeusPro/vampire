"""New composition admission cannot borrow or widen the child semantic scopes."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from test_vampir_update_contracts import load

TOOL = load('update-native-login-composition')


def context():
    return json.loads((TOOL.HERE / 'knowledge/native-contexts/login-response-composition-11322.json').read_text('utf-8'))


class CompositionAdapterTests(unittest.TestCase):
    def test_proved_composition_replaces_same_source_bootstrap_and_follows_latest_proved_role(self):
        api = TOOL.select(); seed = (Path('G:/seed'), {}, 11322)
        proved = (Path('F:/proved'), dict(transfer_proof={'sha256': 'a' * 64}), 11322)
        newer = (Path('F:/newer'), dict(transfer_proof={'sha256': 'b' * 64}), 11324)
        unproved = (Path('G:/candidate'), {}, 11325)
        for rows, expected in (([seed], seed), ([seed, proved], proved), ([seed, proved, newer], newer),
                               ([seed, proved, unproved], proved)):
            with patch.object(api, 'contexts', return_value=rows):
                self.assertEqual(api.baseline_context(None), expected[:2])

    def test_scope_keeps_same_packet_separate_from_dispatch_services_and_session(self):
        api = TOOL.select(); c = context()
        self.assertEqual(len(api.roots(c)), 22)
        self.assertEqual(api.layout['packet_bytes'], 352)
        for key in ('native_reader', 'native_handler', 'native_gate'): self.assertIs(api.layout[key], True)
        for key in ('native_dispatch', 'native_post_state', 'native_continuation', 'real_services', 'session_executed'):
            self.assertIs(api.layout[key], False)
        for family in ('login-full-handler', '../composition', None):
            with self.assertRaises(ValueError): TOOL.select(family)

    def test_dependency_role_is_closed_before_reading_anything(self):
        with patch.object(TOOL, 'load', side_effect=AssertionError('No arbitrary module')):
            with self.assertRaises(ValueError): TOOL.dependency(None, 'dispatch', 'a' * 64)

    def test_dependency_needs_portable_proof_and_a_published_semantic_report(self):
        tool = Mock(); tool.at.return_value = (Path('child'), {})
        args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        with patch.object(TOOL, 'load', return_value=SimpleNamespace(select=lambda _: tool)):
            with self.assertRaisesRegex(ValueError, 'target proof'): TOOL.dependency(args, 'reader', 'a' * 64)
        tool.at.return_value = (Path('child'), dict(transfer_proof=dict(path='proof', sha256='b' * 64)))
        tool.index = 'generated-child'
        def module(name):
            return SimpleNamespace(select=lambda _: tool) if name == 'update-native-login-input' else SimpleNamespace(read=lambda _: {})
        with patch.object(TOOL, 'load', side_effect=module), patch.object(TOOL.core, 'pointer', return_value=dict(path='child', sha256='c' * 64)), \
                patch.object(Path, 'read_text', return_value=json.dumps(dict(contexts=[]))):
            with self.assertRaisesRegex(ValueError, 'semantic report'): TOOL.dependency(args, 'reader', 'a' * 64)

    def test_report_from_whole_handler_cannot_admit_composition(self):
        api = TOOL.select(); c = context(); c['transfer_proof'] = dict(path='proof', sha256='b' * 64)
        report = dict(source_sha256=c['source_sha256'], scope='bounded_native_login_full_handler', method='bounded_native',
            proof=c['transfer_proof'], context_sha256='c' * 64, network_used=False, profile_activated=False, runtime_activated=False)
        with patch.object(api, 'validate_report', side_effect=AssertionError('Wrong scope before semantics')):
            with self.assertRaisesRegex(ValueError, 'provenance or scope'): api.report_valid(report, c, 'c' * 64)

    def test_changed_child_requires_new_plan_inputs(self):
        api = TOOL.select(); args = SimpleNamespace(root=Path('root'), knowledge=Path('defs'))
        dependencies = {'reader': dict(path='reader', sha256='b' * 64)}
        with patch.object(api, 'baseline_context', return_value=(Path('baseline'), dict(source_sha256='a' * 64))), \
                patch.object(api, 'dependencies', side_effect=lambda *a: copy.deepcopy(dependencies)), \
                patch.object(api, 'input_materials', return_value={}), patch.object(api, 'tools', return_value={}), \
                patch.object(TOOL.core, 'pointer', return_value=dict(path='baseline', sha256='c' * 64)), \
                patch.object(TOOL.core, 'lineage_inputs', return_value={}), patch.object(TOOL.core, 'digest', return_value='d' * 64):
            first = api.plan_inputs(None, args, 'e' * 64); dependencies['reader']['sha256'] = 'f' * 64
            self.assertNotEqual(first, api.plan_inputs(None, args, 'e' * 64))

    def test_relocated_child_disagreement_is_blocked_before_composition(self):
        api = TOOL.select(); c = context(); target = dict(source_sha256=c['source_sha256'], changed=False)
        tool = Mock(); tool.transfer.return_value = (dict(target, changed=True), dict(mapping={}))
        store = object(); memo = {'direction': 'another source pair'}
        args = SimpleNamespace(root=Path('root'), source_store=store, _login_input_seed=memo)
        with patch.object(api, 'roots'), patch.object(TOOL.core, 'checked', return_value=target), \
                patch.object(TOOL.core, 'pointer', return_value=dict(path='target', sha256='c' * 64)), \
                patch.object(TOOL, 'dependency', return_value=(tool, Path('target'), target, {})):
            with self.assertRaisesRegex(ValueError, 'relocated child differs'): api.transfer(None, args, c, c['source_sha256'])
        transfer_args = tool.transfer.call_args.args[1]
        self.assertIsNot(transfer_args, args); self.assertIs(transfer_args.source_store, store)
        self.assertFalse(hasattr(transfer_args, '_login_input_seed')); self.assertIs(args._login_input_seed, memo)

    def test_identical_published_children_are_validated_and_reused_without_self_transfer(self):
        api = TOOL.select(); c = context(); source = dict(source_sha256=c['source_sha256'])
        tools = {role: Mock() for role in ('reader', 'handler')}
        for tool in tools.values(): tool.transfer.side_effect = AssertionError('No self-transfer of proved dependency')
        def child(args, role, sha):
            return tools[role], Path(c[role+'_context']['path']), source, {'report': role}
        compose = SimpleNamespace(compose=lambda *a: dict(c))
        original = TOOL.load
        with patch.object(api, 'roots'), patch.object(TOOL.core, 'checked', return_value=source), \
                patch.object(TOOL.core, 'pointer', side_effect=lambda p: next(c[role+'_context'] for role in tools if str(p)==str(Path(c[role+'_context']['path'])))), \
                patch.object(TOOL, 'dependency', side_effect=child), \
                patch.object(TOOL, 'load', side_effect=lambda n: compose if n=='login-composition-rules' else original(n)):
            result, relation = api.transfer(None, SimpleNamespace(root=Path('root')), c, c['source_sha256'])
        for role, tool in tools.items():
            tool.validate.assert_called_once(); tool.transfer.assert_not_called()
            self.assertEqual(relation['children'][role]['method'], 'reuse_identical_checked_context')
        self.assertEqual(result['layout'], api.layout); self.assertNotIn('exports', result)


if __name__ == '__main__': unittest.main()
