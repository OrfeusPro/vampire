"""Post-state matrices retain ordered events, raw RAX and tail/store provenance."""
import copy
import json
import unittest

from test_vampir_update_contracts import load, HERE

TOOL = load('post-state-case-contracts')


def context():
    return json.loads((HERE / 'knowledge/native-contexts/login-post-state-11318.json').read_text('utf-8'))


def report(c=None):
    c = c or context()
    return dict(schema=1, source_sha256=c['source_sha256'], method='bounded_native',
        cases=TOOL.expected_rows(c), tail_calls=copy.deepcopy(c['tail_calls']), native_post_state_used=True,
        network_used=False, profile_activated=False, runtime_activated=False, backend_used=False, full_handler_executed=False)


class PostStateMatrixTests(unittest.TestCase):
    def test_matrix_retains_thirty_two_wrapper_and_twelve_boundary_cases(self):
        matrix = TOOL.matrix()
        self.assertEqual(TOOL.case_count(), 44);self.assertEqual(len(matrix), 44)
        self.assertEqual(sum(direct for direct, _ in matrix), 4)
        self.assertEqual(len({TOOL.canonical([d, s]) for d, s in matrix}), 44)
        TOOL.validate_report(report(), context())

    def test_raw_register_contract_is_not_boolean_success(self):
        c = context();rows = TOOL.expected_rows(c)
        self.assertEqual([rows[i]['returned'] for i in (32, 33, 34, 35, 36, 37, 41, 42, 43)],
            [0, 0x28003030, 0x28003030, 0x28001000, 0x28001000, 0, 0, 0, 0])
        bad = report(c);bad['cases'][35]['returned'] = 0
        with self.assertRaisesRegex(ValueError, 'raw return'): TOOL.validate_report(bad, c)

    def test_list_path_and_eligible_fallback_keep_distinct_store_instructions(self):
        c = context();origin = int(c['functions']['target'], 16);rows = TOOL.expected_rows(c)
        self.assertEqual(rows[0]['writes'][0]['instruction'], hex(origin + 356))
        self.assertEqual(rows[1]['writes'][0]['instruction'], hex(origin + 338))
        self.assertEqual(rows[2]['writes'][0]['instruction'], hex(origin + 211))
        self.assertEqual(rows[38]['writes'][0]['instruction'], hex(origin + 356))
        self.assertEqual(rows[39]['writes'][0]['instruction'], hex(origin + 338))
        self.assertEqual(rows[1]['events'][-4:], ['virtual_0x4c8', 'virtual_0x540', 'virtual_0x2e8', 'mark'])
        self.assertEqual(rows[2]['events'][-2:], ['virtual_0x2e8', 'virtual_0x540'])

    def test_direct_zero_flag_skips_list_match_and_tail_preserves_stack(self):
        rows = TOOL.expected_rows(context());direct = rows[40]
        self.assertNotIn('list_match', direct['events'])
        self.assertIn('settle', direct['events']);self.assertEqual(direct['target_entry'], [dict(service=True, actor=True, flag=0, stack=0x38000)])
        for row in rows:
            for entry in row['target_entry']: self.assertEqual(entry['stack'], 0x38000)

    def test_exact_dimensions_reject_missing_duplicate_or_reordered_case(self):
        for change in (lambda rows: rows.pop(), lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])), lambda rows: rows.reverse()):
            r = report();change(r['cases'])
            with self.assertRaises(ValueError): TOOL.validate_report(r, context())

    def test_weak_boolean_numeric_types_and_changed_settings_are_rejected(self):
        for field, value in (('direct', 0), ('returned', True), ('initial_rax', False), ('guards', 1), ('abi', None), ('arguments_checked', 1)):
            r = report();r['cases'][0][field] = value
            with self.assertRaises(ValueError): TOOL.validate_report(r, context())
        r = report();r['cases'][0]['settings']['predicate'] = 0
        with self.assertRaises(ValueError): TOOL.validate_report(r, context())

    def test_events_writes_and_argument_projection_must_all_match(self):
        changes = (lambda r: r['cases'][0]['events'].remove('assign'),
            lambda r: r['cases'][0]['events'].append('mark'),
            lambda r: r['cases'][0]['writes'][0].update(value=1),
            lambda r: r['cases'][0]['writes'][0].update(size=4),
            lambda r: r['cases'][0]['target_entry'][0].update(stack=0x38008),
            lambda r: r['cases'][0]['target_entry'][0].update(flag=0))
        for change in changes:
            r = report();change(r)
            with self.assertRaises(ValueError): TOOL.validate_report(r, context())

    def test_scope_schema_source_and_tail_are_checked_independently(self):
        changes = [dict(schema=True), dict(method='static'), dict(source_sha256='f' * 64), dict(tail_calls=[]), dict(native_post_state_used=1)]
        changes += [{key: value} for key in ('network_used', 'profile_activated', 'runtime_activated', 'backend_used', 'full_handler_executed') for value in (True, 0, None)]
        for change in changes:
            with self.assertRaises(ValueError): TOOL.validate_report(dict(report(), **change), context())

    def test_write_instruction_and_tail_are_relocated_with_context(self):
        c = context();c['functions']['target'] = '0x144000000';r = report(c)
        TOOL.validate_report(r, c)
        self.assertEqual(r['cases'][0]['writes'][0]['instruction'], hex(0x144000000 + 356))
        old = report()
        with self.assertRaises(ValueError): TOOL.validate_report(old, c)


class PostStatePortableAdmissionTests(unittest.TestCase):
    def test_family_name_or_self_declared_budget_never_grants_native_admission(self):
        from unittest.mock import patch
        verifier = load('verify-post-state-context')
        for c in (context(), dict(context(), family='login-post-state'),
                dict(context(), family='login-post-state', transfer_proof={'path': 'p'}, function_budget=2)):
            with patch.object(verifier, 'load', side_effect=AssertionError('No native/tool load')):
                with self.assertRaises(ValueError): verifier.admit(c, 'root')

    def test_adapter_proof_and_source_barrier_are_required_before_harness(self):
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        verifier = load('verify-post-state-context');adapter = Mock();adapter.roots.return_value = {1, 2}
        store = Mock();c = dict(context(), family='login-post-state', transfer_proof={'path': 'p'})
        modules = {'knowledge-index': SimpleNamespace(api=lambda: 'index'),
            'update-bindings': SimpleNamespace(SourceStore=lambda *args: store),
            'update-native-response': SimpleNamespace(select=lambda family: adapter)}
        with patch.object(verifier, 'load', side_effect=lambda name: modules[name]):
            verifier.admit(c, Path('root'));adapter.validate.assert_called_once();store.validate.assert_called_once()
            adapter.validate.side_effect = ValueError('Proof changed');store.validate.reset_mock()
            with self.assertRaisesRegex(ValueError, 'Proof changed'): verifier.admit(c, Path('root'))
            store.validate.assert_not_called()


if __name__ == '__main__': unittest.main()
