"""Точная матрица и отказ в неверном допуске; строки здесь синтетические."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract, oracle = load('service-lifecycle-case-contracts'), load('service-lifecycle-oracle')


def fixture_context():
    return dict(family=contract.FAMILY, format=contract.FORMAT, source_sha256='a' * 64,
        backend_context=dict(path='fixture-backend', sha256='b' * 64),
        backend_check=dict(path='fixture-backend-check', sha256='c' * 64), **contract.EXTENTS)


def fixture_report():
    context = fixture_context()
    rows = [oracle.expected_case(spec) for spec in contract.scenarios()]
    return dict(schema=1, method='bounded_native', scope=contract.SCOPE,
        source_sha256=context['source_sha256'], backend_context=context['backend_context'],
        backend_check=context['backend_check'], cases=rows, matrix_sha256=contract.matrix_sha256(),
        summary=contract.observed_summary(rows), **contract.EXTENTS,
        **dict.fromkeys(contract.TRUE_FLAGS, True), **dict.fromkeys(contract.FALSE_FLAGS, False))


class ServiceLifecycleMatrixTests(unittest.TestCase):
    def test_exact_42_semantic_cases_84_rounds_and_honest_entry_counts(self):
        specs = contract.scenarios()
        self.assertEqual(len(specs), 42)
        self.assertEqual(len({s['case_id'] for s in specs}), 42)
        groups = ('assignment_lifecycle', 'control_move_release', 'deleting_flags',
                  'reset_and_ring_ownership', 'constructor_registration_branches')
        self.assertEqual([sum(s['group'] == g for s in specs) for g in groups], [12, 10, 6, 6, 8])
        self.assertEqual(contract.matrix_sha256(),
                         '51398ac6c7fe410a4ffd14862772d216a9313f3fc5af75a17b504a4cd5f2996d')
        summary = fixture_report()['summary']
        self.assertEqual((summary['cases'], summary['rounds'], summary['native_entries'],
            summary['native_calls']), (42, 84, 230, 972))
        self.assertEqual((summary['native_allocations'], summary['native_frees'],
            summary['atomic_transitions'], summary['callback_copies']), (456, 344, 116, 20))

    def test_poison_rounds_are_distinct_inputs_not_extra_semantic_cases(self):
        for spec in contract.scenarios():
            self.assertEqual(spec['rounds'], list(contract.POISONS))
            self.assertEqual(spec['cleanup_find'], 'end')
            self.assertNotEqual(spec['rounds'][0], spec['rounds'][1])
            contract.validate_spec(spec)
        changed = contract.scenarios()
        changed[0]['rounds'][0]['allocator_poison'] = 0
        self.assertEqual(contract.scenarios()[0]['rounds'][0]['allocator_poison'], 0x5a)

    def test_local_spare_branch_is_absent_after_native_base_zero_capacity(self):
        rows = [s for s in contract.scenarios() if s['group'] == 'constructor_registration_branches']
        self.assertFalse(any('spare' in s['iterator_fixture']['name'] for s in rows))
        for spec in rows:
            profile = spec['iterator_fixture']
            if profile['local'] == 'end':
                self.assertIn('local', profile['reserve'])
        mixed = next(s for s in rows if s['iterator_fixture']['name'] == 'both_insert_mixed')
        self.assertEqual(mixed['iterator_fixture']['reserve'], ['local'])

    def test_wrong_types_fields_round_order_and_entry_are_rejected(self):
        for mutation in ('extra', 'round-type', 'round-order', 'group', 'old'):
            spec = contract.scenarios()[0]
            if mutation == 'extra':
                spec['manual_cleanup'] = True
            elif mutation == 'round-type':
                spec['rounds'][0]['allocator_poison'] = 90.0
            elif mutation == 'round-order':
                spec['rounds'].reverse()
            elif mutation == 'group':
                spec['group'] = 'control_move_release'
            else:
                spec['old_backend'] = 'foreign'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.validate_spec(spec)


class ServiceLifecycleAdmissionTests(unittest.TestCase):
    def test_complete_synthetic_report_validates_as_test_data_only(self):
        contract.validate_report(fixture_report(), fixture_context())

    def test_wrong_scope_flags_dependency_extent_and_summary_are_rejected(self):
        for key, value in (('native_service_assignment_used', False), ('native_control_dispatch_used', 1),
                ('native_callback_destructor_used', True), ('native_socket_used', True),
                ('native_concurrent_lifetime_used', True), ('source_sha256', 'bad'),
                ('backend_bytes', 784), ('control_bytes', 24.0), ('summary', {}),
                ('backend_check', dict(path='foreign', sha256='d' * 64)), ('schema', True)):
            report = fixture_report()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.validate_report(report, fixture_context())

    def test_reordering_duplicate_round_and_counter_forgery_are_rejected(self):
        for mutation in ('row-order', 'duplicate', 'missing-round', 'round-order', 'atomic', 'retained'):
            report = fixture_report()
            if mutation == 'row-order':
                report['cases'][0], report['cases'][1] = report['cases'][1], report['cases'][0]
            elif mutation == 'duplicate':
                report['cases'][1] = copy.deepcopy(report['cases'][0])
            elif mutation == 'missing-round':
                report['cases'][0]['observation']['rounds'].pop()
            elif mutation == 'round-order':
                report['cases'][0]['observation']['rounds'].reverse()
            elif mutation == 'atomic':
                report['cases'][0]['observation']['rounds'][0]['atomic_transitions'][0]['after'] = 1
            else:
                report['cases'][0]['observation']['rounds'][0]['retained_owners'] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.validate_report(report, fixture_context())


if __name__ == '__main__':
    unittest.main()
