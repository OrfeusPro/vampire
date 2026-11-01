"""Pure frozen-matrix/admission tests; synthetic rows are not native evidence."""
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


contract, oracle = load('buffer-transport-case-contracts'), load('buffer-transport-oracle')


def fixture_context():
    return dict(family=contract.FAMILY, format=contract.FORMAT, source_sha256='a' * 64,
        wire_context=dict(path='fixture-wire', sha256='b' * 64),
        wire_check=dict(path='fixture-wire-check', sha256='c' * 64),
        functions={'archive.raw': '0x140001000', 'vector.resize': '0x140002000'},
        source_inputs=dict(archive_table=dict(address='0x140003000', bytes='00' * 248)),
        leaves={'0x140004000': '895108c3'}, **contract.EXTENTS)


def fixture_report():
    context = fixture_context()
    rows = [oracle.expected_case(spec) for spec in contract.scenarios()]
    return dict(schema=1, method='bounded_native', scope=contract.SCOPE,
        source_sha256=context['source_sha256'], wire_context=context['wire_context'],
        wire_check=context['wire_check'], source_layout=contract.source_layout(context),
        cases=rows, matrix_sha256=contract.matrix_sha256(), summary=contract.observed_summary(rows),
        **contract.EXTENTS, **dict.fromkeys(contract.TRUE_FLAGS, True),
        **dict.fromkeys(contract.FALSE_FLAGS, False))


class BufferTransportMatrixTests(unittest.TestCase):
    def test_frozen_65_cases_95_ordered_steps_and_separate_native_counts(self):
        specs = contract.scenarios()
        self.assertEqual(len(specs), contract.case_count())
        self.assertEqual(len({s['case_id'] for s in specs}), 65)
        self.assertEqual([sum(s['mode'] == mode for s in specs)
            for mode in ('resize', 'append', 'transport', 'archive')], [34, 13, 8, 10])
        self.assertEqual(sum(len(s['steps']) for s in specs), 95)
        self.assertEqual(contract.matrix_sha256(),
            '4fc2d23189c26657d6b74dda0e6ef35a006b4a625344da60fcc01712037da2eb')
        summary = contract.observed_summary([oracle.expected_case(s) for s in specs])
        self.assertEqual([summary[k] for k in ('resize_calls', 'grow_calls', 'append_calls',
            'transport_calls', 'archive_raw_calls', 'set_count_calls')], [86, 50, 33, 12, 16, 12])
        self.assertEqual((summary['cumulative_cases'], summary['wake_calls'],
            summary['aligned_allocations'], summary['maximum_allocation_bytes']), (9, 4, 6, 6183))

    def test_initial_and_per_step_inputs_are_independent_and_strictly_typed(self):
        for spec in contract.scenarios():
            contract.validate_spec(spec)
        original = contract.scenarios()[0]
        for key, value in (('mode', 'transport'), ('extra', 0), ('case_id', 'resize-99')):
            changed = copy.deepcopy(original)
            changed[key] = value
            with self.assertRaises(ValueError):
                contract.validate_spec(changed)
        for value in (False, 0.0, -1, 1 << 64):
            changed = copy.deepcopy(original)
            changed['steps'][0]['requested_size'] = value
            with self.assertRaises(ValueError):
                contract.validate_spec(changed)
        changed = contract.scenarios()
        changed[0]['initial']['capacity'] = 17
        self.assertEqual(contract.scenarios()[0]['initial']['capacity'], 8)


class BufferTransportAdmissionTests(unittest.TestCase):
    def test_complete_synthetic_report_validates_but_is_not_native_evidence(self):
        contract.validate_report(fixture_report(), fixture_context())

    def test_wrong_scope_flags_source_layout_and_dependency_bindings_are_refused(self):
        for key, value in (('native_growth_used', False), ('native_resize_used', 1),
                ('native_archive_constructor_used', True), ('native_socket_used', True),
                ('source_sha256', 'x' * 64), ('vector_bytes', 24.0),
                ('wire_check', dict(path='foreign', sha256='d' * 64)),
                ('source_layout', {}), ('summary', {}), ('schema', True)):
            changed = fixture_report()
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.validate_report(changed, fixture_context())

    def test_reordered_duplicated_or_incomplete_actual_cases_are_refused(self):
        for mutation in ('reorder', 'duplicate', 'missing-step', 'invented-growth', 'lost-zero-copy'):
            report = fixture_report()
            if mutation == 'reorder':
                report['cases'][0], report['cases'][1] = report['cases'][1], report['cases'][0]
            elif mutation == 'duplicate':
                report['cases'][1] = copy.deepcopy(report['cases'][0])
            elif mutation == 'missing-step':
                report['cases'][31]['observation']['steps'].pop()
            elif mutation == 'invented-growth':
                report['cases'][0]['observation']['steps'][0]['calls']['grow'] = 1
            else:
                row = next(r for r in report['cases'] if r['spec']['case_id'] == 'append-00')
                row['observation']['steps'][0]['events'].pop()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.validate_report(report, fixture_context())


if __name__ == '__main__':
    unittest.main()
