"""Pure result-gate coverage and standalone proof-admission checks."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    result = module_from_spec(spec); spec.loader.exec_module(result)
    return result


class ResultGateCaseContractTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('result-gate-case-contracts')
        self.context = dict(function='0x1467d0c60', switch=dict(input_first=1305, input_count=227,
            index_bytes=(bytes([0, 1, 2, 3]) + bytes([3]) * 223).hex(),
            table_bytes=struct.pack('<4I', 0x67d1045, 0x67d0e7f, 0x67d0f87, 0x67d1045).hex()))

    def report(self):
        return dict(self.tool.expected_rows(self.context), schema=1, method='bounded_native',
            function=self.context['function'], code_instructions=251,
            network_used=False, profile_activated=False, runtime_activated=False,
            handler_executed=False, login_handoff_executed=False, session_executed=False)

    def test_reviewed_count_scope_and_verifier(self):
        self.assertEqual(self.tool.case_count(), 243)
        self.assertEqual(self.tool.FAMILIES, ('result-gate',))
        self.assertEqual(self.tool.verifier(), 'verify-result-gate-context')
        report = self.report()
        self.assertEqual((len(report['cases']), len(report['switch_cases'])), (16, 227))
        self.tool.validate_report(report, self.context)

    def test_unknown_family_or_missing_checked_context_rejected(self):
        for family in ('handler', '', None, [], 1):
            with self.assertRaises(ValueError): self.tool.case_count(family)
        with self.assertRaises(ValueError): self.tool.validate_report(self.report())

    def test_whole_codes_and_state_flags_exact(self):
        report = self.report()
        self.assertEqual({row['code'] for row in report['cases']}, {0, 1, 42, 58, 708, 1304, 0xffffffff, 0x1197})
        for code in self.tool.CODES:
            self.assertEqual({row['state_flag'] for row in report['cases'] if row['code'] == code}, {0, 1})
        self.assertNotIn(1197, {row['code'] for row in report['cases']})

    def test_special_error_service_site_returns_true_only_with_clear_state(self):
        rows = {row['state_flag']: row for row in self.report()['cases'] if row['code'] == 0x1197}
        self.assertEqual(rows[0]['returned'], 1)
        self.assertEqual(rows[0]['events'][-1]['call_offset'], 961)
        self.assertEqual(rows[0]['events'][-1]['action'], 'gate_error')
        self.assertEqual(rows[1]['returned'], 0)
        self.assertEqual([event['action'] for event in rows[1]['events']], ['gate_state'])
        report = self.report()
        next(row for row in report['cases'] if row['code'] == 0x1197 and row['state_flag'] == 0)['events'][-1]['call_offset'] = 1001
        with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_ordinary_failure_and_suppressed_error_routes_are_distinct(self):
        for row in self.report()['cases']:
            if row['code'] == 0:
                self.assertEqual(row['returned'], 1)
            elif row['code'] != 0x1197:
                self.assertEqual(row['returned'], 0)
            if row['code'] in (1, 58, 708, 1304, 0xffffffff) and row['state_flag'] == 0:
                self.assertEqual(row['events'][-1]['call_offset'], 1001)
            if row['state_flag'] == 1 or row['code'] in (0, 42):
                self.assertEqual(len(row['events']), 1)

    def test_duplicate_or_missing_full_rows_rejected(self):
        report = self.report(); report['cases'][1] = copy.deepcopy(report['cases'][0])
        with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)
        report = self.report(); report['cases'].pop()
        with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_bool_is_not_integer_code_flag_return_or_index(self):
        for group, field in (('cases', 'code'), ('cases', 'state_flag'), ('cases', 'returned'), ('switch_cases', 'index')):
            report = self.report(); report[group][0][field] = False
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_state_temp_guards_and_return_abi_required_only_for_returned_cases(self):
        for field in ('abi', 'state_guards', 'temporary_guards', 'guards'):
            report = self.report(); report['cases'][0][field] = False
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)
        for row in self.report()['switch_cases']:
            self.assertFalse(row['abi_return_checked'])
            self.assertFalse(row['external_branch_services_executed'])
            self.assertTrue(row['stopped_before_target'])
            self.assertNotIn('returned', row)

    def test_all_227_index_codes_targets_and_duplicate_rva_slots_exact(self):
        rows = self.report()['switch_cases']
        self.assertEqual([row['code'] for row in rows], list(range(1305, 1532)))
        self.assertEqual([row['index'] for row in rows[:4]], [0, 1, 2, 3])
        self.assertEqual(rows[0]['target'], rows[3]['target'])
        self.assertNotEqual(rows[0]['target'], rows[1]['target'])
        self.assertNotEqual(rows[1]['target'], rows[2]['target'])
        for field, value in (('code', 0), ('index', 2), ('target', rows[1]['target'])):
            report = self.report(); report['switch_cases'][0][field] = value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_dispatch_stopping_boundary_and_fixture_events_strict(self):
        for field, value in (('stopped_before_target', False), ('abi_return_checked', True),
                             ('external_branch_services_executed', True), ('guards', False)):
            report = self.report(); report['switch_cases'][0][field] = value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)
        report = self.report(); report['switch_cases'][0]['events'].append(dict(action='gate_error', call_offset=1001, arguments_checked=True))
        with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_source_scope_code_coverage_and_activation_flags_strict(self):
        for field in ('network_used', 'profile_activated', 'runtime_activated', 'handler_executed', 'login_handoff_executed', 'session_executed'):
            for value in (True, 0, None):
                report = self.report(); report[field] = value
                with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)
        for field, value in (('method', 'static'), ('code_instructions', 252), ('function', '0x1000')):
            report = self.report(); report[field] = value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_index_layout_shape_cannot_be_relaxed(self):
        for field, value in (('input_first', 1304), ('input_first', True), ('input_count', 228),
                             ('table_bytes', '00' * 12), ('index_bytes', '00' * 226), ('index_bytes', '04' + '00' * 226)):
            context = copy.deepcopy(self.context); context['switch'][field] = value
            with self.assertRaises(ValueError): self.tool.expected_rows(context)

    def test_checked_historical_context_keeps_all_index_entries(self):
        context = json.loads((HERE / 'knowledge/native-contexts/result-gate-11320.json').read_text('utf-8'))
        rows = self.tool.expected_rows(context)
        self.assertEqual((len(rows['cases']), len(rows['switch_cases'])), (16, 227))
        self.assertEqual({row['index'] for row in rows['switch_cases']}, {0, 1, 2, 3})
        self.assertEqual(rows['switch_cases'][0]['target'], '0x1467d1045')
        self.assertEqual(rows['switch_cases'][-1]['target'], '0x1467d0f87')

    def test_tools_cover_verifier_and_frozen_harness(self):
        self.assertEqual({Path(path).name for path in self.tool.tools()}, set(self.tool.TOOLS))
        source = (HERE / 'verify-result-gate-context.py').read_text('utf-8')
        self.assertIn('adapter.validate(index, args, context)', source)
        self.assertIn('rules.export_coverage', source)
        self.assertIn('verify_whole_exports=False', source)
        self.assertIn("'XMM'+str(i)", source)
        self.assertNotIn('544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c', source)


class ResultGateStandaloneAdmissionTests(unittest.TestCase):
    def run_admission(self, change=None, roots=None):
        verifier = load('verify-result-gate-context')
        context = dict(family='result-gate', function='0x1000', source_sha256='a' * 64, transfer_proof=dict(path='proof', sha256='b' * 64))
        if change: context.update(change)
        calls = []
        def module(name):
            if name == 'knowledge-index': return SimpleNamespace(api=lambda: SimpleNamespace())
            if name == 'update-bindings':
                return SimpleNamespace(SourceStore=lambda index, root: SimpleNamespace(image=lambda native, sha: object(), validate=lambda: calls.append('source')))
            if name == 'update-native-response':
                return SimpleNamespace(select=lambda family: SimpleNamespace(roots=lambda c: {0x1000} if roots is None else roots,
                    validate=lambda index, args, c: calls.append('proof')))
            if name == 'result-gate-transfer-rules':
                return SimpleNamespace(rows=lambda *args: calls.append('code_boundary'), export_coverage=lambda *args: calls.append('exports'))
            if name == 'build-native-entry-code': return object()
            raise AssertionError(name)
        with patch.object(verifier, 'load', module): verifier.admit(context, Path('F:/PhoneExit Resources/Vampir'))
        return calls

    def test_proof_boundary_export_source_validation_required_before_native(self):
        self.assertEqual(self.run_admission(), ['proof', 'code_boundary', 'exports', 'source'])

    def test_missing_proof_unknown_scope_or_wrong_root_is_rejected(self):
        for change in (dict(transfer_proof=None), dict(family='other'), dict(function_budget=16), dict(native_handler={})):
            with self.assertRaises(ValueError): self.run_admission(change)
        for roots in ({0x1001}, {0x1000, 0x2000}, set()):
            with self.assertRaises(ValueError): self.run_admission(roots=roots)


if __name__ == '__main__':
    unittest.main()
