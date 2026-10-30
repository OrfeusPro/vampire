"""Pure exact bounded handler report/admission tests; native execution excluded."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    result = module_from_spec(spec); spec.loader.exec_module(result)
    return result


class LoginHandlerCaseContractsTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('login-handler-case-contracts')
        self.context = dict(base_table='0x1000', table='0x2000', functions=dict(handler='0x3000'))

    def report(self, family):
        return dict(schema=1, method='bounded_native', cases=self.tool.expected_rows(family, self.context),
                    handler=self.context['functions']['handler'], network_used=False, profile_activated=False,
                    runtime_activated=False, gate_executed=False, successful_login_executed=False)

    def test_reviewed_counts_and_verifier_paths(self):
        for family, count in zip(self.tool.FAMILIES, (8, 14)):
            report = self.report(family)
            self.assertEqual(self.tool.case_count(family), count)
            self.assertEqual(len(report['cases']), count)
            self.assertTrue((HERE / (self.tool.verifier(family) + '.py')).is_file())
            self.tool.validate_report(family, report, self.context)

    def test_unknown_family_or_missing_source_context_rejected(self):
        for family in ('', 'login-handler-success', None, [], 2):
            with self.assertRaises(ValueError):
                self.tool.case_count(family)
        with self.assertRaisesRegex(ValueError, 'checked source context'):
            self.tool.validate_report('login-continuation', self.report('login-continuation'))

    def test_duplicates_and_omitted_matrix_rows_rejected(self):
        for family in self.tool.FAMILIES:
            report = self.report(family)
            report['cases'][1] = copy.deepcopy(report['cases'][0])
            with self.assertRaises(ValueError):
                self.tool.validate_report(family, report, self.context)
            report = self.report(family)
            report['cases'].pop()
            with self.assertRaises(ValueError):
                self.tool.validate_report(family, report, self.context)

    def test_bool_is_not_numeric_matrix_value_or_outcome(self):
        for family, field in (('login-continuation', 'level'), ('login-handler-early', 'poison')):
            report = self.report(family)
            report['cases'][0][field] = False
            with self.assertRaises(ValueError):
                self.tool.validate_report(family, report, self.context)
        report = self.report('login-continuation')
        report['cases'][0]['values']['0x338'] = False
        with self.assertRaises(ValueError):
            self.tool.validate_report('login-continuation', report, self.context)

    def test_continuation_level_clamp_and_capacity_reset(self):
        for row in self.report('login-continuation')['cases']:
            self.assertEqual(row['values']['0xf0'], min(row['level'], 1))
            for field in ('0x244', '0x294', '0x2e4'):
                self.assertEqual(row['values'][field], 128)
            self.assertEqual((row['flag'], row['field308']), (0, 0))

    def test_continuation_wrong_fields_and_constructor_tables_rejected(self):
        for field, value in (('field308', 1), ('flag', 1), ('ctor_vptrs', [0x2000, 0x1000])):
            report = self.report('login-continuation')
            report['cases'][0][field] = value
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-continuation', report, self.context)
        report = self.report('login-continuation')
        report['cases'][0]['values']['0x248'] = 0
        with self.assertRaises(ValueError):
            self.tool.validate_report('login-continuation', report, self.context)

    def test_continuation_helper_order_receiver_and_second_exact(self):
        for field, value in (('call_offset', 42), ('offset', '0xa0'), ('second', 1)):
            report = self.report('login-continuation')
            report['cases'][0]['events'][0][field] = value
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-continuation', report, self.context)

    def test_continuation_write_store_offsets_sizes_and_values_exact(self):
        for field, value in (('instruction_offset', 201), ('offset', '0x1a4'), ('size', 8), ('value', 1), ('phase', 'constructor')):
            report = self.report('login-continuation')
            report['cases'][0]['writes'][0][field] = value
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-continuation', report, self.context)

    def test_continuation_capacity_branch_changes_exact_event_and_write_counts(self):
        rows = self.report('login-continuation')['cases']
        for low, high in zip(rows[::2], rows[1::2]):
            self.assertEqual(high['capacity'], 256)
            self.assertEqual(len(high['events']) - len(low['events']), 3)
            self.assertEqual(len(high['writes']) - len(low['writes']), 3)

    def test_high_level_trace_uses_its_branch_site_for_a_repeated_helper(self):
        # The helper at reset+53/+62 is identical, but only one site executes.
        # The same exclusive pair occurs in the next three container branches.
        for row in self.report('login-continuation')['cases']:
            offsets = [event['call_offset'] for event in row['events']]
            if row['level'] <= 1:
                self.assertTrue({53, 108, 163, 287} <= set(offsets))
                self.assertFalse({62, 117, 172, 296} & set(offsets))
            else:
                self.assertTrue({62, 117, 172, 296} <= set(offsets))
                self.assertFalse({53, 108, 163, 287} & set(offsets))
        for actual, wrong in ((62, 53), (117, 108), (172, 163), (296, 287)):
            report = self.report('login-continuation')
            row = next(row for row in report['cases'] if row['level'] == 2)
            next(event for event in row['events'] if event['call_offset'] == actual)['call_offset'] = wrong
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-continuation', report, self.context)

    def test_early_four_codes_and_optional_branches_exact(self):
        rows = self.report('login-handler-early')['cases']
        self.assertEqual({row['code'] for row in rows}, {54, 9818, 9819, 90021})
        for row in rows:
            names = [event['action'] for event in row['events']]
            if row['code'] == 54:
                self.assertFalse(row['optional_present'])
                self.assertEqual(names[-1], 'popup54')
            else:
                self.assertEqual(names[-1], 'error_finish')
                self.assertEqual(any(name in ('error_9818', 'error_90021') for name in names), row['optional_present'])

    def test_early_actions_order_call_sites_and_argument_guard_required(self):
        for field, value in (('action', 'free'), ('call_offset', 117), ('arguments_checked', False)):
            report = self.report('login-handler-early')
            report['cases'][0]['events'][0][field] = value
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-handler-early', report, self.context)

    def test_90021_null_lookup_uses_shared_finish_site_and_present_uses_own_site(self):
        report = self.report('login-handler-early')
        for row in report['cases']:
            if row['code'] == 90021:
                self.assertEqual(row['events'][-1]['action'], 'error_finish')
                self.assertEqual(row['events'][-1]['call_offset'], 1341 if row['optional_present'] else 1384)
        for present, wrong_site in ((False, 1341), (True, 1384)):
            changed = self.report('login-handler-early')
            row = next(row for row in changed['cases'] if row['code'] == 90021 and row['optional_present'] is present)
            row['events'][-1]['call_offset'] = wrong_site
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-handler-early', changed, self.context)

    def test_early_handler_report_must_match_context(self):
        report = self.report('login-handler-early')
        report['handler'] = '0x4000'
        with self.assertRaisesRegex(ValueError, 'root differs'):
            self.tool.validate_report('login-handler-early', report, self.context)

    def test_all_activation_and_success_scope_flags_are_strict(self):
        for family in self.tool.FAMILIES:
            for key in ('network_used', 'profile_activated', 'runtime_activated', 'gate_executed', 'successful_login_executed'):
                for value in (True, 0, None):
                    report = self.report(family); report[key] = value
                    with self.assertRaises(ValueError):
                        self.tool.validate_report(family, report, self.context)

    def test_report_and_all_case_guards_required(self):
        for family in self.tool.FAMILIES:
            for field in ('guards', 'abi'):
                report = self.report(family); report['cases'][0][field] = False
                with self.assertRaises(ValueError):
                    self.tool.validate_report(family, report, self.context)
            report = self.report(family); report['method'] = 'static'
            with self.assertRaises(ValueError):
                self.tool.validate_report(family, report, self.context)

    def test_verifiers_use_proof_guard_and_nonvolatile_xmm(self):
        for family in self.tool.FAMILIES:
            source = (HERE / (self.tool.verifier(family) + '.py')).read_text('utf-8')
            self.assertIn('adapter.validate(index, args, context)', source)
            self.assertIn("'XMM'+str(i)", source)
            self.assertNotIn('544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c', source)
            self.assertIn("'update-native-harness'", source)


class LoginHandlerStandaloneAdmissionTests(unittest.TestCase):
    def check(self, family, change=None, count_override=None):
        verifier = load('verify-login-continuation-portable' if family == 'login-continuation' else 'verify-login-handler-early-context')
        context = dict(family=family, transfer_proof=dict(path='proof', sha256='a' * 64))
        if change:
            context.update(change)
        calls = []
        count = (2 if family == 'login-continuation' else 1) if count_override is None else count_override
        def module(name):
            if name == 'knowledge-index':
                return SimpleNamespace(api=lambda: SimpleNamespace())
            if name == 'update-bindings':
                return SimpleNamespace(SourceStore=lambda index, root: SimpleNamespace(validate=lambda: calls.append('frozen')))
            if name == 'update-native-login-handler':
                return SimpleNamespace(select=lambda family: SimpleNamespace(roots=lambda c: set(range(count)),
                    validate=lambda index, args, c: calls.append('proof')))
            raise AssertionError(name)
        with patch.object(verifier, 'load', module):
            verifier.admit(context, Path('F:/PhoneExit Resources/Vampir'))
        return calls

    def test_only_exact_family_roots_are_admitted_after_proof_and_source_validation(self):
        for family in ('login-continuation', 'login-handler-early'):
            self.assertEqual(self.check(family), ['proof', 'frozen'])

    def test_missing_proof_and_unreviewed_scopes_fail_before_execution(self):
        for family in ('login-continuation', 'login-handler-early'):
            for change in (dict(transfer_proof=None), dict(family='other'), dict(function_budget=16), dict(native_admission={})):
                with self.assertRaises(ValueError):
                    self.check(family, change=change)
            with self.assertRaises(ValueError):
                self.check(family, count_override=3)


if __name__ == '__main__':
    unittest.main()
