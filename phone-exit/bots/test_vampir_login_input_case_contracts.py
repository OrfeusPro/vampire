"""Pure portable Login input coverage/admission guards; no native execution."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class LoginInputCaseContractsTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('login-input-case-contracts')

    def report(self, family):
        native = family == 'login-strings-buffer'
        return dict(self.tool.expected_rows(family), schema=1, method='bounded_native', operations=copy.deepcopy(self.tool.ORDER),
                    network_used=False, profile_activated=False, runtime_activated=False,
                    native_nested_used=True, native_scalars_used=native,
                    native_strings=native, native_buffer_construction=native)

    def test_reviewed_counts_and_verifiers(self):
        for family, count in zip(self.tool.FAMILIES, (232, 506)):
            self.assertEqual(self.tool.case_count(family), count)
            self.assertTrue((HERE / (self.tool.verifier(family) + '.py')).is_file())
            self.tool.validate_report(family, self.report(family))
        self.assertEqual(self.tool.verifier('login-nested'), 'verify-login-nested-context')
        self.assertEqual(self.tool.verifier('login-strings-buffer'), 'verify-login-input-context')

    def test_unknown_family_rejected(self):
        for family in ('login-input', '', 1, None, []):
            with self.assertRaises(ValueError):
                self.tool.case_count(family)

    def test_every_nested_failure_and_truthy_shape_is_covered(self):
        result = self.report('login-nested')
        self.assertEqual(len(result['cases']), 2 * 2 * 2 * 29)
        self.assertEqual({row['fail_at'] for row in result['cases']}, {None, *range(28)})
        self.assertEqual({row['truthy'] for row in result['cases']}, {1, 257})
        row = next(row for row in result['cases'] if row['fail_at'] == 27)
        row['operations'] = 27
        with self.assertRaisesRegex(ValueError, 'matrix/outcome'):
            self.tool.validate_report('login-nested', result)

    def test_duplicate_full_dimensions_rejected(self):
        result = self.report('login-strings-buffer')
        result['cases'][1] = copy.deepcopy(result['cases'][0])
        with self.assertRaisesRegex(ValueError, 'matrix/outcome'):
            self.tool.validate_report('login-strings-buffer', result)

    def test_missing_or_extra_cases_rejected(self):
        for family in self.tool.FAMILIES:
            for change in ('drop', 'add'):
                result = self.report(family)
                result['cases'].pop() if change == 'drop' else result['cases'].append(copy.deepcopy(result['cases'][0]))
                with self.assertRaises(ValueError):
                    self.tool.validate_report(family, result)

    def test_bool_is_not_integer_dimension_or_output(self):
        for family, key in (('login-nested', 'returned'), ('login-strings-buffer', 'code')):
            result = self.report(family)
            result['cases'][0][key] = False if key == 'code' else True
            with self.assertRaises(ValueError):
                self.tool.validate_report(family, result)
        result = self.report('login-nested')
        result['cases'][0]['guards'] = 1
        with self.assertRaises(ValueError):
            self.tool.validate_report('login-nested', result)

    def test_all_truncations_consume_available_prefix_and_reject(self):
        result = self.report('login-strings-buffer')
        self.assertEqual(len(result['truncated']), 367)
        self.assertTrue(all(row['returned'] == 0 and row['consumed'] == row['size'] for row in result['truncated']))
        for key, value in (('returned', 1), ('consumed', 0), ('first_string_utf16', '3f000000')):
            changed = copy.deepcopy(result)
            changed['truncated'][-1][key] = value
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-strings-buffer', changed)

    def test_partial_first_string_is_not_assigned(self):
        result = self.report('login-strings-buffer')
        row = next(row for row in result['truncated'] if row['text'] == '🙂' and row['size'] == 9)
        self.assertEqual(row['first_string_utf16'], '')
        complete = next(row for row in result['truncated'] if row['text'] == '🙂' and row['size'] == 10)
        self.assertEqual(complete['first_string_utf16'], '3dd842de0000')

    def test_bool_projection_normalized_and_raw32_preserved(self):
        result = self.report('login-strings-buffer')
        row = next(row for row in result['cases'] if row['flag'] == 255 and row['code'] == 0xffffffff)
        self.assertEqual(row['scalar_values']['0x88'], '01')
        self.assertEqual(row['scalar_values']['0x10'], 'ffffffff')
        for key, value in (('0x88', 'ff'), ('0x154', '00000000')):
            changed = copy.deepcopy(result)
            changed['cases'][result['cases'].index(row)]['scalar_values'][key] = value
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-strings-buffer', changed)

    def test_trailing_bytes_boundaries_and_special_observations_exact(self):
        result = self.report('login-strings-buffer')
        self.assertEqual(result['trailing']['size'] - result['trailing']['consumed'], 5)
        self.assertEqual([len(row['text']) for row in result['boundaries']], [15, 16, 127, 128])
        self.assertEqual(result['special'][4]['input_hex'], '610062')
        self.assertEqual(result['special'][4]['first_string_utf16'], '61000000')
        for collection in ('trailing', 'boundaries', 'special'):
            changed = copy.deepcopy(result)
            row = changed[collection] if collection == 'trailing' else changed[collection][0]
            row['consumed'] += 1
            with self.assertRaises(ValueError):
                self.tool.validate_report('login-strings-buffer', changed)

    def test_top_level_scope_flags_and_order_strict(self):
        for family in self.tool.FAMILIES:
            baseline = self.report(family)
            for flag in ('network_used', 'profile_activated', 'runtime_activated', 'native_nested_used',
                         'native_scalars_used', 'native_strings', 'native_buffer_construction'):
                changed = copy.deepcopy(baseline)
                changed[flag] = not baseline[flag]
                with self.assertRaises(ValueError):
                    self.tool.validate_report(family, changed)
            changed = copy.deepcopy(baseline)
            changed['operations'][-1] = ('raw32', 0x158)
            with self.assertRaises(ValueError):
                self.tool.validate_report(family, changed)

    def test_new_constructor_and_abi_guards_are_required(self):
        for family in self.tool.FAMILIES:
            for flag in ('constructor_guards', 'abi_guards'):
                changed = self.report(family)
                changed['cases'][0][flag] = False
                with self.assertRaises(ValueError):
                    self.tool.validate_report(family, changed)

    def test_nested_cannot_claim_extra_wire_cases(self):
        result = self.report('login-nested')
        result['special'] = [dict(returned=1)]
        with self.assertRaises(ValueError):
            self.tool.validate_report('login-nested', result)

    def test_tools_pin_new_verifiers_and_separate_harness(self):
        names = {Path(path).name for path in self.tool.tools()}
        self.assertEqual(names, set(self.tool.TOOLS))
        for verifier in ('verify-login-nested-context', 'verify-login-input-context'):
            source = (HERE / (verifier + '.py')).read_text('utf-8')
            self.assertIn("load('verify-login-input-harness')", source)
            self.assertIn("'XMM' + str(i)", source)
            self.assertNotIn("discover-login-result-11320", source)


class LoginInputHarnessAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.harness = load('verify-login-input-harness')
        self.root = Path('F:/PhoneExit Resources/Vampir')
        self.validated = []

    def context(self, family):
        result = dict(family=family, functions={str(i): hex(0x1000 + i * 16) for i in range(6)},
                      leaves={'0x5000': 'c3'}, exports={'run-fixture': 'a' * 64}, transfer_proof={'path': 'proof', 'sha256': 'b' * 64})
        if family == 'login-strings-buffer':
            result.update(function_budget=20, input=dict(functions={str(i): hex(0x2000 + i * 16) for i in range(14)}))
        return result

    def roots(self, context):
        return {int(value, 16) for value in context['functions'].values()} | {
            int(value, 16) for value in context.get('input', {}).get('functions', {}).values()}

    def modules(self, name, path):
        if name == 'portable_login_index':
            return SimpleNamespace(api=lambda: SimpleNamespace())
        if name == 'portable_login_adapter':
            return SimpleNamespace(select=lambda family: SimpleNamespace(roots=self.roots,
                validate=lambda index, args, context: self.validated.append((family, context))))
        if name == 'portable_login_sources':
            return SimpleNamespace(SourceStore=lambda index, root: SimpleNamespace(validate=lambda: self.validated.append('frozen')))
        raise AssertionError(name)

    def admit(self, context, *, functions=None, leaves=None, exports=None):
        with patch.object(self.harness, 'load', self.modules):
            return self.harness.admit(context, self.root, self.roots(context) if functions is None else functions,
                {int(address, 16): value for address, value in context['leaves'].items()} if leaves is None else leaves,
                context['exports'] if exports is None else exports)

    def test_both_exact_scopes_call_adapter_proof_guard(self):
        for family in ('login-nested', 'login-strings-buffer'):
            self.admit(self.context(family))
        self.assertEqual([row[0] for row in self.validated if isinstance(row, tuple)], ['login-nested', 'login-strings-buffer'])
        self.assertEqual(self.validated.count('frozen'), 2)

    def test_rejects_unregistered_scope_and_missing_proof(self):
        result = self.context('login-nested')
        result.pop('transfer_proof')
        with self.assertRaises(ValueError):
            self.admit(result)
        result = self.context('login-nested')
        result['family'] = 'unreviewed'
        with self.assertRaises(ValueError):
            self.admit(result)
        self.assertFalse(self.validated)

    def test_exact_roots_leaves_exports_and_budget_required(self):
        context = self.context('login-strings-buffer')
        for kwargs in (dict(functions=self.roots(context) | {0x7000}), dict(leaves={}), dict(exports={})):
            with self.assertRaises(ValueError):
                self.admit(context, **kwargs)
        for budget in (16, 21, True):
            changed = copy.deepcopy(context)
            changed['function_budget'] = budget
            with self.assertRaises(ValueError):
                self.admit(changed)
        changed = copy.deepcopy(context)
        changed['native_admission'] = dict(adapter='unreviewed')
        with self.assertRaises(ValueError):
            self.admit(changed)
        self.assertFalse(self.validated)


if __name__ == '__main__':
    unittest.main()
