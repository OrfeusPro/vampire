"""Fixture-only admission tests; these synthetic rows are not native evidence."""
import copy
import importlib.util
import itertools
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


contract = load('login-backend-wire-native-contracts')
oracle = load('login-backend-wire-native-oracle')
verifier = load('verify-login-backend-wire-context')


def parent_report():
    parent = contract.INPUT.PARENT
    cases = []
    for scenario, empty, result, metadata in itertools.product(
            parent.PREPARE.SCENARIOS, (False, True), (0, 1), parent.PARENT.INTEGRATION_CASES):
        main = scenario[2] and scenario[3] and bool(scenario[4] & 1)
        aux = scenario[2] and scenario[3] and bool(scenario[4] & 2)
        active = metadata[0] not in ('none', 'invalid')
        strings = {hex(offset): '' for offset in oracle.HANDOFF.STRING_OFFSETS}
        strings['0x10'] = '' if empty else 'Ж界🙂'
        strings['0x110'] = 'compiled-tag-fixture'
        if aux and active: strings['0xd8'] = '{"fixture":"quote\\\"-🙂"}'
        integers = {hex(offset): 0 for offset in oracle.HANDOFF.SCALAR_WIDTHS}
        integers.update({'0x50': 0 if empty else 0x89abcdef, '0x98': 3,
            '0xf8': 207, '0x120': 0 if empty else 0xffffffff,
            '0x130': int(not empty), '0x131': 0 if empty else 255})
        cases.append(dict(scenario=scenario[0], selector=3, empty=empty, send_return=result,
            poison=85, cache_case='warm', metadata_case=list(metadata), guards=True,
            strings=strings, integers=integers, native_calls=dict(sdk_value=int(main)),
            metadata_calls=parent.PARENT._native_calls(active) if aux else {}, sdk_event=main,
            lifecycle=['send', 'post_notify'] + (['sdk_event'] if main else []) + ['destructor']))
    return dict(schema=1, source_sha256='a' * 64, method='bounded_native',
        scope='bounded_native_login_prepare_metadata', cases=cases,
        native_sdk_used=True, native_metadata_used=True, network_used=False,
        profile_activated=False, runtime_activated=False,
        metadata_fields=[dict(key=key) for key in parent.PARENT.COLLECTOR_ORDER])


def context():
    return dict(family=contract.FAMILY, format=contract.FORMAT,
        source_sha256='a' * 64, **contract.EXTENTS)


def report(parent, rows):
    return dict(schema=1, source_sha256='a' * 64, method='bounded_native',
        scope=contract.SCOPE, cases=rows, metadata_fields=copy.deepcopy(parent['metadata_fields']),
        matrix_sha256=contract.matrix_sha256(), summary=contract.observed_summary(rows),
        **contract.EXTENTS, **dict.fromkeys(contract.TRUE_FLAGS, True),
        **dict.fromkeys(contract.FALSE_FLAGS, False))


class BackendNativeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = parent_report()
        cls.prepared = oracle.prepared_rows(cls.parent)
        cls.specs = contract.scenarios()
        cls.rows = [oracle.expected_case(spec, cls.prepared) for spec in cls.specs]
        cls.good = report(cls.parent, cls.rows)

    def row_at(self, predicate):
        index = next(i for i, spec in enumerate(self.specs) if predicate(spec))
        return index, copy.deepcopy(self.rows[index])

    def reject_row(self, index, row):
        with self.assertRaises(ValueError): oracle.validate_case(row, self.specs[index], self.prepared)

    def test_exact_frozen1807_matrix_observations_and_aggregate_counts(self):
        contract.validate_report(self.good, context(), self.parent)
        self.assertEqual(contract.observed_summary(self.rows), contract.INPUT.summary())
        self.assertEqual(self.good['summary']['writer_calls'], 1344)
        self.assertEqual(self.good['summary']['backend_calls'], 1359)
        self.assertEqual(self.good['summary']['pending_suppressed'], 448)
        self.assertEqual(self.good['summary']['fallback_calls'], 6)
        self.assertEqual(self.good['summary']['initial_growth_calls'], 2688)
        self.assertEqual(self.good['summary']['sequence_wraps'], 444)

    def test_request_id3_old_sequence_and_checksum_prefix_are_exact_bytes(self):
        index, row = self.row_at(lambda spec: spec['sequence_seed'] == 0xffff
            and spec['pending_case'] == 'empty-count-equal' and spec['backend_case'] == 'serialize')
        wire = row['wire']; body = bytes.fromhex(wire['writer_delta_hex'])
        self.assertEqual(wire['writer_prefix_hex'], '0300ffff')
        self.assertEqual(row['backend']['sequence_after'], 0)
        self.assertEqual(wire['inner_hex'], (bytes.fromhex('0300ffff') + body).hex())
        frame = bytes.fromhex(wire['frame_hex'])
        self.assertEqual(int.from_bytes(frame[:3], 'little'), len(frame))
        self.assertEqual(frame[3:7], bytes.fromhex('67e6096a'))
        self.assertEqual(frame[7:], bytes.fromhex(wire['inner_hex']))
        for bad_prefix in ('0400ffff', '03000000', '0003ffff'):
            bad = copy.deepcopy(row); bad['wire']['writer_prefix_hex'] = bad_prefix
            self.reject_row(index, bad)

    def test_independent_fields_reject_consistently_forged_body_and_frame(self):
        index, row = self.row_at(lambda spec: not spec['empty']
            and spec['pending_case'] == 'empty-count-equal' and spec['backend_case'] == 'serialize')
        row['strings']['0xd8'] = 'wrong-but-consistently-encoded'
        body = contract.BYTES.login_body(row)
        frame = contract.BYTES.frame(body, row['sequence_seed'])
        wire = row['wire']
        wire.update(writer_delta_hex=body.hex(), inner_hex=frame[7:].hex(),
            checksum_input_hex=frame[7:].hex(), plaintext_frame_hex=frame.hex(),
            frame_hex=frame.hex(), transport_hex=frame.hex(),
            inner_bytes=len(frame)-7, frame_bytes=len(frame), writer_return_count=len(frame)-7,
            transform_size=len(frame)-3)
        self.reject_row(index, row)

    def test_unicode_prefix_counts_utf8_bytes_and_preserves_raw_bool255(self):
        index, row = self.row_at(lambda spec: not spec['empty']
            and spec['pending_case'] == 'empty-count-equal' and spec['backend_case'] == 'serialize')
        body = bytes.fromhex(row['wire']['writer_delta_hex'])
        self.assertEqual(struct.unpack_from('<H', body)[0], len('Ж界🙂'.encode('utf-8')))
        self.assertEqual(body[-1], 255)
        for value in (1, True):
            bad = copy.deepcopy(row); bad['integers']['0x131'] = value
            self.reject_row(index, bad)
        bad = copy.deepcopy(row); bad['wire']['writer_delta_hex'] = (b'\x04\0' + body[2:]).hex()
        self.reject_row(index, bad)

    def test_pending_hit_suppresses_backend_and_every_wire_provider(self):
        index, row = self.row_at(lambda spec: spec['pending_case'] == 'heap-chain-hit')
        self.assertEqual(row['backend']['entry_calls'], 0)
        self.assertIsNone(row['backend']['return_byte'])
        self.assertIsNone(row['wire']['frame_hex'])
        self.assertEqual(row['wire']['cleanup_order'], [])
        for section, key, value in (('backend', 'entry_calls', 1), ('backend', 'return_byte', 0),
                ('handoff', 'service_calls', 1), ('handoff', 'thunk_same_packet', True),
                ('wire', 'writer_calls', 1), ('wire', 'transport_hex', '00'),
                ('wire', 'checksum_calls', 1), ('wire', 'initial_growth_sizes', [1024])):
            bad = copy.deepcopy(row); bad[section][key] = value
            self.reject_row(index, bad)

    def test_archive_constructor_flags_share_current_preparation_enum_provider(self):
        for empty, flags in ((False, 0xffffffff), (True, 0)):
            index, row = self.row_at(lambda spec: spec['empty'] is empty
                and spec['pending_case'] == 'empty-count-equal' and spec['backend_case'] == 'serialize')
            self.assertEqual(row['wire']['archive_flags_bits'], flags)
            self.assertEqual(row['integers']['0x120'], flags)
            for value in (1, None, bool(flags)):
                bad = copy.deepcopy(row); bad['wire']['archive_flags_bits'] = value
                self.reject_row(index, bad)
        index, row = self.row_at(lambda spec: spec['pending_case'] == 'heap-chain-hit')
        self.assertIsNone(row['wire']['archive_flags_bits'])
        row['wire']['archive_flags_bits'] = 1
        self.reject_row(index, row)

    def test_negative_gates_execute_backend_but_do_not_serialize(self):
        focused = [(i, spec) for i, spec in enumerate(self.specs) if spec['group'] == 'focused-negative']
        self.assertEqual(len(focused), 15)
        for index, spec in focused:
            row = self.rows[index]
            self.assertEqual(row['handoff']['service_calls'], 1)
            self.assertEqual(row['backend']['entry_calls'], 1)
            self.assertEqual(row['backend']['return_byte'], 0)
            self.assertEqual(row['backend']['sequence_after'], spec['sequence_seed'])
            self.assertIsNone(row['wire']['frame_hex'])
            self.assertEqual(row['backend']['action_calls'],
                int(spec['backend_case'] in ('mode2action', 'mode2action-otherflag')))
            self.assertEqual(row['backend']['state_getter_calls'], int(spec['backend_case'] != 'globaldisabled'))
        index, row = self.row_at(lambda spec: spec['backend_case'] == 'mode2action-otherflag')
        row['backend']['action_calls'] = 0
        self.reject_row(index, row)

    def test_transport_AL0and1_are_independent_of_opaque_high_return_bits(self):
        for result in (0, 1):
            index, row = self.row_at(lambda spec: spec['backend_case'] == 'serialize'
                and spec['pending_case'] == 'empty-count-equal' and spec['transport_result_byte'] == result)
            self.assertEqual(row['backend']['return_byte'], result)
            self.assertEqual(row['wire']['transport_return_al'], result)
            self.assertNotIn('returned', row['backend'])
            bad = copy.deepcopy(row); bad['backend']['return_byte'] = 0xabcdef00 | result
            self.reject_row(index, bad)
            bad = copy.deepcopy(row); bad['wire']['transport_return_al'] = 1 - result
            self.reject_row(index, bad)

    def test_debug_platform_short_circuit_and_extra_id_getter_calls(self):
        for debug, first, second, offset, ids in (
                ('off', 1, 1, 4, 1), ('firsttrue', 1, 0, 0, 2), ('secondtrue', 1, 1, 0, 2)):
            index, row = self.row_at(lambda spec: spec['debug_case'] == debug
                and spec['pending_case'] == 'empty-count-equal' and spec['backend_case'] == 'serialize')
            b = row['backend']
            self.assertEqual((b['platform_first_calls'], b['platform_second_calls'],
                b['diagnostic_selector_offset'], b['id_getter_calls']), (first, second, offset, ids))
            bad = copy.deepcopy(row); bad['backend']['diagnostic_selector_offset'] = 4 - offset
            self.reject_row(index, bad)

    def test_publisher_source_tables_thunk_and_same_packet_cannot_be_labels(self):
        for section, key, value in (('publisher', 'published_singleton', False),
                ('publisher', 'vptrs', ['primary', 'secondary']),
                ('publisher', 'backend_zeroed_before_ambient', False),
                ('publisher', 'ambient_backend_bound', False), ('publisher', 'returned_service', False),
                ('handoff', 'source_service_vtable', False), ('handoff', 'thunk_calls', 0),
                ('handoff', 'thunk_arguments_checked', False), ('handoff', 'thunk_same_packet', False),
                ('handoff', 'service_arguments', dict(receiver='synthetic_service', packet='rebuilt')),
                ('wire', 'writer_source_edge', False), ('wire', 'same_packet', False)):
            row = copy.deepcopy(self.rows[0]); row[section][key] = value
            with self.subTest(section=section, key=key): self.reject_row(0, row)

    def test_checksum_input_identity_span_key_and_header_cannot_change(self):
        for key, value in (('checksum_input_hex', self.rows[0]['wire']['writer_delta_hex']),
                ('checksum_value', 0), ('transform_offset', 0), ('transform_size', 3),
                ('transform_key_bits', 0), ('transform_in_place', False),
                ('transform_identity', False), ('prefix_immutable', False),
                ('plaintext_frame_hex', '00'), ('frame_hex', '00'), ('transport_hex', '00')):
            row = copy.deepcopy(self.rows[0]); row['wire'][key] = value
            with self.subTest(key=key): self.reject_row(0, row)

    def test_counts_archive_capacity_cleanup_and_ownership_are_checked(self):
        for key, value in (('writer_entry_count', 0), ('writer_return_count', 1),
                ('archive_constructor_calls', 1), ('archive_cleanup_calls', 1),
                ('initial_growth_calls', 1), ('initial_growth_sizes', [1024, 2048]),
                ('cleanup_order', ['inner', 'outer']), ('transport_before_cleanup', False),
                ('wire_temporaries_released', False), ('archive_buffers_released', False),
                ('ownership_checked', False), ('packet_immutable', False), ('strings_immutable', False)):
            row = copy.deepcopy(self.rows[0]); row['wire'][key] = value
            with self.subTest(key=key): self.reject_row(0, row)
        for section, keys in (('ownership', self.rows[0]['ownership']),
                ('publisher', {'guards': True, 'abi': True})):
            for key in keys:
                row = copy.deepcopy(self.rows[0]); row[section][key] = False
                with self.subTest(section=section, key=key): self.reject_row(0, row)

    def test_boolean_count_types_extra_fields_and_nan_are_rejected(self):
        for section, key, value in (('wire', 'writer_calls', True), ('wire', 'guards', 1),
                ('backend', 'sequence_before', 0.0), ('backend', 'request_id', True),
                ('publisher', 'calls', 1.0), ('handoff', 'forwarded', 1),
                ('wire', 'extra', True), ('backend', 'return_byte', float('nan'))):
            row = copy.deepcopy(self.rows[0]); row[section][key] = value
            with self.subTest(section=section, key=key): self.reject_row(0, row)

    def test_report_layout_flags_source_and_recipe_are_strict(self):
        for key in contract.EXTENTS:
            for value in (None, True, float(contract.EXTENTS[key]), contract.EXTENTS[key] + 1):
                bad = dict(self.good, **{key: value})
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    contract.validate_report(bad, context(), self.parent)
            ctx = context(); ctx[key] = False
            with self.assertRaises(ValueError): contract.validate_report(self.good, ctx, self.parent)
        for flag in contract.TRUE_FLAGS + contract.FALSE_FLAGS:
            bad = dict(self.good, **{flag: not self.good[flag]})
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                contract.validate_report(bad, context(), self.parent)
        for key, value in (('source_sha256', 'b' * 64), ('scope', 'static_login_backend_wire_preparation'),
                ('method', 'fixture'), ('schema', True), ('matrix_sha256', '0' * 64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.validate_report(dict(self.good, **{key: value}), context(), self.parent)

    def test_exact_order_missing_duplicate_and_aggregate_summary_not_just_count(self):
        for change in ('missing', 'duplicate', 'swapped', 'summary'):
            bad = dict(self.good, cases=list(self.rows), summary=dict(self.good['summary']))
            if change == 'missing': bad['cases'].pop()
            elif change == 'duplicate': bad['cases'][-1] = self.rows[0]
            elif change == 'swapped': bad['cases'][0], bad['cases'][1] = bad['cases'][1], bad['cases'][0]
            else: bad['summary']['transport_calls'] -= 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.validate_report(bad, context(), self.parent)

    def test_independent_parent_mutations_cannot_replace_prepared_expectations(self):
        parent = copy.deepcopy(self.parent)
        parent['cases'][0]['strings']['0x10'] = 'one old return differs'
        with self.assertRaises(ValueError): oracle.prepared_rows(parent)
        parent = dict(self.parent, source_sha256='b' * 64)
        with self.assertRaises(ValueError): contract.validate_report(self.good, context(), parent)
        bad = dict(self.good, metadata_fields=[dict(key='changed')])
        with self.assertRaises(ValueError): contract.validate_report(bad, context(), self.parent)

    def test_expected_rows_do_not_mutate_parent_or_reference_bytes(self):
        before = contract.canonical(self.parent)
        first = oracle.expected_case(self.specs[0], self.prepared)
        first['publisher']['vptrs'].clear(); first['strings']['0x10'] = 'mutated copy'
        self.assertEqual(contract.canonical(self.parent), before)
        self.assertEqual(oracle.expected_case(self.specs[0], self.prepared), self.rows[0])

    def test_verifier_diagnostics_preserve_actual_and_bound_difference_paths(self):
        actual = copy.deepcopy(self.rows[0]); actual['wire']['transport_hex'] = 'wrong'
        changes = verifier.differences(actual, self.rows[0])
        self.assertEqual(changes, [dict(path='$.wire.transport_hex', actual='wrong',
                                      expected=self.rows[0]['wire']['transport_hex'])])
        self.assertEqual(len(verifier.differences([0] * 30, [1] * 30)), 16)
        with mock.patch.object(contract, 'tools', return_value={'frozen': 'a' * 64}):
            payload = verifier.failure_payload(dict(context(), transfer_proof={'path': 'proof', 'sha256': 'a' * 64}),
                contract, self.specs[0], actual, self.rows[0], ValueError('different'))
        self.assertIs(payload['actual'], actual)
        self.assertFalse(payload['accepted'])
        self.assertEqual(payload['method'], 'bounded_native_failure_diagnostic')
        self.assertEqual(payload['differences'], changes)


class BackendVerifierFixtureTests(unittest.TestCase):
    def test_early_native_or_fixture_guard_failure_has_no_fabricated_actual_row(self):
        parent = parent_report()
        spec = contract.scenarios()[0]
        ctx = dict(context(), transfer_proof={'path': 'proof', 'sha256': 'a' * 64},
            exports={}, functions={'prepare': '0x1000'}, leaves={}, tails={})
        reduced = SimpleNamespace(**{key: value for key, value in vars(contract).items() if not key.startswith('__')})
        reduced.scenarios = lambda: [spec]
        reduced.tools = lambda: {'frozen': 'a' * 64}
        reduced.validate_report = mock.Mock()
        native_guard = ValueError('exact caller or allocation owner differs')
        run = mock.Mock(side_effect=native_guard)
        h = SimpleNamespace(uc=object(), evidence={})
        snapshot = mock.Mock(return_value=Path('failure/manifest.json'))
        modules = {'portable-native-family': object(), 'login-backend-wire-native-contracts': reduced,
            'login-backend-wire-native-oracle': oracle,
            'verify-login-backend-wire-harness': SimpleNamespace(make_harness=lambda *a, **kw: h,
                MemoryPolicy=lambda uc: uc),
            'login-backend-wire-runtime': SimpleNamespace(install=lambda *args: run),
            'research-workflow': SimpleNamespace(snapshot=snapshot)}
        with mock.patch.object(verifier, 'dependencies', return_value=({}, {}, parent)), \
                mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                self.assertRaisesRegex(ValueError, 'execution failed') as caught:
            verifier.verify(ctx, 'resource-root')
        payload = snapshot.call_args.args[2]
        self.assertIsNone(payload['actual']); self.assertIsNone(payload['expected'])
        self.assertFalse(payload['actual_row_available']); self.assertFalse(payload['accepted'])
        self.assertEqual(payload['differences'], [])
        self.assertEqual(payload['state'], 'native_execution_failure')
        self.assertEqual(payload['error'], str(native_guard))
        self.assertIs(caught.exception.__cause__, native_guard)
        run.assert_called_once_with(spec)
        reduced.validate_report.assert_not_called()

    def test_verifier_collects_actual_callback_rows_and_passes_all_three_code_kinds(self):
        parent = parent_report(); prepared = oracle.prepared_rows(parent)
        specs = contract.scenarios()[:2]
        calls = []
        def run(spec):
            calls.append(spec)
            return oracle.expected_case(spec, prepared)
        ctx = dict(context(), exports={'whole-export': 'a' * 64},
            functions={'prepare': '0x1000'}, leaves={'0x2000': 'c3'}, tails={'0x3000': 'eb00'})
        raw_uc, wrapped_uc = object(), object()
        h = SimpleNamespace(uc=raw_uc, evidence={'source': 'fixture-only'})
        harness = SimpleNamespace(make_harness=mock.Mock(return_value=h),
            MemoryPolicy=mock.Mock(return_value=wrapped_uc), runtime_inputs=lambda: {'fixture_only': True})
        runtime = SimpleNamespace(install=mock.Mock(return_value=run))
        reduced_contract = SimpleNamespace(**{key: value for key, value in vars(contract).items()
            if not key.startswith('__')})
        reduced_contract.scenarios = lambda: specs
        reduced_contract.validate_report = mock.Mock()
        modules = {'portable-native-family': object(), 'login-backend-wire-native-contracts': reduced_contract,
            'login-backend-wire-native-oracle': oracle, 'verify-login-backend-wire-harness': harness,
            'login-backend-wire-runtime': runtime}
        prepare, wire = {'fixture': 'prepare'}, {'fixture': 'wire'}
        with mock.patch.object(verifier, 'dependencies', return_value=(prepare, wire, parent)), \
                mock.patch.object(verifier, 'load', side_effect=modules.__getitem__):
            result = verifier.verify(ctx, 'resource-root')
        self.assertEqual(calls, specs)
        self.assertEqual(result['cases'], [oracle.expected_case(spec, prepared) for spec in specs])
        self.assertIs(h.uc, wrapped_uc)
        harness.MemoryPolicy.assert_called_once_with(raw_uc)
        harness.make_harness.assert_called_once_with(ctx, ctx['exports'], {0x1000},
            leaves={0x2000: 'c3'}, tails={0x3000: 'eb00'}, root='resource-root')
        runtime.install.assert_called_once_with(h, prepare, ctx, wire, reduced_contract)
        reduced_contract.validate_report.assert_called_once_with(result, ctx, parent)

    def test_verifier_completed_mismatch_saves_actual_without_manufacturing_a_report(self):
        parent = parent_report(); prepared = oracle.prepared_rows(parent)
        spec = contract.scenarios()[0]
        actual = oracle.expected_case(spec, prepared)
        actual['wire']['transport_hex'] = 'bad-actual'
        ctx = dict(context(), transfer_proof={'path': 'proof', 'sha256': 'a' * 64},
            exports={}, functions={'prepare': '0x1000'}, leaves={}, tails={})
        reduced = SimpleNamespace(**{key: value for key, value in vars(contract).items() if not key.startswith('__')})
        reduced.scenarios = lambda: [spec]
        reduced.tools = lambda: {'frozen': 'a' * 64}
        reduced.validate_report = mock.Mock()
        h = SimpleNamespace(uc=object(), evidence={})
        snapshot = mock.Mock(return_value=Path('failure/manifest.json'))
        modules = {'portable-native-family': object(), 'login-backend-wire-native-contracts': reduced,
            'login-backend-wire-native-oracle': oracle,
            'verify-login-backend-wire-harness': SimpleNamespace(make_harness=lambda *a, **kw: h,
                MemoryPolicy=lambda uc: uc),
            'login-backend-wire-runtime': SimpleNamespace(install=lambda *args: lambda s: actual),
            'research-workflow': SimpleNamespace(snapshot=snapshot)}
        with mock.patch.object(verifier, 'dependencies', return_value=({}, {}, parent)), \
                mock.patch.object(verifier, 'load', side_effect=modules.__getitem__), \
                self.assertRaisesRegex(ValueError, 'diagnostic'):
            verifier.verify(ctx, 'resource-root')
        payload = snapshot.call_args.args[2]
        self.assertIs(payload['actual'], actual)
        self.assertEqual(payload['actual']['wire']['transport_hex'], 'bad-actual')
        self.assertNotEqual(payload['expected']['wire']['transport_hex'], 'bad-actual')
        reduced.validate_report.assert_not_called()

    def test_dependency_resolution_uses_declared_handoff_and_checks_proof_links(self):
        sha = 'a' * 64
        pointer = lambda name: dict(path=name, sha256=sha)
        ctx = dict(context(), handoff_context=pointer('handoff'), wire_context=pointer('wire'),
            transfer_proof=pointer('proof'))
        parent = parent_report()
        handoff = dict(source_sha256=sha, prepare_context=pointer('prepare'),
            transfer_proof=pointer('parent-proof'))
        values = dict(handoff=handoff, wire=dict(source_sha256=sha,
            packets={'game-login': dict(object_size=320, fields=[list(row) for row in contract.BYTES.FIELDS])}),
            prepare=dict(source_sha256=sha),
            proof=dict(target=dict(source_sha256=sha), dependencies=dict(handoff=pointer('handoff'),
                wire=pointer('wire'), prepare_check=pointer('parent'),
                handoff_check=pointer('handoff-report'), wire_check=pointer('wire-report'))),
            parent=parent, **{'parent-proof': dict(target=dict(source_sha256=sha),
                dependencies=dict(prepare_check=pointer('parent'))),
                'handoff-report': dict(source_sha256=sha), 'wire-report': dict(source_sha256=sha)})
        checked = []
        def check(root, ref, kind):
            checked.append((ref['path'], kind)); return values[ref['path']]
        original = verifier.load
        fake_parent = SimpleNamespace(validate_report=mock.Mock())
        def modules(name):
            return fake_parent if name == 'login-send-handoff-case-contracts' else original(name)
        with mock.patch.object(verifier, 'load', side_effect=modules):
            prepare, wire, prepared = verifier.dependencies(ctx, 'resource-root', SimpleNamespace(checked=check))
            self.assertIs(prepare, values['prepare']); self.assertIs(wire, values['wire']); self.assertIs(prepared, parent)
            fake_parent.validate_report.assert_called_once_with(values['handoff-report'], handoff, parent)
            self.assertIn(('prepare', 'generated-native-contexts'), checked)
            values['proof']['dependencies']['prepare_check'] = pointer('another-parent')
            with self.assertRaisesRegex(ValueError, 'links'):
                verifier.dependencies(ctx, 'resource-root', SimpleNamespace(checked=check))


if __name__ == '__main__':
    unittest.main()
