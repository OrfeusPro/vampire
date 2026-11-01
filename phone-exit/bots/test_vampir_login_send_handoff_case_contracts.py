"""Pure handoff coverage and source/ownership/fixture-boundary mutations."""
import copy
from collections import Counter
import importlib.util
import itertools
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


contract = load('login-send-handoff-case-contracts')
oracle = load('login-send-handoff-oracle')


def parent_report():
    cases = []
    for scenario, empty, old_return, metadata in itertools.product(
            contract.PREPARE.SCENARIOS, (False, True), (0, 1), contract.PARENT.INTEGRATION_CASES):
        main = scenario[2] and scenario[3] and bool(scenario[4] & 1)
        aux = scenario[2] and scenario[3] and bool(scenario[4] & 2)
        active = metadata[0] not in ('none', 'invalid')
        metadata_calls = contract.PARENT._native_calls(active) if aux else {}
        cases.append(dict(scenario=scenario[0], selector=3, empty=empty, send_return=old_return,
            poison=85, cache_case='warm', metadata_case=list(metadata), guards=True,
            strings={hex(offset): '' if empty else 'Ж🙂-"' for offset in oracle.STRING_OFFSETS},
            integers={hex(offset): 255 if offset == 0x131 and not empty else 0
                      for offset in oracle.SCALAR_WIDTHS},
            native_calls=dict(sdk_value=int(main)), metadata_calls=metadata_calls, sdk_event=main,
            lifecycle=['send', 'post_notify'] + (['sdk_event'] if main else []) + ['destructor']))
    return dict(schema=1, method='bounded_native', scope='bounded_native_login_prepare_metadata',
        source_sha256='a' * 64, cases=cases, native_sdk_used=True, native_metadata_used=True,
        network_used=False, profile_activated=False, runtime_activated=False,
        metadata_fields=[dict(key=key) for key in contract.PARENT.COLLECTOR_ORDER])


def context():
    return dict(source_sha256='a' * 64, family=contract.FAMILY, format=contract.FORMAT,
        packet_bytes=320, session_bytes=160)


def report(parent):
    prepared = oracle.prepared_rows(parent)
    return dict(schema=1, method='bounded_native', scope=contract.SCOPE, source_sha256='a' * 64,
        packet_bytes=320, session_bytes=160,
        metadata_fields=copy.deepcopy(parent['metadata_fields']),
        cases=[oracle.expected_case(spec, prepared) for spec in contract.scenarios()],
        **dict.fromkeys(contract.TRUE_FLAGS, True), **dict.fromkeys(contract.FALSE_FLAGS, False))


class SendHandoffCaseContractsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = parent_report()
        cls.prepared = oracle.prepared_rows(cls.parent)
        cls.specs = contract.scenarios()
        cls.good = report(cls.parent)

    def test_exact_matrix_uses224_inputs_and_four_pending_branches(self):
        self.assertEqual(contract.case_count(), 896)
        self.assertEqual(len(self.specs), 896)
        self.assertEqual(len({contract.canonical(row) for row in self.specs}), 896)
        self.assertEqual(len(self.prepared), 224)
        self.assertEqual(Counter(row['pending_case'] for row in self.specs), dict.fromkeys(contract.PENDING_CASES, 224))
        self.assertTrue(all('send_return' not in row for row in self.specs))
        contract.validate_report(self.good, context(), self.parent)

    def test_only_actual_lookup_hit_suppresses_all_downstream_calls(self):
        rows = self.good['cases'][:4]
        self.assertEqual([row['handoff']['forwarded'] for row in rows], [True, True, True, False])
        self.assertEqual([row['handoff']['observed_lookup_keys'] for row in rows], [[], [], [8], [8, 4]])
        self.assertEqual([row['handoff']['bucket_storage'] for row in rows], ['not-read', 'inline', 'heap', 'heap'])
        for row in rows:
            handoff = row['handoff']; count = int(handoff['forwarded'])
            self.assertEqual([handoff[key] for key in ('pending_insert_calls', 'delegate_calls',
                'service_getter_calls', 'sink_calls', 'source_virtual_calls')], [count] * 5)
            self.assertEqual(handoff['sender_returns'], 1)
            self.assertNotIn('returned', handoff)

    def test_heap_chain_keys_really_collide_with_query_in_four_buckets(self):
        query, bucket_count = 4, 4
        for name in ('heap-chain-miss', 'heap-chain-hit'):
            keys = contract.pending_settings(name)['lookup_keys']
            self.assertEqual(keys[0], 8)
            self.assertTrue(all(key & (bucket_count - 1) == query & (bucket_count - 1) for key in keys))
        self.assertNotEqual(5 & (bucket_count - 1), query & (bucket_count - 1))
        for index, stale_keys in ((2, [5]), (3, [5, 4])):
            row = copy.deepcopy(self.good['cases'][index])
            row['handoff']['observed_lookup_keys'] = stale_keys
            with self.subTest(index=index), self.assertRaises(ValueError):
                oracle.validate_case(row, self.specs[index], self.prepared)

    def test_inline_empty_query_bucket_can_coexist_with_one_live_other_key(self):
        query, existing_key, bucket_count = 4, 5, 2
        heads = [-1, 0]
        self.assertEqual(heads[query & (bucket_count - 1)], -1)
        self.assertEqual(heads[existing_key & (bucket_count - 1)], 0)
        pending = contract.pending_settings('inline-bucket-miss')
        self.assertEqual(pending['bucket_storage'], 'inline')
        self.assertEqual(pending['lookup_keys'], [])
        self.assertTrue(pending['forwarded'])

    def test_zero_fifth_argument_selects_exact_timeout_bits_only_on_forwarding(self):
        for row, pending in zip(self.good['cases'][:4], contract.PENDING_CASES):
            handoff = row['handoff']; expected = contract.PENDING_TIMEOUT_BITS[pending]
            self.assertEqual(handoff['configured_timeout_bits'], expected)
            self.assertEqual(handoff['entry_timeout_bits'], 0)
            self.assertEqual(handoff['selected_timeout_bits'], expected if handoff['forwarded'] else None)

    def test_parent_return_pairs_collapse_without_replaying_or_mutating_parent(self):
        before = contract.canonical(self.parent)
        self.assertEqual(len(oracle.prepared_rows(self.parent)), 224)
        self.assertEqual(contract.canonical(self.parent), before)
        self.assertEqual(self.good['cases'][0]['lifecycle'][0], 'sender_entry')
        self.assertEqual(self.parent['cases'][0]['lifecycle'][0], 'send')

    def test_parent_pair_divergence_duplicate_or_missing_row_rejected(self):
        for change in ('missing', 'duplicate', 'strings', 'native_calls', 'lifecycle'):
            parent = copy.deepcopy(self.parent)
            if change == 'missing': parent['cases'].pop()
            elif change == 'duplicate': parent['cases'][-1] = copy.deepcopy(parent['cases'][0])
            else:
                row = next(row for row in parent['cases'] if row['send_return'] == 1)
                if change == 'strings': row['strings']['0x10'] = 'changed'
                elif change == 'native_calls': row['native_calls']['sdk_value'] += 1
                else: row['lifecycle'] = ['send', 'destructor']
            with self.subTest(change=change), self.assertRaises(ValueError): oracle.prepared_rows(parent)

    def test_each_dimension_and_type_is_exact(self):
        for key, value in (('scenario', 'other'), ('selector', True), ('empty', 0), ('poison', 170),
                ('cache_case', 'resolve'), ('metadata_case', ['none', 'full', 0]), ('pending_case', 'other')):
            spec = copy.deepcopy(self.specs[0]); spec[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): oracle.expected_case(spec, self.prepared)
        for spec in ({}, dict(self.specs[0], send_return=0), None):
            with self.assertRaises(ValueError): contract.validate_spec(spec)

    def test_matrix_missing_extra_duplicate_or_reordered_row_rejected(self):
        for change in ('missing', 'extra', 'duplicate', 'reordered'):
            data = copy.deepcopy(self.good)
            if change == 'missing': data['cases'].pop()
            elif change == 'extra': data['cases'].append(copy.deepcopy(data['cases'][0]))
            elif change == 'duplicate': data['cases'][-1] = copy.deepcopy(data['cases'][0])
            else: data['cases'][0], data['cases'][1] = data['cases'][1], data['cases'][0]
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.validate_report(data, context(), self.parent)

    def test_same_packet_sink_arguments_and_native_getter_are_not_labels(self):
        for key, value in (('sink_arguments', dict(receiver='packet', packet='rebuilt')),
                ('sink_same_packet', False), ('service_getter_calls', 0), ('source_virtual_calls', 0),
                ('getter_global_checked', False), ('sender_arguments_checked', False),
                ('fifth_argument_checked', False), ('pending_insert_arguments_checked', False),
                ('delegate_arguments_checked', False), ('sink_arguments_checked', False)):
            row = copy.deepcopy(self.good['cases'][0]); row['handoff'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): oracle.validate_case(row, self.specs[0], self.prepared)

    def test_lookup_branch_observations_and_timeout_cannot_be_forged(self):
        for index, key, value in ((0, 'bucket_storage', 'inline'), (2, 'observed_lookup_keys', [4]),
                (3, 'observed_lookup_keys', [8]), (3, 'sink_calls', 1),
                (0, 'entry_timeout_bits', 1), (0, 'selected_timeout_bits', 0)):
            row = copy.deepcopy(self.good['cases'][index]); row['handoff'][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                oracle.validate_case(row, self.specs[index], self.prepared)

    def test_prepared_fields_raw_flag_and_lifecycle_are_independent_expectations(self):
        for change in ('string', 'raw_flag', 'bool_flag', 'cleanup', 'packet', 'pointee'):
            row = copy.deepcopy(self.good['cases'][0])
            if change == 'string': row['strings']['0xd8'] = 'forged-metadata'
            elif change == 'raw_flag': row['integers']['0x131'] = 1
            elif change == 'bool_flag': row['integers']['0x130'] = False
            elif change == 'cleanup': row['lifecycle'] = ['sender_entry', 'destructor']
            else: row['handoff']['packet_immutable' if change == 'packet' else 'strings_immutable'] = False
            with self.subTest(change=change), self.assertRaises(ValueError): oracle.validate_case(row, self.specs[0], self.prepared)

    def test_parent_raw_types_and_string_bounds_cannot_broaden(self):
        for value in (True, -1, 256):
            parent = copy.deepcopy(self.parent)
            for row in parent['cases']: row['integers']['0x131'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): oracle.prepared_rows(parent)
        for value in ('x\0y', '\ud800', 'x' * 1024):
            parent = copy.deepcopy(self.parent)
            for row in parent['cases']: row['strings']['0x10'] = value
            with self.subTest(value=repr(value)), self.assertRaises(ValueError): oracle.prepared_rows(parent)

    def test_scope_flags_and_context_extents_cannot_admit_wire_or_online(self):
        for flag in contract.TRUE_FLAGS + contract.FALSE_FLAGS:
            data = copy.deepcopy(self.good); data[flag] = not data[flag]
            with self.subTest(flag=flag), self.assertRaises(ValueError): contract.validate_report(data, context(), self.parent)
        for key, value in (('scope', 'bounded_native_login_prepare_wire'), ('schema', True),
                ('method', 'fixture'), ('source_sha256', 'b' * 64)):
            data = copy.deepcopy(self.good); data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): contract.validate_report(data, context(), self.parent)
        for key, value in (('packet_bytes', 352), ('session_bytes', True), ('format', 'send-handoff-v2')):
            ctx = context(); ctx[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): contract.validate_report(self.good, ctx, self.parent)

    def test_published_layout_is_required_and_uses_exact_integer_extents(self):
        for key, expected in (('packet_bytes', 320), ('session_bytes', 160)):
            for value in (None, True, False, float(expected), expected - 1, expected + 1):
                data = copy.deepcopy(self.good); data[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    contract.validate_report(data, context(), self.parent)
            data = copy.deepcopy(self.good); del data[key]
            with self.subTest(key=key, missing=True), self.assertRaises(ValueError):
                contract.validate_report(data, context(), self.parent)

    def test_no_emitted_bytes_or_raw_return_can_be_injected_into_handoff(self):
        for key, value in (('payload_hex', '0000'), ('native_wire_used', True), ('returned', 1)):
            row = copy.deepcopy(self.good['cases'][0]); row['handoff'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): oracle.validate_case(row, self.specs[0], self.prepared)
        data = copy.deepcopy(self.good); data['metadata_fields'][0]['key'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'provenance'): contract.validate_report(data, context(), self.parent)

    def test_actual_boolean_and_count_types_are_not_interchangeable(self):
        for key, value in (('forwarded', 1), ('sender_calls', True), ('sender_returns', 1.0),
                ('packet_immutable', 1), ('synthetic_service_vtable', 1)):
            row = copy.deepcopy(self.good['cases'][0]); row['handoff'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): oracle.validate_case(row, self.specs[0], self.prepared)


if __name__ == '__main__':
    unittest.main()
