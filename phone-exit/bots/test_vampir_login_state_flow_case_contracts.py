"""Pure integration matrix and strict native-state/provenance mutations."""
import copy
from collections import Counter
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


contract = load('login-state-flow-case-contracts')
oracle = load('login-state-flow-oracle')


def context():
    return dict(source_sha256='a' * 64, family=contract.FAMILY, format=contract.FORMAT,
        packet_bytes=352, packet_allocation_bytes=344, owner_bytes=80, node_bytes=40, framing_minimum=5,
        continuation_bytes=1024, post_state_service_bytes=768, post_state_actor_bytes=832, post_state_class_bytes=64)


def report():
    return dict(schema=1, method='bounded_native', source_sha256='a' * 64, scope=contract.SCOPE,
        cases=[oracle.expected_case(spec) for spec in contract.scenarios()],
        framing_precondition='frame_size_at_least_5', initial_context_precondition='active_packet_and_tls_zero',
        **dict.fromkeys(contract.TRUE_FLAGS, True), **dict.fromkeys(contract.FALSE_FLAGS, False))


class StateFlowContractTests(unittest.TestCase):
    def test_exact_cartesian_matrix_and_five_negative_deliveries(self):
        rows = contract.scenarios()
        self.assertEqual(contract.case_count(), 325)
        self.assertEqual(len(rows), 325)
        self.assertEqual(len({contract.canonical(row) for row in rows}), 325)
        self.assertEqual(Counter(row['group'] for row in rows),
            {'state-flow': 320, 'negative-handler': 4, 'negative-reader': 1})
        self.assertEqual(Counter(row['kind'] for row in rows), {'delivery': 325})
        pairs = {(contract.canonical(row['post_settings']), contract.canonical(row['continuation_settings'])) for row in rows[:320]}
        self.assertEqual(len(pairs), 40 * 8)
        self.assertTrue(all(row['post_settings']['flag'] == 1 for row in rows))

    def test_child_settings_reused_without_running_the_old_native_suites(self):
        post = [settings for direct, settings in contract.POST_STATE.matrix() if not direct]
        self.assertEqual(contract.post_settings(), post)
        self.assertEqual(len(post), 40)
        self.assertEqual(len(contract.continuation_settings()), 8)
        self.assertEqual([row['composition'] for row in contract.scenarios()[:320]],
            [dict(kind='full', scenario={})] * 320)

    def test_post_early_exits_do_not_short_circuit_native_continuation(self):
        rows = contract.scenarios()[:320]
        gates = [row for row in rows if not oracle.expected_case(row)['post_state']['target_entry']]
        self.assertEqual(len(gates), 3 * 8)
        for spec in gates:
            row = oracle.expected_case(spec)
            self.assertEqual(row['post_state']['wrapper_calls'], 1)
            self.assertEqual(row['post_state']['getter_calls'], 1)
            self.assertEqual(row['continuation']['reset_calls'], 1)
            self.assertTrue(row['continuation']['reset_via_source_vtable'])

    def test_native_post_target_early_exits_keep_slot_and_still_reset_continuation(self):
        seeds = contract.scenarios()[35 * 8:38 * 8]
        self.assertEqual(len(seeds), 24)
        for spec in seeds:
            row = oracle.expected_case(spec)
            self.assertEqual(row['post_state']['getter_calls'], 2)
            self.assertEqual(len(row['post_state']['target_entry']), 1)
            self.assertEqual(row['post_state']['writes'], [])
            self.assertEqual(row['post_state']['slot'], 0xaabbccdd)
            self.assertEqual(row['continuation']['reset_calls'], 1)

    def test_all_post_store_sites_and_chunk_bounds_are_separate(self):
        rows = [oracle.expected_case(spec)['post_state'] for spec in contract.scenarios()[:320]]
        self.assertEqual({write['instruction_offset'] for row in rows for write in row['writes']}, {211, 338, 356})
        zero_count = next(row for row in rows if row['settings']['object_count'] == 0)
        chunk_one = next(row for row in rows if row['settings']['object_index'] == 0x10005)
        self.assertEqual(zero_count['writes'][0]['instruction_offset'], 356)
        self.assertEqual(chunk_one['writes'][0]['instruction_offset'], 338)
        self.assertEqual(zero_count['events'][-1], 'mark')
        self.assertEqual(chunk_one['events'][-1], 'mark')

    def test_post_projection_omits_standalone_raw_return_and_absolute_stack(self):
        row = oracle.expected_case(contract.scenarios()[0])['post_state']
        self.assertNotIn('returned', row)
        self.assertNotIn('initial_rax', row)
        self.assertNotIn('stack', row['target_entry'][0])
        self.assertTrue(row['target_entry'][0]['tail_stack_preserved'])
        self.assertEqual(row['writes'], [dict(offset='0x250', size=8, value=0, instruction_offset=356)])

    def test_continuation_reuses_instruction_derived_reset_events_and_stores(self):
        for spec in contract.scenarios()[:8]:
            row = oracle.expected_case(spec)['continuation']
            wanted = contract.CONTINUATION.continuation_case(row['level'], row['capacity'], dict(base_table='0x0', table='0x0'))
            if row['level'] <= 1:
                wanted['events'][0]['second'] = 'source_vtable_low32'
            self.assertEqual(row['values'], wanted['values'])
            self.assertEqual(row['events'], wanted['events'])
            self.assertEqual(row['writes'], wanted['writes'])
            self.assertEqual(row['ctor_vptrs'], ['base_table', 'table'])
            self.assertTrue(row['constructor_published_singleton'])
            self.assertFalse(row['reset_state_unchanged'])

    def test_low_first_helper_retains_checked_source_vtable_without_changing_frozen_child(self):
        for spec in contract.scenarios()[:8]:
            settings = spec['continuation_settings']
            actual = oracle.expected_case(spec)['continuation']['events']
            frozen = contract.CONTINUATION.continuation_case(settings['level'], settings['capacity'],
                dict(base_table='0x0', table='0x0'))['events']
            self.assertEqual(frozen[0]['second'], 0)
            if settings['level'] <= 1:
                self.assertEqual((actual[0]['call_offset'], actual[0]['second']), (43, 'source_vtable_low32'))
            else:
                self.assertEqual((actual[0]['call_offset'], actual[0]['second']), (62, 0))
            self.assertTrue(all(event['second'] == 0 for event in actual[1:]))

    def test_raw_or_zero_low_carry_and_symbolic_high_carry_cannot_replace_exact_projection(self):
        for index, bad in ((0, 0), (0, 1238083864), (4, 'source_vtable_low32')):
            spec = contract.scenarios()[index]; row = oracle.expected_case(spec)
            row['continuation']['events'][0]['second'] = bad
            with self.subTest(index=index, bad=bad), self.assertRaises(ValueError):
                oracle.validate_case(row, spec)

    def test_continuation_level_and_capacity_boundaries_do_not_share_one_outcome(self):
        rows = [oracle.expected_case(spec)['continuation'] for spec in contract.scenarios()[:8]]
        self.assertEqual([row['values']['0xf0'] for row in rows], [0, 0, 1, 1, 1, 1, 1, 1])
        self.assertEqual([len(row['events']) for row in rows], [14, 17] * 4)
        self.assertEqual([len(row['writes']) for row in rows], [19, 22, 19, 22, 26, 29, 26, 29])

    def test_negative_handler_paths_never_enter_post_or_reset(self):
        for spec in contract.scenarios()[320:324]:
            row = oracle.expected_case(spec)
            self.assertEqual(row['dispatch']['handler_calls'], 1)
            self.assertEqual(row['post_state']['wrapper_calls'], 0)
            self.assertEqual(row['post_state']['getter_calls'], 0)
            self.assertEqual(row['post_state']['target_entry'], [])
            cont = row['continuation']
            self.assertEqual((cont['constructor_calls'], cont['getter_calls'], cont['reset_calls']), (1, 0, 0))
            self.assertIsNone(cont['values'])
            self.assertEqual((cont['field308'], cont['flag']), (0xffff, 1))
            self.assertTrue(cont['reset_state_unchanged'])
            self.assertEqual(cont['events'], [])
            self.assertEqual(cont['writes'], [])

    def test_empty_body_observes_name_getter_diagnostic_and_cleanup_without_handler(self):
        spec = contract.scenarios()[-1]
        self.assertEqual(contract.frame_body(spec), b'')
        row = oracle.expected_case(spec)
        self.assertIsNone(row['handler'])
        self.assertEqual(row['dispatch']['handler_calls'], 0)
        self.assertEqual(row['dispatch']['name_getter_calls'], 1)
        self.assertEqual(row['dispatch']['archive']['cleanup_chain'], ['reader', 'buffer', 'archive', 'base'])
        self.assertEqual(row['continuation']['reset_calls'], 0)

    def test_first_positive_observes_actual_rehash_without_adding_parent_matrix(self):
        first = contract.scenarios()[0]
        self.assertEqual(first['before_keys'], [0, 1, 2, 3, 5, 6, 7, 8])
        self.assertEqual(contract.expected_setup(first)['rehash_calls'], 1)
        self.assertEqual(contract.expected_setup(first)['insert_calls'], 9)
        self.assertTrue(all(not spec['before_keys'] for spec in contract.scenarios()[1:]))

    def test_admitted_standalone_lookup_is_not_claimed_as_executed(self):
        self.assertIn('native_lookup_used', contract.DISPATCH.TRUE_FLAGS)
        self.assertNotIn('native_lookup_used', contract.TRUE_FLAGS)
        self.assertIn('native_lookup_used', contract.FALSE_FLAGS)
        self.assertTrue(all(oracle.expected_case(spec)['dispatch']['lookup_calls'] == 0
            for spec in contract.scenarios()))

    def test_handler_fixture_markers_are_replaced_by_native_projections(self):
        spec = contract.scenarios()[0]
        parent = contract.DISPATCH.expected_case(spec)
        row = oracle.expected_case(spec)
        self.assertEqual(row['reader'], parent['reader'])
        self.assertEqual(row['dispatch'], parent['dispatch'])
        expected = [event for event in parent['handler']['events'] if event['action'] not in ('post_state', 'virtual_view')]
        self.assertEqual(row['handler']['events'], expected)
        self.assertFalse(any(event['action'] in ('post_state', 'virtual_view') for event in row['handler']['events']))

    def test_exact_report_validates(self):
        contract.validate_report(report(), context())

    def test_source_schema_family_and_declared_extents_are_exact(self):
        value = report()
        for key, bad in [('owner_bytes', 72), ('packet_allocation_bytes', 352), ('packet_bytes', True),
                         ('continuation_bytes', 1000), ('post_state_actor_bytes', 768),
                         ('post_state_class_bytes', 32), ('post_state_service_bytes', 832),
                         ('family', 'login-dispatch'), ('format', 'login-dispatch-v1'), ('source_sha256', 'b' * 64)]:
            wrong = context(); wrong[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.validate_report(value, wrong)
        for key, bad in [('scope', 'session'), ('schema', True), ('method', 'fixture'),
                         ('framing_precondition', 'native_short_header'), ('initial_context_precondition', 'stale_tls')]:
            wrong = dict(value); wrong[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.validate_report(wrong, context())

    def test_native_and_fixture_boundaries_require_literal_bools(self):
        value = report()
        for key in contract.TRUE_FLAGS + contract.FALSE_FLAGS:
            for bad in (not value[key], int(value[key])):
                wrong = dict(value); wrong[key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    contract.validate_report(wrong, context())

    def test_missing_duplicate_reordered_or_wrong_batch_rows_fail(self):
        value = report()
        for action in ('missing', 'duplicate', 'reordered'):
            wrong = dict(value); wrong['cases'] = list(value['cases'])
            if action == 'missing': wrong['cases'].pop()
            elif action == 'duplicate': wrong['cases'][-1] = wrong['cases'][0]
            else: wrong['cases'][0], wrong['cases'][1] = wrong['cases'][1], wrong['cases'][0]
            with self.subTest(action=action), self.assertRaises(ValueError):
                contract.validate_report(wrong, context())

    def test_native_state_call_binding_and_preparation_mutations_fail(self):
        spec = contract.scenarios()[0]; value = oracle.expected_case(spec)
        edits = [lambda r: r.update(packet_reseeded=True), lambda r: r.update(providers_prepared_before_delivery=False),
            lambda r: r.update(continuation_reseeded_at_handler=True),
            lambda r: r['post_state'].update(wrapper_calls=0), lambda r: r['post_state'].update(getter_calls=1),
            lambda r: r['post_state']['target_entry'][0].update(tail_stack_preserved=False),
            lambda r: r['post_state']['target_entry'][0].update(flag=0),
            lambda r: r['post_state']['writes'][0].update(instruction_offset=338),
            lambda r: r['post_state'].update(slot=0xdeadbeef),
            lambda r: r['continuation'].update(ctor_vptrs=['table', 'base_table']),
            lambda r: r['continuation'].update(constructor_published_singleton=False),
            lambda r: r['continuation'].update(reset_via_source_vtable=False),
            lambda r: r['continuation']['events'][0].update(call_offset=62),
            lambda r: r['continuation']['writes'][0].update(value=1),
            lambda r: r['continuation']['values'].update({'0xf0': 9}),
            lambda r: r['continuation'].update(unattributed_store=True)]
        for edit in edits:
            wrong = copy.deepcopy(value); edit(wrong)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                oracle.validate_case(wrong, spec)

    def test_negative_paths_reject_coordinator_injected_native_state(self):
        spec = contract.scenarios()[320]; value = oracle.expected_case(spec)
        for path in ('post', 'reset', 'unchanged'):
            wrong = copy.deepcopy(value)
            if path == 'post': wrong['post_state']['wrapper_calls'] = 1
            elif path == 'reset': wrong['continuation']['reset_calls'] = 1
            else: wrong['continuation']['reset_state_unchanged'] = False
            with self.subTest(path=path), self.assertRaises(ValueError):
                oracle.validate_case(wrong, spec)


if __name__ == '__main__': unittest.main()
