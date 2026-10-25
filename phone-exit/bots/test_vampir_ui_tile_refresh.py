"""Reviewed offline current-source replay; no process, network or profile access."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('tile_refresh_replay', HERE / 'replay-nktileview-refresh.py')
replay = importlib.util.module_from_spec(spec); spec.loader.exec_module(replay)
spec = importlib.util.spec_from_file_location('tile_packing_replay', HERE / 'replay-nktileview-packing.py')
packing = importlib.util.module_from_spec(spec); spec.loader.exec_module(packing)
spec = importlib.util.spec_from_file_location('tile_scroll_style_replay', HERE / 'replay-nktileview-scroll-style.py')
scroll_style = importlib.util.module_from_spec(spec); spec.loader.exec_module(scroll_style)
spec = importlib.util.spec_from_file_location('ui_resource_setter_replay', HERE / 'replay-ui-resource-setter.py')
resource_setter = importlib.util.module_from_spec(spec); spec.loader.exec_module(resource_setter)
spec = importlib.util.spec_from_file_location('ui_content_config_replay', HERE / 'replay-ui-content-config.py')
content_config = importlib.util.module_from_spec(spec); spec.loader.exec_module(content_config)
spec = importlib.util.spec_from_file_location('ui_config_callables_replay', HERE / 'replay-ui-config-callables.py')
config_callables = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_callables)
spec = importlib.util.spec_from_file_location('ui_config_payload_replay', HERE / 'replay-ui-config-payload.py')
config_payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_payload)
spec = importlib.util.spec_from_file_location('ui_config_reader_replay', HERE / 'replay-ui-config-reader.py')
config_reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_reader)
spec = importlib.util.spec_from_file_location('ui_config_uniqueness_replay', HERE / 'replay-ui-config-uniqueness.py')
config_uniqueness = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_uniqueness)
spec = importlib.util.spec_from_file_location('ui_config_consumers_replay', HERE / 'replay-ui-config-consumers.py')
config_consumers = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_consumers)
spec = importlib.util.spec_from_file_location('ui_string_assignment_replay', HERE / 'replay-ui-string-assignment.py')
string_assignment = importlib.util.module_from_spec(spec); spec.loader.exec_module(string_assignment)
spec = importlib.util.spec_from_file_location('ui_config_callers_inspector', HERE / 'inspect-ui-config-callers.py')
config_callers = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_callers)
spec = importlib.util.spec_from_file_location('ui_config_reload_replay', HERE / 'replay-ui-config-reload.py')
config_reload = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_reload)

spec = importlib.util.spec_from_file_location('ui_config_load_wrapper_replay', HERE / 'replay-ui-config-load-wrapper.py')
config_load = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_load)

spec = importlib.util.spec_from_file_location('ui_config_path_provider_replay', HERE / 'replay-ui-config-path-provider.py')
config_path = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_path)


spec = importlib.util.spec_from_file_location('ui_config_path_join_replay', HERE / 'replay-ui-config-path-join.py')
config_join = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_join)


spec = importlib.util.spec_from_file_location('ui_config_source_helpers_replay', HERE / 'replay-ui-config-source-helpers.py')
config_sources = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_sources)


spec = importlib.util.spec_from_file_location('ui_config_parser_core_replay', HERE / 'replay-ui-config-parser-core.py')
config_parser = importlib.util.module_from_spec(spec); spec.loader.exec_module(config_parser)


class TileRefreshTests(unittest.TestCase):
    def test_native_parser_core_and_compare_integrated_with_wrapper(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base = dict(source=source, source_sha256=replay.getter.SHA, question='ui-nktileview-property-schema')
        result = config_parser.run(dict(base, functions=[dict(address=hex(a)) for a in config_parser.ROOTS]),
            dict(base, functions=[dict(address='0x14158edf0')]))
        self.assertEqual(len(result['core_cases']), 600)
        self.assertEqual(len(result['wrapper_cases']), 128)
        for case in result['wrapper_cases']:
            self.assertEqual(case['core_calls'], int(bool(case['input_units'])))
            self.assertNotIn('parse_core', case['services'])
        cases=[c for c in result['core_cases'] if c['capacity']==64 and c['extra']]
        unquoted={c['flag']:c for c in cases if c['input_fixture']==config_parser.KEY+'one,two)end'}
        self.assertEqual(unquoted[0]['result_utf16'], config_parser.units('one,two)end'))
        self.assertEqual(unquoted[1]['result_utf16'], config_parser.units('one'))
        self.assertTrue(all(c['success'] for c in cases if c['input_fixture']==config_parser.KEY))
        self.assertFalse(any(c['success'] for c in cases if c['input_fixture']=='x'+config_parser.KEY+'bad'))

    def test_native_manager_and_parser_buffer_cleanup_boundaries(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_sources.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_sources.ROOTS]))
        self.assertEqual(len(result['manager_cases']), 14)
        self.assertEqual(len(result['parser_cases']), 192)
        self.assertEqual(result['directory_static']['method'], 'static_only_not_executed')
        self.assertEqual({c['input_units'] for c in result['parser_cases']}, {0, 2, 3, 4095, 4096})
        for case in result['parser_cases']:
            self.assertEqual(case['large_buffer'], case['input_units'] >= 4096)
            self.assertEqual(case['success'], bool(case['input_units'] and case['core_result_fixture']))
            self.assertTrue(case['complete_return'])

    def test_native_counted_path_join_and_static_saved_source(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_join.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in (config_join.ROOT,0x141585780)]))
        self.assertEqual(len(result['cases']), 378)
        self.assertEqual(result['base_path_static']['method'], 'static_instructions_only_not_executed')
        self.assertIn('-saveddirsuffix=', result['base_path_static']['literals'])
        variants={(c['prefix'],c['suffix']):c['result'] for c in result['cases']}
        self.assertEqual(variants[('A','Config/')], 'A/Config/')
        self.assertEqual(variants[('A/','/Config/')], 'A//Config/')
        self.assertEqual(variants[('A','')], 'A/')
        self.assertEqual(variants[('A\0B','Config/')], 'A\0B/Config/')

    def test_native_path_provider_calls_native_join_on_same_memory(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base = dict(source=source, source_sha256=replay.getter.SHA, question='ui-nktileview-property-schema')
        result = config_path.run(dict(base, functions=[dict(address=hex(config_path.ROOT))]),
            dict(base, functions=[dict(address=hex(config_join.ROOT))]))
        self.assertTrue(result['native_join'])
        self.assertEqual(len(result['initial_cases']), 28)
        self.assertEqual(len(result['cached_cases']), 18)
        for case in result['initial_cases']:
            self.assertIn('append_native', case['services'])
            self.assertNotIn('append', case['services'])
            self.assertTrue(case['complete_return'])

    def test_native_config_path_provider_cached_and_initial_branches(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_path.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(config_path.ROOT))]))
        self.assertEqual(len(result['cached_cases']), 18)
        self.assertEqual(len(result['initial_cases']), 12)
        self.assertEqual(result['literals']['Config/']['address'], '0x1489f3fb0')
        self.assertEqual(result['atexit_target'], '0x14885e690')
        for case in result['initial_cases']:
            self.assertTrue(case['complete_return'])
            self.assertEqual(case['services'][-3:], ['append', 'atexit', 'footer'])

    def test_native_config_load_wrappers_forward_context_flags_and_low_byte(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_load.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_load.ROOTS]))
        self.assertEqual(len(result['path_cases']), 6)
        self.assertEqual(len(result['load_cases']), 768)
        self.assertEqual(result['context_fields'], dict(override_string='0x50', flag6='0x181', flag4='0x182', flag7='0x183'))
        self.assertEqual({c['loader_result'] for c in result['load_cases']}, {0, 1, 0x1234, 0x123400})
        for case in result['load_cases']:
            self.assertEqual(case['forwarded_low_byte'], case['loader_result'] & 255)
            self.assertTrue(case['complete_return'])

    def test_native_reload_wrapper_config_service_precedes_sparse_callbacks(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_reload.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(config_reload.ROOT))]))
        self.assertEqual(len(result['cases']), 48)
        self.assertEqual(sum(len(c['callbacks']) for c in result['cases']), 72)
        self.assertEqual(result['registry']['address'], '0x14b1867f0')
        self.assertEqual(result['registry']['stride'], '0x60')
        for case in result['cases']:
            self.assertEqual(case['callbacks'], case['occupied'])
            self.assertTrue(case['complete_return'])
            self.assertEqual(case['events'][:2], ['path_value', 'config_service'])

    def test_static_config_callers_preserve_diagnostic_scope_and_gates(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_callers.inspect(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_callers.ROOTS]))
        self.assertEqual(len(result['call_edges']), 7)
        self.assertEqual(len(result['literals']), 8)
        self.assertEqual(result['conditions']['special_keys'], ['~', 'Reload'])
        self.assertIn('count <=1', result['conditions']['missing_or_empty_value'])
        self.assertTrue(all(e['boundary_verified'] for e in result['call_edges']))
        with self.assertRaises(ValueError):
            config_callers.inspect(dict(source=source, source_sha256='0' * 64,
                question='ui-nktileview-property-schema', functions=[]))

    def test_native_registered_bindings_dispatch_after_replacement_and_reuse(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_reader.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_reader.DISPATCH_ROOTS]),
            native_replacement=True, native_hash=True, dispatch=True)
        self.assertEqual(len(result['cases']), 384)
        self.assertEqual(sum(len(c['dispatch_calls']) for c in result['cases']), 4608)
        self.assertEqual(sum(d['native_assignments'] for c in result['cases'] for d in c['dispatch_calls']), 1152)
        for case in result['cases']:
            self.assertEqual(len(case['dispatch_calls']), 12)
            self.assertEqual(sum(d['native_read_invokes'] for d in case['dispatch_calls']), 6)
            self.assertEqual(sum(d['slot'] is None for d in case['dispatch_calls']), 3)
            self.assertTrue(all(d['complete_return'] for d in case['dispatch_calls']))

    def test_native_string_assignment_identity_empty_and_resize_paths(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = string_assignment.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(string_assignment.ASSIGN))]))
        self.assertEqual(len(result['cases']), 80)
        self.assertEqual(len(result['identity_cases']), 4)
        for case in result['cases']:
            self.assertTrue(case['complete_return'])
            self.assertEqual(case['copy_calls'], int(not case['identity'] and case['native_units'] > 0))
            if case['value_fixture'] == 'A\0B': self.assertEqual(case['native_units'], 2)

    def test_native_assignment_runs_inside_config_consumer_write(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_consumers.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_consumers.ROOTS + (string_assignment.ASSIGN,)]),
            native_assignment=True)
        self.assertEqual(len(result['cases']), 96)
        self.assertEqual(sum(c['native_assignment_calls'] for c in result['cases']), 64)
        self.assertTrue(result['native_assignment'])

    def test_native_config_consumers_read_write_read_preserve_other_bindings(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_consumers.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_consumers.ROOTS]))
        self.assertEqual(len(result['cases']), 96)
        self.assertEqual(sum(c['complete_consumer_calls'] for c in result['cases']), 288)
        self.assertEqual(sum(c['native_read_invokes'] for c in result['cases']), 128)
        self.assertEqual(sum(c['native_write_invokes'] for c in result['cases']), 64)
        for case in result['cases']:
            self.assertEqual(len(case['reads']), 2)
            self.assertEqual(case['reads'][1]['missing_zeroed'], case['target_index'] is None)

    def test_native_counted_utf16_hash_matches_bitwise_reference(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_reader.key_hash.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(config_reader.key_hash.HASH))]))
        self.assertEqual(len(result['cases']), 537)
        self.assertEqual(len(result['consistency']), 8)
        for pair in result['consistency']:
            if pair['compared_equal'] and not pair['embedded_nul_synthetic']:
                self.assertEqual(pair['left_hash'], pair['right_hash'])
        adversarial = [p for p in result['consistency'] if p['embedded_nul_synthetic']]
        self.assertEqual(len(adversarial), 1)
        self.assertNotEqual(adversarial[0]['left_hash'], adversarial[0]['right_hash'])

    def test_native_hash_drives_reader_lookup_across_eight_buckets(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_reader.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_reader.HASH_ROOTS]),
            native_replacement=True, native_hash=True)
        self.assertEqual(len(result['cases']), 384)
        self.assertNotIn('hash_key', result['fixtures'])
        self.assertNotIn('uniqueness_false', result['fixtures'])
        for case in result['cases']:
            self.assertEqual(case['bucket_count'], 8)
            self.assertEqual(sorted(i for chain in case['native_bucket_chains'] for i in chain), [0, 1, 2])
            self.assertTrue(all(e['native_hash_calls'] == 1 and e['native_hash_result'] is not None for e in case['sequence']))

    def test_native_reader_replacement_and_free_slot_reuse_share_one_memory(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_reader.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_reader.REPLACEMENT_ROOTS]),
            native_replacement=True)
        self.assertEqual(len(result['cases']), 384)
        self.assertEqual(sum(len(c['sequence']) for c in result['cases']), 2304)
        self.assertNotIn('uniqueness_false', result['fixtures'])
        for case in result['cases']:
            self.assertEqual(case['native_bucket_chain'], [2, 1, 0])
            self.assertEqual(case['free_slot'], 3)
            self.assertEqual([e['retained_slot'] for e in case['sequence']], [0, 0, 1, 1, 2, 0])
            self.assertEqual(sum(e['replacement'] for e in case['sequence']), 3)
            self.assertEqual(sum(e['reused_slot'] for e in case['sequence']), 2)
            self.assertEqual(sum(e['native_compares'] for e in case['sequence']), 3)

    def test_native_config_key_lookup_and_replacement_preserve_hash_links(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base = dict(source=source, source_sha256=replay.getter.SHA, question='ui-nktileview-property-schema')
        result = config_uniqueness.run(dict(base, functions=[dict(address=hex(a)) for a in config_uniqueness.ROOTS]),
            dict(base, functions=[dict(address=hex(config_uniqueness.COMPARE))]))
        self.assertEqual(len(result['cases']), 512)
        self.assertEqual(sum(c['expected_match'] for c in result['cases']), 288)
        self.assertEqual(len(result['lookup_cases']), 8)
        self.assertEqual(len(result['fast_cases']), 2)
        for case in result['cases']:
            self.assertEqual(case['moves'], int(case['expected_match']))
            self.assertEqual(case['cleanups'], int(case['expected_match']) * sum(case['active']))

    def test_native_complete_config_reader_keeps_three_independent_bindings(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = config_reader.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=hex(a)) for a in config_reader.ROOTS]))
        self.assertEqual(len(result['cases']), 48)
        self.assertEqual(sum(len(c['sequence']) for c in result['cases']), 144)
        for case in result['cases']:
            self.assertEqual(case['native_bucket_chain'], [2, 1, 0])
            self.assertEqual([entry['previous_bindings_preserved'] for entry in case['sequence']], [0, 1, 2])
            for entry in case['sequence']:
                self.assertTrue(entry['complete_reader_return'])
                self.assertTrue(entry['moved_key_source_cleared'])
                self.assertEqual(entry['calls'].count('assign_string'), int(entry['found_fixture']))

    def test_native_config_callable_payload_copy_and_cleanup(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base = dict(source=source, source_sha256=replay.getter.SHA, question='ui-nktileview-property-schema')
        result = config_payload.run(dict(base, functions=[dict(address=hex(a)) for a in config_payload.ROOTS]),
            dict(base, functions=[dict(address=hex(a)) for a in config_payload.LEAVES]))
        self.assertEqual(len(result['copy_cases']), 48)
        self.assertEqual(len(result['cleanup_cases']), 16)
        self.assertEqual(len(result['address_cases']), 3)
        for case in result['copy_cases']:
            self.assertEqual(case['native_capture_copies'], sum(case['active']))
            self.assertTrue(case['complete_return'])
        for case in result['cleanup_cases']:
            self.assertEqual(case['deallocation_fixture_calls'], int(case['entry'] == '0x141421b80' and bool(case['flags'] & 1)))

    def test_native_config_string_clone_and_assignment_forwarding(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        base = dict(source=source, source_sha256=replay.getter.SHA, question='ui-nktileview-property-schema')
        result = config_callables.run(dict(base, functions=[dict(address=hex(a)) for a in config_callables.ROOTS]),
            dict(base, functions=[dict(address=hex(config_callables.LEAF))]))
        self.assertEqual(len(result['clone_cases']), 32)
        self.assertEqual(len(result['leaf_cases']), 3)
        self.assertEqual(sum(c['source_count'] == 0 for c in result['clone_cases']), 4)
        for case in result['clone_cases']:
            self.assertTrue(case['complete_return'])
            self.assertEqual(case['copies'], int(case['source_count'] != 0))
        self.assertEqual(result['registration']['status'], 'static_sparse_container_shape_not_event_dispatch')

    def test_native_config_lookup_prefix_and_missing_assignment(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = content_config.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address='0x1445c2c30')]))
        self.assertEqual(len(result['cases']), 26)
        self.assertEqual(sum(c['zero_length_fstring_fixture'] for c in result['cases']), 2)
        for case in result['cases']:
            self.assertEqual(case['lookup_calls'], 1)
            self.assertEqual(len(case['assignment_calls']), int(case['found_fixture']))
            self.assertTrue(case['stopped_before_callback_setup'])
            if case['found_fixture']:
                self.assertEqual(case['assignment_calls'][0]['utf16_units'], len(case['value_fixture'].encode('utf-16le')) // 2)

    def test_native_resource_setter_identity_and_cache_invalidation(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = resource_setter.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address=a) for a in ('0x14191ab70', '0x1445cf4f0')]))
        self.assertEqual(len(result['cases']), 54)
        self.assertEqual(sum(not c['changed'] for c in result['cases']), 18)
        self.assertEqual(result['resolver']['template'], '/UI/Resource/Texture/%s')
        self.assertIsNone(result['resolver']['global_prefix_value'])

    def test_native_scroll_style_fallback_preserves_existing_parameters(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = scroll_style.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address='0x144a8b800')]))
        self.assertEqual(len(result['cases']), 32)
        for case in result['cases']:
            existing = case['horizontal_present'] and case['vertical_present']
            self.assertEqual(case['requested_keys'], list(scroll_style.KEYS) if not existing and case['gate'] else [])
            self.assertEqual(case['scheduled_fixture_calls'], int(not existing and not case['gate']))

    def test_native_packing_prefix_and_cached_exits(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        result = packing.run(dict(source=source, source_sha256=replay.getter.SHA,
            question='ui-nktileview-property-schema', functions=[dict(address='0x144626640')]))
        self.assertEqual(len(result['cases']), 128)
        self.assertEqual(sum(c['complete_cached_exit'] for c in result['cases']), 32)
        self.assertTrue(all(c['entered_recalculation'] for c in result['cases'] if c['force_flag']))

    def test_native_wrapper_and_leaf_preserve_payload_and_call_order(self):
        source = json.loads((replay.native.ROOT / 'code-clues/ui-properties.json').read_text('utf-8'))['source']
        request = dict(source=source, source_sha256=replay.getter.SHA, question='ui-nktileview-property-schema',
                       functions=[dict(address=a) for a in ('0x144a8f220', '0x144626640')])
        result = replay.run(request)
        self.assertEqual(len(result['cases']), 24)
        for case in result['cases']:
            self.assertEqual(case['flags'], [0, 1] if case['receiver_present'] else [])
        self.assertIn('not_unwind', result['leaf']['boundary'])


if __name__ == '__main__':
    unittest.main()
