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


class TileRefreshTests(unittest.TestCase):
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
