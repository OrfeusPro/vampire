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


class TileRefreshTests(unittest.TestCase):
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
