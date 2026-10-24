"""Reviewed offline current-source replay; no process, network or profile access."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('tile_refresh_replay', HERE / 'replay-nktileview-refresh.py')
replay = importlib.util.module_from_spec(spec); spec.loader.exec_module(replay)


class TileRefreshTests(unittest.TestCase):
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
