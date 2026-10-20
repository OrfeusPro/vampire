"""Source-bound numeric Login input: native caller, CRT quirks and separate server ID."""
import importlib.util
import json
from pathlib import Path
import unittest


class LoginRevisionInputTests(unittest.TestCase):
    def test_native_revision_scenarios_reproduce_and_keep_server_id_separate(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-login-revision-input.py'
        spec = importlib.util.spec_from_file_location('revision_input_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        saved = json.loads((tool.native.ROOT / 'code-clues/login-revision-input-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['cases']), 10)
        values = {case['patch_text_fixture']: case['extra_number'] for case in saved['cases']}
        self.assertEqual(values['Revision258269'], 258269)
        self.assertEqual(values['Revision258392'], 258392)
        self.assertEqual(values['Revision-1'], 0xffffffff)
        self.assertEqual(values['Revision42junk'], 42)
        self.assertEqual(values['short'], 0)
        self.assertEqual({case['selected_server_id'] for case in saved['cases']}, {251})
        self.assertEqual(saved['crt']['imported']['name'], '_wtoi')


if __name__ == '__main__': unittest.main()
