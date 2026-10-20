import importlib.util
import json
from pathlib import Path
import unittest


class CharacterSelectPostManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-character-select-post-manager.py'
        spec = importlib.util.spec_from_file_location('post_manager_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/character-select-post-manager-replay.json').read_text('utf-8'))

    def test_native_chain_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 8)
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['reserve_trigger_verified'])

    def test_accepted_id110_updates_the_constructed_manager(self):
        for case in self.report['cases']:
            accepted = case['code'] == 0 or (case['code'] == 0x1197 and case['gate_state'] == 0)
            entries = [e['address'] for e in case['events'] if e['action'] == 'native_post_manager']
            expected = [self.tool.VALUE, self.tool.VIRTUAL58, self.tool.REFRESH] if accepted else []
            self.assertEqual(entries, expected)
            self.assertEqual(case['raw2728'], case['decoded_raw20'] if accepted else 7)
            self.assertEqual(case['status30'], int(accepted))
            self.assertEqual((case['queries'], case['config_queries']), (205, 205) if accepted else (0, 0))

    def test_refresh_requires_all_three_gates_and_skips_two_entries(self):
        for case in self.report['cases']:
            calls = [e for e in case['events'] if e['action'] == 'post_manager_callback_capture']
            accepted = case['code'] == 0 or (case['code'] == 0x1197 and case['gate_state'] == 0)
            if case['mode'] != 'active' or not accepted:
                self.assertEqual(calls, [])
                continue
            self.assertEqual(len(calls), 203)
            self.assertEqual([c['index'] for c in calls], [i for i in range(205) if i not in (146, 147)])
            self.assertEqual([c['value'] for c in calls], [1000 + i for i in range(205) if i not in (146, 147)])


if __name__ == '__main__':
    unittest.main()
