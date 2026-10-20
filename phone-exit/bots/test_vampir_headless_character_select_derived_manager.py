import importlib.util
import json
from pathlib import Path
import unittest


class CharacterSelectDerivedManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-character-select-derived-manager.py'
        spec = importlib.util.spec_from_file_location('derived_manager_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/character-select-derived-manager-replay.json').read_text('utf-8'))

    def test_actual_factory_and_derived_override_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 18)
        self.assertEqual(self.report['null_allocation_return'], 0)
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['reserve_trigger_verified'])

    def test_derived_effects_are_reached_only_after_accepted_selection(self):
        for case in self.report['cases']:
            accepted = case['code'] == 0 or (case['code'] == 0x1197 and case['gate_state'] == 0)
            events = case['events']
            actions = [e['action'] for e in events]
            apply = [e for e in events if e['action'] == 'derived_slot60_capture']
            self.assertEqual(actions.count('native_derived_slot58'), int(accepted))
            self.assertEqual(len(apply), int(accepted))
            if apply:
                self.assertEqual(apply[0], dict(action='derived_slot60_capture', index=27,
                                              value=case['secondary_value'], arg4=1, trailing=[0, 1, 1]))
                override_index = actions.index('native_derived_slot58')
                apply_index = actions.index('derived_slot60_capture')
                refresh_index = next(i for i, e in enumerate(events)
                                     if e['action'] == 'native_post_manager' and e['address'] == self.tool.base.REFRESH)
                self.assertLess(override_index, apply_index)
                self.assertLess(apply_index, refresh_index)
            self.assertEqual(case['raw2728'], case['decoded_raw20'] if accepted else 7)
            self.assertEqual(case['status30'], int(accepted))

    def test_entry71_flag_is_independent_of_callback_gates(self):
        for case in self.report['cases']:
            accepted = case['code'] == 0 or (case['code'] == 0x1197 and case['gate_state'] == 0)
            self.assertEqual(case['flag'], int(case['mode'] != 'empty') if accepted else 0xa5)
            self.assertEqual((case['queries'], case['config_queries']), (205, 205) if accepted else (0, 0))
            callbacks = [e for e in case['events'] if e['action'] == 'post_manager_callback_capture']
            self.assertEqual(len(callbacks), 203 if accepted and case['mode'] == 'active' else 0)


if __name__ == '__main__':
    unittest.main()
