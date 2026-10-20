import importlib.util
import json
from pathlib import Path
import unittest


class WorldLoadPredicateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-world-load-predicate.py'
        spec = importlib.util.spec_from_file_location('world_load_predicate_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/world-load-predicate-replay.json').read_text('utf-8'))

    def test_native_evidence_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual((len(self.report['synthetic']), len(self.report['real']), len(self.report['composed'])), (81, 10, 6))
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['live_registry_verified'])

    def test_path_comparison_is_not_world_id_comparison(self):
        by_pair = {(c['current'], c['target']): c for c in self.report['synthetic']}
        # Different IDs, equal ASCII spelling modulo case: no load.
        for pair in ((11, 12), (13, 14)):
            self.assertEqual(by_pair[pair]['result'], 0)
            self.assertEqual(by_pair[pair]['compare_calls'], 1)
        self.assertEqual(by_pair[(16, 17)]['result'], 1)  # Non-ASCII case is not folded.
        for pair in ((9, 9), (9, 10), (10, 9), (10, 10)):
            self.assertEqual(by_pair[pair]['result'], 0)  # Missing / empty.
            self.assertEqual(by_pair[pair]['compare_calls'], 0)
        self.assertEqual(by_pair[(9, 11)]['result'], 1)
        self.assertEqual(by_pair[(11, 9)]['result'], 1)
        self.assertEqual([c['result'] for c in self.report['allocated_empty']], [0, 0, 0, 1])
        self.assertEqual([c['compare_calls'] for c in self.report['allocated_empty']], [0, 0, 0, 0])
        for row in self.report['real']:
            case = row['case']
            self.assertEqual(case['result'], int(case['current_path'] != case['target_path']))
        self.assertEqual(self.report['source_tables']['source_row2_label_verified'], True)

    def test_composed_id204_uses_actual_paths_after_data_application(self):
        expected = [(0, 1, 0), (0, 0, 1), (1, 0, 0), (1, 0, 0), (0, 0, 1), (0, 0, 0)]
        for case, effects in zip(self.report['composed'], expected):
            actions = [e['action'] for e in case['events']]
            observed = tuple(actions.count(name) for name in (
                'load_state_capture', 'finish_packet_capture', 'load_callback_capture'))
            self.assertEqual(observed, effects)
            predicates = [e for e in case['events'] if e['action'] == 'native_level_predicate_composed']
            if case['input']['code']:
                self.assertEqual(predicates, [])
            else:
                self.assertEqual(len(predicates), 1)
                self.assertEqual(predicates[0]['current'], case['input']['current_world'])
                self.assertEqual(predicates[0]['target'], case['decoded']['fields']['0x14'])
            self.assertEqual(case['state']['status30'], 5 if effects[1] else 2)


if __name__ == '__main__':
    unittest.main()
