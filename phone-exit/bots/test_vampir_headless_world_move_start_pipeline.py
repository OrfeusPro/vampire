"""Reader-to-service state and branching checks, with explicit engine captures."""
import importlib.util
import json
from pathlib import Path
import unittest


class WorldMoveStartPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-world-move-start-pipeline.py'
        spec = importlib.util.spec_from_file_location('start_pipeline_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/world-move-start-pipeline-replay.json').read_text('utf-8'))

    def test_native_pipeline_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 35)
        self.assertFalse(self.report['network_ready'])

    def test_result_gate_and_data_transfer(self):
        for case in self.report['cases']:
            inp, state, decoded = case['input'], case['state'], case['decoded']
            events = case['events']
            self.assertEqual(events[0]['action'], 'native_start_handler')
            self.assertEqual((decoded['returned'], decoded['consumed']), (1, 30))
            self.assertEqual([e['packet_id'] for e in events if e['action'] == 'native_gate'], [204])
            accepted = inp['code'] == 0 or (inp['code'] == 0x1197 and inp['gate_state'] != 1)
            self.assertEqual(sum(e['action'] == 'native_start_receive' for e in events), int(accepted))
            self.assertEqual(state['current40'], inp['current_world'])
            if accepted:
                self.assertEqual(state['previousf4'], inp['current_world'])
                self.assertEqual(state['target44'], inp['target_world'])
                self.assertEqual(state['kind59'], min(inp['new_kind'], 22))
                self.assertEqual(state['vector_hex'], decoded['vector_hex'])
            else:
                self.assertEqual((state['previousf4'], state['target44'], state['kind59']), (0, 0x12345678, 0))
                self.assertEqual(state['vector_hex'], '00' * 24)
                self.assertIn('start_error_ui_capture', [e['action'] for e in events])

    def test_load_reuse_and_alternate_paths_have_distinct_effects(self):
        sends, loads, callbacks = 0, 0, 0
        for case in self.report['cases']:
            inp, state = case['input'], case['state']
            actions = [e['action'] for e in case['events']]
            accepted = inp['code'] == 0 or (inp['code'] == 0x1197 and inp['gate_state'] != 1)
            reuse = inp['current_world'] == inp['target_world'] and (
                min(inp['new_kind'], 22) == 3 or
                (inp['old_kind'] == 3 and inp['new_kind'] == 0 and bool(inp['flag'])))
            load = accepted and inp['load_world']
            callback = accepted and not load and not inp['alternate'] and not reuse
            finish = accepted and not load and (inp['alternate'] or reuse)
            send = finish and (inp['status'] in (2, 3, 4) or (inp['alternate'] and inp['status'] == 5))
            self.assertEqual(actions.count('load_state_capture'), int(load))
            self.assertEqual(actions.count('load_callback_capture'), int(callback))
            self.assertEqual(actions.count('finish_packet_capture'), int(send))
            self.assertEqual(state['status30'], 5 if send else inp['status'])
            if send:
                packet = next(e for e in case['events'] if e['action'] == 'finish_packet_capture')
                raw = bytes.fromhex(packet['packet_hex'])
                self.assertEqual(int.from_bytes(raw[:8], 'little'), 0x149919e68)
                self.assertEqual(raw[10], 1)
            # The alternate path changes 5 -> 2 before the actual guard sends
            # and changes 2 -> 5. Plain reuse does not reopen status 5.
            status_events = [e['value'] for e in case['events'] if e['action'] == 'native_status_set']
            expected = [2, 5] if send and inp['alternate'] and inp['status'] == 5 else [5] if send else []
            self.assertEqual(status_events, expected)
            sends += int(send)
            loads += int(load)
            callbacks += int(callback)
        self.assertGreater(sends, 0)
        self.assertGreater(loads, 0)
        self.assertGreater(callbacks, 0)


if __name__ == '__main__':
    unittest.main()
