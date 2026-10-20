import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
REPORT = Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-connect-flow.json')


class LobbyConnectFlowTests(unittest.TestCase):
    def test_native_wrapper_and_connected_callback_reproduce(self):
        spec = importlib.util.spec_from_file_location('test_native_lobby_connect', HERE / 'replay-lobby-connect-flow.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), json.loads(REPORT.read_text('utf-8')))

    def test_version_precedes_original_request_only_for_state_two(self):
        report = json.loads(REPORT.read_text('utf-8'))
        self.assertEqual(len(report['wrappers']), 8)
        for case in report['wrappers']:
            sends = [e['packet'] for e in case['events'] if e['action'] == 'lower_send_capture']
            prepares = [e for e in case['events'] if e['action'] == 'prepare_version_fixture']
            self.assertEqual(len(prepares), int(case['state_fixture'] == 2))
            expected = ['version', 'request'] if case['state_fixture'] == 2 and case['prepare_present_fixture'] else ['request']
            self.assertEqual(sends, expected)
            self.assertTrue(case['returned'])
        rows = {r['address']: r for f in report['fragments'] for r in f['instructions']}
        # Ghidra's unreachable warning does not erase this actual direct call.
        self.assertEqual(rows[0x144aa8a06]['direct_target'], 0x144aa9da0)
        self.assertEqual(rows[0x144aa8a9b]['direct_target'], 0x144aa9da0)

    def test_connected_flush_preserves_bytes_clears_pending_and_keeps_sequence(self):
        report = json.loads(REPORT.read_text('utf-8'))
        self.assertEqual(len(report['connected']), 4)
        for case in report['connected']:
            events = case['events']
            self.assertEqual(events[0]['action'], 'socket_option_capture')
            self.assertEqual(case['sequence_after'], 97)
            self.assertEqual(case['pending_remaining'], 0)
            queue = [e for e in events if e['action'] == 'transport_queue_capture']
            if case['pending_hex']:
                self.assertEqual(queue, [dict(action='transport_queue_capture', bytes_hex=case['pending_hex'])])
                self.assertEqual(events[-1]['action'], 'clear_pending_capture')
            else:
                self.assertEqual(queue, [])
                self.assertNotIn('clear_pending_capture', [e['action'] for e in events])
            self.assertEqual('special_helper_capture' in [e['action'] for e in events], bool(case['special_fixture']))
            self.assertEqual(case['special_bytes_after'], '000100000000' if case['special_fixture'] else '00007b000000')


if __name__ == '__main__': unittest.main()
