import importlib.util
import json
from pathlib import Path
import struct
import unittest


class CharacterSelectOptionSendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-character-select-option-send.py'
        spec = importlib.util.spec_from_file_location('option_send_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/character-select-option-send-replay.json').read_text('utf-8'))

    def test_native_continuation_and_writer_reproduce(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual((len(self.report['cases']), len(self.report['writer_cases'])), (10, 6))
        self.assertEqual((self.report['binding']['name'], self.report['binding']['packet_id']), ('PktOptionSet', 1782))
        self.assertFalse(self.report['network_ready'])
        self.assertFalse(self.report['world_move_trigger_verified'])

    def test_only_changed_connected_server_options_reach_send(self):
        sends = []
        for i, case in enumerate(self.report['cases']):
            events = [e for e in case['events'] if e['action'] == 'option_send_capture']
            profile = [e for e in case['events'] if e['action'] == 'profile_apply_capture']
            # Source-bound scenarios independently distinguish unchanged values,
            # absent metadata, local-only records, disconnected transport and
            # the separate kind2 persistence path.
            self.assertEqual(len(events), int(i in (1, 2)))
            self.assertEqual(len(profile), int(i == 7))
            if events:
                event = events[0]
                self.assertEqual((event['packet_id'], event['index'], event['value'], event['packet_flag']),
                                 (1782, 27, case['spec']['value'], 0))
                self.assertEqual(bytes.fromhex(case['wire']['payload_hex']), struct.pack('<HBI', 1, 27, event['value']))
                sends.append(event['value'])
            self.assertEqual(case['option27'], case['spec']['value'] if i < 8 else case['spec'].get('old_value', 0))
        self.assertEqual(sends, [1, 255])

    def test_whole_writer_uses_u16_count_and_raw_byte_u32_items(self):
        for case in self.report['writer_cases']:
            data = bytes.fromhex(case['payload_hex'])
            self.assertEqual(case['returned'], 1)
            self.assertEqual(case['size'], 2 + 5 * len(case['items']))
            self.assertEqual(struct.unpack_from('<H', data)[0], len(case['items']))
            self.assertEqual([list(struct.unpack_from('<BI', data, 2 + i * 5)) for i in range(len(case['items']))], case['items'])
        # Writer preserves raw 255; it does not silently clamp it to the number
        # of manager entries. No general receiver policy is inferred here.
        self.assertEqual(self.report['writer_cases'][4]['items'][1], [255, 0x80000000])


if __name__ == '__main__':
    unittest.main()
