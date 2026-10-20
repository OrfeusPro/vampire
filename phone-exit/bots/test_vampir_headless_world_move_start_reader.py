import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.world_move_start_result import decode_world_move_start_result


class WorldMoveStartReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE / 'resource-tools/vampir/replay-world-move-start-reader.py'
        spec = importlib.util.spec_from_file_location('start_reader_test', path)
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)
        cls.report = json.loads((cls.tool.native.ROOT / 'code-clues/world-move-start-reader-replay.json').read_text('utf-8'))

    def decode(self, data):
        return decode_world_move_start_result(data, max_payload_size=64)

    def test_native_whole_reader_reproduces(self):
        self.assertEqual(self.tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 24)
        self.assertEqual(self.report['binding']['packet_id'], 204)
        self.assertFalse(self.report['network_ready'])

    def test_portable_fields_match_native_including_signed_zero(self):
        for case in self.report['cases']:
            data = bytes.fromhex(case['payload_hex'])
            model = self.decode(data)
            self.assertEqual((case['returned'], case['consumed']), (1, 30))
            for offset, value in case['fields'].items():
                offset = int(offset, 16)
                self.assertEqual(model.result_code if offset == 0x10 else model.data.at(offset), value)
            self.assertEqual(struct.pack('<ddd', *model.data.at(0x18).finite_values()).hex(), case['vector_hex'])
            self.assertEqual(model.data.at(0x18).bits, struct.unpack_from('<III', data, 8))
            self.assertNotIn('89abcdef', repr(model))

    def test_short_and_trailing_data_are_rejected(self):
        self.assertEqual(len(self.report['short']), 30)
        for size, case in enumerate(self.report['short']):
            data = bytes.fromhex(case['payload_hex'])
            self.assertEqual(len(data), size)
            self.assertEqual(case['returned'], 0)
            self.assertLessEqual(case['consumed'], size)
            with self.assertRaises(ValueError):
                self.decode(data)
        body = bytes.fromhex(self.report['cases'][0]['payload_hex'])
        self.assertEqual((self.report['trailing']['returned'], self.report['trailing']['consumed']), (1, 30))
        with self.assertRaises(ValueError):
            self.decode(body + b'\0')

    def test_explicit_budget_and_immutable_input(self):
        body = bytes.fromhex(self.report['cases'][0]['payload_hex'])
        for budget in (True, None, 29, 0x1000000):
            with self.assertRaises(ValueError):
                decode_world_move_start_result(body, max_payload_size=budget)
        with self.assertRaises(BufferError):
            decode_world_move_start_result(body + b'\0', max_payload_size=30)
        with self.assertRaises(ValueError):
            self.decode(bytearray(body))


if __name__ == '__main__':
    unittest.main()
