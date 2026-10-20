import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_server_list import decode_lobby_server_list


class LobbyServerListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-server-list-reader-replay.json').read_text('utf-8'))

    def test_whole_native_reader_and_containers_reproduce(self):
        spec = importlib.util.spec_from_file_location('test_native_lobby_server_list', HERE / 'resource-tools/vampir/replay-lobby-server-list-reader.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 10)

    def test_all_native_fields_match_portable_decoder(self):
        for case in self.report['cases']:
            body = bytes.fromhex(case['payload_hex'])
            value = decode_lobby_server_list(body, max_payload_size=8192, max_collection_items=100)
            self.assertEqual(value.result_code, case['result_code'])
            self.assertEqual([[g.raw_08, g.text_10, g.raw_20] for g in value.groups], case['arrays']['0x18'])
            self.assertEqual(len(value.servers), len(case['arrays']['0x28']))
            for actual, wanted in zip(value.servers, case['arrays']['0x28']):
                for name in ('strings', 'u32', 'u16', 'enums', 'array50'):
                    self.assertEqual(list(getattr(actual, name)), wanted[name])
                self.assertEqual(list(actual.flags), [bool(v) for v in wanted['flags']])
            self.assertEqual(list(value.values38), case['arrays']['0x38'])
            for name in ('map48', 'map98'):
                self.assertEqual([list(pair) for pair in getattr(value, name)], case['maps']['0x48' if name == 'map48' else '0x98'])
            self.assertEqual(list(value.flags), [bool(v) for v in case['flags']])
            self.assertEqual(value.enum_e9, case['enum_e9'])
            self.assertEqual(list(value.strings), case['strings'])
            self.assertEqual(case['returned'], 1)
            self.assertEqual(case['consumed'], len(body))

    def test_every_truncated_prefix_and_exact_tail(self):
        for case in self.report['cases']:
            body = bytes.fromhex(case['payload_hex'])
            for cut in range(len(body)):
                with self.assertRaises(ValueError):
                    decode_lobby_server_list(body[:cut], max_payload_size=8192, max_collection_items=100)
            with self.assertRaises(ValueError):
                decode_lobby_server_list(body + b'extra', max_payload_size=8192, max_collection_items=100)
        self.assertEqual(len(self.report['truncated']), 21)
        self.assertTrue(all(c['returned'] == 0 for c in self.report['truncated']))

    def test_aggregate_budget_counts_nested_and_duplicate_map_entries(self):
        case = self.report['cases'][-1]
        body = bytes.fromhex(case['payload_hex'])
        fixture = case['fixture']
        budget = sum(len(fixture.get(k, [])) for k in ('groups', 'servers', 'values', 'map48', 'map98'))
        budget += sum(len(s['array50']) for s in fixture['servers'])
        actual = decode_lobby_server_list(body, max_payload_size=len(body), max_collection_items=budget)
        self.assertEqual(actual.map48, ((3, 11), (7, 13)))
        self.assertEqual(actual.map98, ((8, 7), (42, 9)))
        with self.assertRaises(BufferError):
            decode_lobby_server_list(body, max_payload_size=len(body), max_collection_items=budget - 1)
        self.assertNotIn('game.invalid', repr(actual))
        self.assertNotIn('game.invalid', repr(actual.servers[0]))
        for bad in (True, -1, 65536):
            with self.assertRaises(ValueError): decode_lobby_server_list(bytes(21), max_payload_size=21, max_collection_items=bad)
        with self.assertRaises(BufferError): decode_lobby_server_list(body, max_payload_size=21, max_collection_items=100)
        with self.assertRaises(ValueError): decode_lobby_server_list(bytearray(21), max_payload_size=21, max_collection_items=0)


if __name__ == '__main__': unittest.main()
