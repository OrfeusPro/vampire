from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_server_list import LobbyServerRecord, LobbyServerListResult
from vampir_core.game_server_target import select_game_server_target


def record(server_id=42, host='game.example.com', port=12001):
    return LobbyServerRecord(('display-fixture', host, 'extra'), (7, server_id, 0, 0), (port, 23456), (0, 0, 0), (False,) * 5, ())


def listing(*records):
    return LobbyServerListResult(0, (), records or (record(),), (), (), (), (False, False), 0, ('', ''))


class GameServerTargetTests(unittest.TestCase):
    def test_native_copy_begin_lookup_and_connect_reproduce(self):
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-record-endpoint-replay.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location('test_lobby_record_endpoint', HERE / 'resource-tools/vampir/replay-lobby-record-endpoint.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 16)
        for case in report['cases']:
            source, native = case['source_record'], case['result']
            r = record(source['server_id'], source['host'], source['port'])
            if source['port'] <= 32767:
                target = select_game_server_target(listing(r), server_id=source['server_id'])
                self.assertEqual((target.server_id, target.group_id, target.host, target.port, target.other_word),
                    (source['server_id'], source['group_id'], native['target_text'], native['target_words'][0], native['target_words'][1]))
            else:
                with self.assertRaises(ValueError): select_game_server_target(listing(r), server_id=source['server_id'])
            self.assertEqual(native['copied_record']['ids'], [7, source['server_id']])

    def test_uses_explicit_server_id_not_group_or_array_order(self):
        data = listing(record(207), record(42))
        selected = select_game_server_target(data, server_id=42)
        self.assertEqual((selected.server_id, selected.group_id), (42, 7))
        self.assertNotIn('game.example.com', repr(selected))
        for missing in (7, 100):
            with self.assertRaises(ValueError): select_game_server_target(data, server_id=missing)
        with self.assertRaises(ValueError): select_game_server_target(listing(record(), record()), server_id=42)
        with self.assertRaises(ValueError): select_game_server_target(replace(data, result_code=1), server_id=42)
        with self.assertRaises(ValueError): select_game_server_target(replace(data, flags=(False, True)), server_id=42)

    def test_local_host_and_port_policy(self):
        for host in ('127.0.0.1', '10.0.0.1', '::1', '2001:4860:4860::8888', '999.1.1.1',
                'a.local', 'localHost', 'a.internal', 'user@host.example', 'game.example/path', 'bad-.example'):
            with self.assertRaises(ValueError): select_game_server_target(listing(record(host=host)), server_id=42)
        for port in (0, 32768, 65535, True):
            with self.assertRaises(ValueError): select_game_server_target(listing(record(port=port)), server_id=42)
        for identifier in (0, -1, True, 0x100000000):
            with self.assertRaises(ValueError): select_game_server_target(listing(), server_id=identifier)
        self.assertEqual(select_game_server_target(listing(record(host='8.8.8.8')), server_id=42).host, '8.8.8.8')


if __name__ == '__main__': unittest.main()
