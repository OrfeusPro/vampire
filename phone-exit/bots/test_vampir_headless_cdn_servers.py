"""Native server-list selection and isolated portable raw detail plans."""
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_config import decode_cdn_config_document, read_cdn_sdk_environment
from vampir_core.cdn_servers import MAX_SERVERS, select_cdn_server
from vampir_core.sdk_config import select_game_sdk_zone


class CdnServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = HERE / 'resource-tools/vampir/build-headless-cdn-server-list.py'
        spec = importlib.util.spec_from_file_location('cdn_server_test_tool', cls.tool)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        cls.report = json.loads((root / 'code-clues/headless-cdn-server-list.json').read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()
        cls.image = cls.module.body.head.headers.uri.http.preparation.url.settings.config.native.Image(cls.raw)

    def test_source_literals_comparator_table_crt_and_instructions(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), self.report['sha256'])
        self.assertEqual(hashlib.sha256(self.tool.read_bytes()).hexdigest(), self.report['tool_sha256'])
        crt = self.report['system_crt']
        self.assertEqual(hashlib.sha256(Path(crt['path']).read_bytes()).hexdigest(), crt['sha256'])
        for row in self.report['literals'] + self.report['anchors'] + [i for f in self.report['fragments'] for i in f['instructions']]:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset'] + len(data)], data)
        self.assertEqual(self.report['port_import']['name'], '_wtoi')
        self.assertFalse(self.report['network_ready'])

    def test_all_native_replays_and_portable_matches(self):
        self.assertEqual(len(self.report['cases']), 31)
        for case in self.report['cases']:
            document = case['document_fixture']
            emulator = self.module.ServerListEmulator(self.raw, self.image, self.report['fragments'], document)
            self.assertEqual(emulator.replay(), case)
            if case['type_missing'] or not case['success']:
                with self.assertRaises(ValueError):
                    select_cdn_server(document)
                continue
            result = select_cdn_server(document)
            self.assertEqual(result.index, case['selected_index'])
            self.assertEqual(result.requested_type, case['loaded_type'])
            chosen = document['server_list'][result.index]
            self.assertEqual(result.entry_type, chosen['type'])
            for key, attribute in zip(self.module.KEYS, ['lobby_address', 'lobby_port', 'patch_url', 'data_url']):
                present = key in chosen.get('detail', {})
                self.assertEqual(getattr(result, attribute), case['fields'][key] if present else None)

    def test_first_match_and_ascii_only_comparison(self):
        def choose(wanted, kinds):
            return select_cdn_server({'select_server': {'type': wanted}, 'server_list': [{'type': s} for s in kinds]})
        self.assertEqual(choose('real', ['REAL', 'real']).index, 0)
        self.assertEqual(choose('real ', ['real', 'real ']).index, 1)
        self.assertEqual(choose('réal', ['RÉAL', 'réal']).index, 1)
        self.assertEqual(choose('', ['']).index, 0)
        with self.assertRaises(ValueError):
            choose('real', ['unreal', 'dev'])

    def test_missing_fields_are_no_replacement_and_plans_are_isolated(self):
        first = select_cdn_server({'select_server': {'type': 'real'}, 'server_list': [
            {'type': 'real', 'detail': {'lobbyAddress': 'lobby.invalid', 'lobbyPort': '2junk'}}]})
        second = select_cdn_server({'select_server': {'type': 'real'}, 'server_list': [{'type': 'real'}]})
        self.assertEqual(first.lobby_port, '2junk')
        self.assertIsNone(second.lobby_address)
        self.assertIsNone(second.lobby_port)
        self.assertNotIn('lobby.invalid', repr(first))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.index = 5
        cases = self.report['cases']
        self.assertEqual(cases[-4]['global_port_uint32'], 0)
        self.assertEqual(cases[-3]['global_port_uint32'], 0xffffffff)
        self.assertEqual(cases[-2]['global_port_uint32'], 65536)
        self.assertEqual(cases[-1]['global_port_uint32'], 2)

    def test_explicit_schema_and_string_limits(self):
        invalid = [{}, {'select_server': {}}, {'select_server': {'type': None}},
                   {'select_server': {'type': 'real'}, 'server_list': None},
                   {'select_server': {'type': 'real'}, 'server_list': [None]},
                   {'select_server': {'type': 'real'}, 'server_list': [{'type': None}]},
                   {'select_server': {'type': 'real'}, 'server_list': [{'type': 'real', 'detail': None}]},
                   {'select_server': {'type': 'real'}, 'server_list': [{'type': 'real', 'detail': {'lobbyPort': 2}}]},
                   {'select_server': {'type': 'real\0'}, 'server_list': []},
                   {'select_server': {'type': '\ud800'}, 'server_list': []},
                   {'select_server': {'type': 'x' * 129}, 'server_list': []}]
        for document in invalid:
            with self.assertRaises(ValueError):
                select_cdn_server(document)
        for value in ['x' * 4097, 'x\0', '\ud800']:
            with self.assertRaises(ValueError):
                select_cdn_server({'select_server': {'type': 'real'}, 'server_list': [
                    {'type': 'real', 'detail': {'lobbyAddress': value}}]})
        result = select_cdn_server({'select_server': {'type': '😀' * 64}, 'server_list': [
            {'type': '😀' * 64, 'detail': {'lobbyAddress': 'x' * 4096}}]})
        self.assertEqual(len(result.lobby_address), 4096)

    def test_server_count_budget_and_missing_type_skip(self):
        servers = [{}] * (MAX_SERVERS - 1) + [{'type': 'real'}]
        document = {'select_server': {'type': 'real'}, 'server_list': servers}
        self.assertEqual(select_cdn_server(document).index, MAX_SERVERS - 1)
        document['server_list'] = servers + [{}]
        with self.assertRaises(ValueError):
            select_cdn_server(document)

    def test_document_to_sdk_and_lobby_detail_plan(self):
        document = {'NetmarbleS': {'Zone': 'real'}, 'select_server': {'type': 'eu'},
                    'server_list': [{'type': 'dev'}, {'type': 'EU', 'detail': {
                        'lobbyAddress': 'eu.invalid', 'lobbyPort': '12345',
                        'patchURL': 'https://patch.invalid/', 'dataURL': 'https://data.invalid/'}}]}
        decoded = decode_cdn_config_document(json.dumps(document).encode())
        self.assertEqual(select_game_sdk_zone(read_cdn_sdk_environment(decoded)), 2)
        result = select_cdn_server(decoded)
        self.assertEqual((result.index, result.lobby_address, result.lobby_port), (1, 'eu.invalid', '12345'))
        self.assertEqual(result.data_url, 'https://data.invalid/')
        self.assertEqual(result.patch_url, 'https://patch.invalid/')


if __name__ == '__main__':
    unittest.main()
