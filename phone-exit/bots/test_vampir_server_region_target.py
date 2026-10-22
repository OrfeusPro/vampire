from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import unittest

from test_vampir_game_server_target import listing, record
from vampir_core.lobby_server_list import LobbyServerGroup
from vampir_core.game_server_target import select_game_server_in_region, SERVER_REGION_CODES, is_game_server_state_excluded


def regional_list():
    kr = replace(record(101), u32=(1, 101, 0, 4))
    jp = replace(record(401), u32=(4, 401, 0, 1))
    return replace(listing(kr, jp), groups=(LobbyServerGroup(1, 'fixture-kr', 1), LobbyServerGroup(4, 'fixture-jp', 4)))


class ServerRegionTargetTests(unittest.TestCase):
    def test_native_state_reset_and_runtime_agree_for_every_byte(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-server-record-state.py'
        spec = importlib.util.spec_from_file_location('test_server_state_native', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        saved = json.loads((tool.native.ROOT / 'code-clues/server-record-state-replay.json').read_text('utf-8'))
        actual = json.loads(json.dumps(tool.build()))
        self.assertEqual(actual, saved)
        self.assertEqual(len(actual['cases']), 256)
        for case in actual['cases']:
            candidate = replace(record(401), enums=(0, case['state'], 0))
            self.assertEqual(is_game_server_state_excluded(candidate), case['excluded'])

    def test_state_exclusion_skips_candidate_without_changing_region(self):
        data = regional_list()
        jp = data.servers[1]
        for state in (2, 3):
            excluded = replace(jp, enums=(0, state, 0))
            candidate = replace(data, servers=(data.servers[0], excluded))
            with self.assertRaises(ValueError): select_game_server_in_region(candidate, region='JP')
            with self.assertRaises(ValueError): select_game_server_in_region(candidate, region='JP', server_id=401)
            next_jp = replace(jp, u32=(4, 402, 0, 1))
            candidate = replace(candidate, servers=candidate.servers + (next_jp,))
            self.assertEqual(select_game_server_in_region(candidate, region='JP').server_id, 402)

    def test_native_enum_gate_and_country_tables_reproduce(self):
        path = Path(__file__).parent / 'resource-tools/vampir/replay-server-region-selection.py'
        spec = importlib.util.spec_from_file_location('test_server_region_native', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/server-region-selection-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        historical = {k: v for k, v in report['enum_initializer']['members'].items() if v}
        self.assertEqual({key: SERVER_REGION_CODES[key] for key in historical}, historical)
        self.assertEqual(len(report['filter_cases']), 32)
        country = {r['JoinedCountry']: r for r in report['tables'][0]['rows']}
        self.assertEqual(country['HK']['ServerRegionType'], 'TW,ASIA,JP')
        self.assertEqual(country['JP']['ServerRegionType'], 'JP')
        self.assertEqual(report['tables'][0]['rows'], report['tables'][1]['rows'])

    def test_selects_by_group_region_instead_of_record_order_or_other_dword(self):
        data = regional_list()
        self.assertEqual(select_game_server_in_region(data, region='JP').server_id, 401)
        self.assertEqual(select_game_server_in_region(replace(data, servers=tuple(reversed(data.servers))), region='JP').server_id, 401)
        self.assertEqual(select_game_server_in_region(data, region='KR', server_id=101).server_id, 101)
        with self.assertRaises(ValueError): select_game_server_in_region(data, region='JP', server_id=101)
        with self.assertRaises(ValueError): select_game_server_in_region(data, region='TW')

    def test_missing_ambiguous_or_invalid_groups_and_ids_fail_without_other_region(self):
        data = regional_list()
        for changed in (replace(data, groups=()), replace(data, groups=data.groups + (data.groups[1],)),
                replace(data, servers=data.servers + (data.servers[1],))):
            with self.assertRaises(ValueError): select_game_server_in_region(changed, region='JP')
        for kwargs in ({'region': ''}, {'region': 'JP', 'server_id': 0}):
            with self.assertRaises(ValueError): select_game_server_in_region(data, **kwargs)
