import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.cdn_servers import select_cdn_server


class RegionalLobbyTests(unittest.TestCase):
    def test_fresh_group_region_gate_does_not_use_another_region(self):
        from dataclasses import replace
        from test_vampir_game_server_target import listing, record
        from vampir_core.lobby_server_list import LobbyServerGroup
        from vampir_core.game_server_target import select_game_server_in_region
        server = replace(record(500), u32=(50, 500, 0, 0))
        data = replace(listing(server), groups=(LobbyServerGroup(50, 'fixture-global', 7),))
        self.assertEqual(select_game_server_in_region(data, region='EU', server_id=500).server_id, 500)
        for region in ('JP', 'SG', 'NA'):
            with self.subTest(region=region), self.assertRaises(ValueError):
                select_game_server_in_region(data, region=region, server_id=500)

    def test_whole_current_native_selector_and_portable_selection(self):
        spec = importlib.util.spec_from_file_location('regional_replay', HERE / 'resource-tools/vampir/replay-release-regional-lobby.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual(len(report['cases']), 540)
        for case in report['cases']:
            region = {5: 'SG', 6: 'NA', 7: 'EU'}.get(case['region'])
            detail = dict(lobbyAddress=case['base'] or '')
            if region and case['regional'] is not None:
                detail['lobbyAddress' + region] = case['regional']
            document = dict(select_server=dict(type='REAL'), server_list=[dict(type='REAL', detail=detail)])
            result = select_cdn_server(document, lobby_region=region)
            if case['enabled'] and result.lobby_address:
                self.assertEqual(result.lobby_address, case['selected'])

    def test_invalid_region_and_malformed_regional_field_rejected(self):
        document = dict(select_server=dict(type='REAL'), server_list=[dict(type='REAL',
            detail=dict(lobbyAddress='base.invalid', lobbyAddressEU=123))])
        self.assertEqual(select_cdn_server(document).lobby_address, 'base.invalid')
        for region in ('EU', 'JP', '', 7, True):
            with self.subTest(region=region), self.assertRaises(ValueError):
                select_cdn_server(document, lobby_region=region)


if __name__ == '__main__':
    unittest.main()
