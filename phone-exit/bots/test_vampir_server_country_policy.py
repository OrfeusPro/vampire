from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from test_vampir_game_server_target import record, listing
import test_vampir_initial_game_login as input_tests
from vampir_core.game_server_target import game_server_allows_joined_country, select_game_server_in_region
from vampir_core.lobby_server_list import LobbyServerGroup

HERE = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class ServerCountryPolicyTests(unittest.TestCase):
    def test_native_response_setter_getters_predicate_reproduce(self):
        tool = load('country_native_test', HERE / 'resource-tools/vampir/replay-server-country-policy.py')
        saved = json.loads((tool.native.ROOT / 'code-clues/server-country-policy-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['cases']), 15)
        by_name = {c['fixture']['name']: c for c in saved['cases']}
        self.assertTrue(by_name['hk-only']['accepted'])
        for name in ('sdk-disabled', 'absent-manager', 'absent-manager-player', 'absent-sdk-player'):
            self.assertFalse(by_name[name]['accepted'])
        for case in saved['cases']:
            r = replace(record(), array50=tuple(case['fixture']['countries']))
            country = case['compared']
            if not case['fixture'].get('record_present', True): continue
            if r.array50 and not country:
                with self.assertRaises(ValueError): game_server_allows_joined_country(r, joined_country_code=country)
            else:
                self.assertEqual(game_server_allows_joined_country(r, joined_country_code=country), case['accepted'])

    def test_country_filter_stays_in_region_and_rejects_explicit_denied_id(self):
        first = replace(record(251), array50=('JP',))
        second = replace(record(252), array50=('hk',))
        data = replace(listing(first, second), groups=(LobbyServerGroup(7, 'jp-fixture', 4),))
        self.assertEqual(select_game_server_in_region(data, region='JP', joined_country_code='HK').server_id, 252)
        with self.assertRaises(ValueError):
            select_game_server_in_region(data, region='JP', server_id=251, joined_country_code='HK')
        with self.assertRaises(ValueError): select_game_server_in_region(data, region='JP', joined_country_code='UA')
        with self.assertRaises(ValueError): select_game_server_in_region(data, region='KR', joined_country_code='HK')
        unrestricted = replace(second, array50=())
        self.assertEqual(select_game_server_in_region(replace(data, servers=(first, unrestricted)),
            region='JP', joined_country_code=None).server_id, 252)

    def test_missing_country_never_uses_exit_or_email_as_fallback(self):
        r = replace(record(), array50=('HK',))
        for country in (None, '', 'HKG', 'HK ', 'ＨＫ', 1):
            with self.assertRaises(ValueError): game_server_allows_joined_country(r, joined_country_code=country)
        self.assertTrue(game_server_allows_joined_country(record(), joined_country_code=None))
        self.assertFalse(game_server_allows_joined_country(replace(r, array50=('ＨＫ', 'private-text')), joined_country_code='HK'))

    def run_list_only(self, countries):
        tool = load('country_login_runner_test', HERE / 'vampir-headless/probe-selected-game-login.py')
        _, inputs = input_tests.InitialGameLoginTests().inputs()
        inputs['sdk_data'] = replace(inputs['sdk_data'], joined_country_code='HK')
        data = replace(listing(replace(record(251), array50=countries)), groups=(LobbyServerGroup(7, 'jp-fixture', 4),))
        def lobby(email, **kwargs):
            kwargs['_consume_auth'](**{k: inputs[k] for k in ('binding', 'sdk_data', 'netmarble_id')})
            return SimpleNamespace(response=inputs['lobby_result'], server_list_response=data, summary={'login_result_code': 0})
        target = load('country_target_test', HERE / 'vampir-headless/probe-selected-game-version.py')
        modules = [SimpleNamespace(load_profile=lambda **kwargs: SimpleNamespace(app_version='fixture')),
                   SimpleNamespace(run=lobby), target]
        with patch.object(tool, 'module', side_effect=modules), patch.object(tool, 'SocksRoute') as route, \
                patch.object(tool, 'exchange_game_login') as exchange:
            result = tool.run('fixture@example.invalid', selected_profile='recovered-base', manifest_path=Path('fixture'),
                socks_port=17948, context='windows-sdk-initial-reset', region='JP', server_policy_byte=0,
                extra_number=0, selection='lowest-valid-id', server_list_only=True)
        route.assert_not_called()
        exchange.assert_not_called()
        for secret in ('sdk-token-fixture', 'nm-fixture', 'private-country-text-fixture', 'game.example.com'):
            self.assertNotIn(secret, str(result))
        return result

    def test_list_only_reports_country_policy_without_game_connection(self):
        result = self.run_list_only(('HK', 'private-country-text-fixture'))
        self.assertEqual(result['status'], 'server_country_policy_checked')
        self.assertEqual(result['sdk_joined_country_code'], 'HK')
        self.assertEqual(result['selected_server_id'], 251)
        self.assertTrue(result['region_server_states'][0]['sdk_joined_country_allowed'])
        self.assertFalse(result['game_login_sent'])

    def test_denied_country_stops_before_game_connection(self):
        result = self.run_list_only(('JP',))
        self.assertEqual(result['status'], 'selected_game_login_not_completed')
        self.assertFalse(result['region_server_states'][0]['sdk_joined_country_allowed'])
        self.assertNotIn('selected_server_id', result)
