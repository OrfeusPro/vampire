import importlib.util
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import LobbyLoginPayload, LobbyVersionResultBody, make_windows_lobby_login


class LobbyLoginPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-login-preparation-replay.json').read_text('utf-8'))

    def test_actual_preparation_constructor_and_selected_server_getter_reproduce(self):
        spec = importlib.util.spec_from_file_location('test_native_lobby_prepare', HERE / 'resource-tools/vampir/replay-lobby-login-preparation.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), self.report)
        self.assertEqual(len(self.report['cases']), 16)
        for case in self.report['cases']:
            self.assertEqual(case['stop'], 'sender_boundary')
            self.assertEqual(case['packet']['raw_80'], 7)
            self.assertEqual(case['packet']['integers'][2], case['fixture']['server_id'])

    def test_windows_builder_matches_native_numeric_context_without_changing_identity(self):
        version = LobbyVersionResultBody(0, False, (0, 0), 0)
        for case in self.report['cases']:
            f, p = case['fixture'], case['packet']
            if f['selector'] != 3: continue
            result = make_windows_lobby_login(version_result=version, kind=f['kind'],
                selected_server_id=f['server_id'], metadata=p['strings'][5])
            self.assertEqual(result.integers, tuple(p['integers']))
            self.assertEqual(result.raw_80, p['raw_80'])
            self.assertEqual(result.strings, ('',) * 5 + (p['strings'][5],))
            # The captured native preparation snapshot is a valid independent body input.
            captured = LobbyLoginPayload(tuple(p['strings']), tuple(p['integers']), p['raw_80'])
            self.assertTrue(captured.encode(max_payload_size=4096).endswith(b'\x07'))

    def test_sdk_nid_branches_are_distinct_and_metadata_is_not_invented(self):
        cases = self.report['cases']
        normal = cases[0]['packet']
        self.assertEqual(normal['strings'], ['player-fixture', 'sdk-token-fixture', 'nm-fixture', 'HK', 'nid-fixture', 'explicit-collected-fixture'])
        no_nid = next(c['packet'] for c in cases if not c['fixture']['nid_info'])
        self.assertEqual(no_nid['strings'][3], '')
        self.assertEqual(no_nid['strings'][5], '')
        self.assertEqual(no_nid['strings'][4], 'nid-fixture')
        no_auth = next(c['packet'] for c in cases if not c['fixture']['sdk_auth'])
        self.assertEqual(no_auth['strings'][:2], ['global-player-fixture', 'previous-token-fixture'])
        self.assertEqual(no_auth['strings'][3], 'HK')

    def test_version_flag_error_and_unknown_context_require_explicit_handling(self):
        version = LobbyVersionResultBody(0, False, (0, 0), 0)
        for value in (-1, True, 0x100000000):
            with self.assertRaises(ValueError):
                make_windows_lobby_login(version_result=version, kind=value, selected_server_id=0, metadata='')
            with self.assertRaises(ValueError):
                make_windows_lobby_login(version_result=version, kind=0, selected_server_id=value, metadata='')
        with self.assertRaises(NotImplementedError):
            make_windows_lobby_login(version_result=replace(version, flag_14=True), kind=0, selected_server_id=0, metadata='')
        with self.assertRaises(ValueError):
            make_windows_lobby_login(version_result=replace(version, result_code=1), kind=0, selected_server_id=0, metadata='')
        with self.assertRaises(TypeError):
            make_windows_lobby_login(version_result=object(), kind=0, selected_server_id=0, metadata='')


if __name__ == '__main__': unittest.main()
