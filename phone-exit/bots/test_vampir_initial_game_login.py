import importlib.util
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.login_context import prepare_initial_windows_game_login
from vampir_core.device_registry import DeviceBinding
from vampir_core.version_packet import VersionPayload
from vampir_core.sdk_sign_in_response import SdkSignInData
from vampir_core.lobby_login_result import LobbyLoginResultBody


class InitialGameLoginTests(unittest.TestCase):
    def inputs(self):
        version = VersionPayload(('1.12.14', 'Windows_fixture', 'cpu-fixture', 'nm-fixture', '127.0.0.1',
            '', '', '', '', 'AC7F34E3AFA91ED417BE86CD45BF18C8'), (0, 207, 1))
        return version, dict(binding=DeviceBinding('fixture@example.invalid', 'fixture', 'real', False,
            'device-fixture', 'nm-fixture', 'observed-fixture', 'unknown', '', 'nid-device-fixture', 'observed-fixture'),
            sdk_data=SdkSignInData('sdk-token-fixture', 'different-player-fixture', None, None, None),
            netmarble_id='nid-fixture', lobby_result=LobbyLoginResultBody(
                ('lobby-first-fixture', 'lobby-second-fixture', '', '', ''), (0, 0, 0, 0)),
            server_id=42, extra_number=123, context='windows-sdk-initial-reset')

    def test_native_initial_context_reproduces_and_builder_keeps_all_proven_fields(self):
        path = HERE / 'resource-tools/vampir/replay-login-initial-context.py'
        spec = importlib.util.spec_from_file_location('test_initial_login_context', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/login-initial-context-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(report['reset_slot']['target'], '0x14556a750')
        self.assertEqual(report['reset_slot']['offset'], 8)
        version, kwargs = self.inputs()
        login = prepare_initial_windows_game_login(version, **kwargs)
        for case in report['cases']:
            p = case['packet']
            self.assertEqual(login.raw_bytes, tuple(p['bytes'][hex(o)] for o in (0x98, 0x99, 0x124, 0x130, 0x131)))
            self.assertEqual(login.strings[:2], (p['strings']['0x10'], p['strings']['0x20']))
            for index, offset in ((4, 0x58), (5, 0x68), (7, 0x88), (9, 0xb8), (10, 0xc8), (11, 0xd8), (12, 0xe8), (13, 0x100)):
                self.assertEqual(login.strings[index], p['strings'][hex(offset)])
        self.assertEqual(login.strings[2:4], ('nid-fixture', '1.12.14'))
        self.assertEqual((login.strings[6], login.strings[8]), ('nm-fixture', 'sdk-token-fixture'))
        self.assertEqual(login.integers, (123, 42, 207, 1))
        self.assertEqual(login.raw_128, 0)
        self.assertNotIn('different-player-fixture', login.strings)
        self.assertNotIn('sdk-token-fixture', repr(login))

    def test_failure_binding_wrong_platform_and_missing_explicit_context_are_rejected(self):
        version, kwargs = self.inputs()
        for changed in ({'context': ''}, {'server_id': 0}, {'extra_number': -1},
                {'binding': replace(kwargs['binding'], confirmation='required')},
                {'binding': replace(kwargs['binding'], nm_device_key='other-device')},
                {'lobby_result': replace(kwargs['lobby_result'], integers=(1, 0, 0, 0))}):
            with self.assertRaises((ValueError, PermissionError)):
                prepare_initial_windows_game_login(version, **dict(kwargs, **changed))
        strings = list(version.strings)
        strings[1] = 'Android_fixture'
        with self.assertRaises(ValueError): prepare_initial_windows_game_login(replace(version, strings=tuple(strings)), **kwargs)

    def test_explicit_configured_language_changes_only_language_byte(self):
        version, kwargs = self.inputs()
        baseline = prepare_initial_windows_game_login(version, **kwargs)
        configured = prepare_initial_windows_game_login(version, **kwargs, language_code=1)
        self.assertEqual(configured, replace(baseline, raw_bytes=(3,3,1,0,0)))
        for invalid in (-1,256,True,'1'):
            with self.assertRaises(ValueError):
                prepare_initial_windows_game_login(version, **kwargs, language_code=invalid)

    def test_explicit_metadata_is_preserved_without_identity_replacement(self):
        version, kwargs = self.inputs()
        baseline=prepare_initial_windows_game_login(version,**kwargs)
        metadata='{"I_PID":"current-fixture"}'
        actual=prepare_initial_windows_game_login(version,**kwargs,nid_metadata=metadata)
        strings=list(baseline.strings);strings[11]=metadata
        self.assertEqual(actual,replace(baseline,strings=tuple(strings)))
        self.assertNotIn('current-fixture',repr(actual))


if __name__ == '__main__': unittest.main()
