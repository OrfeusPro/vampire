import importlib.util
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.login_context import bind_nm_device_key, bind_sdk_login_fields, prepare_registered_login, bind_game_app_version
from vampir_core.device_registry import DeviceBinding
from vampir_core.login_packet import LoginPayload
from vampir_core.version_packet import VersionPayload
from vampir_core.sdk_sign_in_response import parse_sdk_sign_in_response


class LoginContextTests(unittest.TestCase):
    def templates(self):
        return VersionPayload(('',) * 10, (0, 207, 2)), LoginPayload(('',) * 15, (0, 42, 207, 2), (0,) * 5, 0)

    def test_nm_key_shared_by_two_proven_offsets_only(self):
        version, login = self.templates()
        actual_version, actual_login = bind_nm_device_key(version, login, nm_device_key='nm-fixture')
        self.assertEqual(actual_version.strings, ('', '', '', 'nm-fixture', '', '', '', '', '', ''))
        self.assertEqual(actual_login.strings[6], 'nm-fixture')
        self.assertEqual(sum(bool(s) for s in actual_login.strings), 1)
        self.assertEqual((actual_version.integers, actual_login.integers), (version.integers, login.integers))
        self.assertEqual(bind_nm_device_key(actual_version, actual_login, nm_device_key='nm-fixture'), (actual_version, actual_login))
        with self.assertRaises(ValueError): bind_nm_device_key(actual_version, actual_login, nm_device_key='other-device')
        self.assertEqual(version.strings[3], '')

    def test_sdk_token_and_separate_nid_never_use_player_id(self):
        _, login = self.templates()
        response = b'{"errorCode":0,"resultData":{"accessToken":"sdk-token-fixture","playerInfo":{"player":{"playerId":"different-player-fixture"}}}}'
        data = parse_sdk_sign_in_response(status=200, body=response)
        result = bind_sdk_login_fields(login, sdk_data=data, netmarble_id='nid-fixture')
        self.assertEqual((result.strings[2], result.strings[8]), ('nid-fixture', 'sdk-token-fixture'))
        self.assertNotIn('different-player-fixture', result.strings)
        self.assertNotIn('sdk-token-fixture', repr(result))
        with self.assertRaises(ValueError): bind_sdk_login_fields(result, sdk_data=data, netmarble_id='other-account')

    def test_one_explicit_app_version_binds_only_proven_fields(self):
        version, login = self.templates()
        a, b = bind_game_app_version(version, login, app_version='1.12.14')
        self.assertEqual(a.strings[0], '1.12.14')
        self.assertEqual(b.strings[3], '1.12.14')
        self.assertEqual(sum(bool(value) for value in a.strings), 1)
        self.assertEqual(sum(bool(value) for value in b.strings), 1)
        self.assertEqual((a.integers, b.integers, b.raw_bytes, b.raw_128),
            (version.integers, login.integers, login.raw_bytes, login.raw_128))
        self.assertEqual(version.strings[0], '')
        with self.assertRaises(ValueError): bind_game_app_version(a, b, app_version='0.1.1')
        with self.assertRaises(ValueError): bind_game_app_version(version, login, app_version='')

    def test_empty_and_invalid_context_is_rejected(self):
        version, login = self.templates()
        for value in ('', None, 'bad\0key'):
            with self.assertRaises(ValueError): bind_nm_device_key(version, login, nm_device_key=value)

    def test_registered_profile_confirmation_and_identity_gates(self):
        version, login = self.templates()
        data = parse_sdk_sign_in_response(status=200, body=b'{"errorCode":0,"resultData":{"accessToken":"token-fixture","playerInfo":{"player":{"playerId":"player-fixture"}}}}')
        binding = DeviceBinding('test@example.invalid', 'profile-fixture', 'real', True,
            'sdk-fixture', 'nm-fixture', 'observed-fixture', 'unknown', '', 'nid-fixture', 'observed-nid-fixture')
        for state in ('unknown', 'confirmed'):
            a, b = prepare_registered_login(version, login, binding=replace(binding, confirmation=state), sdk_data=data, netmarble_id='nid-account-fixture')
            self.assertEqual((a.strings[3], b.strings[6], b.strings[8]), ('nm-fixture', 'nm-fixture', 'token-fixture'))
        with self.assertRaises(PermissionError):
            prepare_registered_login(version, login, binding=replace(binding, confirmation='required'), sdk_data=data, netmarble_id='nid-account-fixture')
        for change in (dict(kind='planned'), dict(device_key=''), dict(nid_device_key=''), dict(nid_identity_source='')):
            with self.assertRaises(ValueError):
                prepare_registered_login(version, login, binding=replace(binding, **change), sdk_data=data, netmarble_id='nid-account-fixture')


class NativeVersionDeviceInputTests(unittest.TestCase):
    def test_actual_wrapper_and_nm_getter_reproduce(self):
        path = HERE / 'resource-tools/vampir/replay-version-device-input.py'
        spec = importlib.util.spec_from_file_location('version_device_input_test', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        report = json.loads((tool.native.ROOT / 'code-clues/version-device-input-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 4)
        self.assertFalse(report['network_ready'])
        for case in report['cases']:
            self.assertEqual(case['value'], case['repeated'])
            version, login = LoginContextTests().templates()
            version, login = bind_nm_device_key(version, login, nm_device_key=case['value'])
            self.assertEqual(version.strings[3], login.strings[6])


if __name__ == '__main__': unittest.main()
