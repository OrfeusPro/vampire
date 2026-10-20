import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.lobby_packets import LobbyLoginPayload
from vampir_core.login_packet import LoginPayload
from vampir_core.login_context import bind_lobby_sdk_fields
from vampir_core.sdk_sign_in_response import SdkSignInData


class LobbyLoginWriterTests(unittest.TestCase):
    def test_sdk_country_and_identity_binding_preserves_unknown_fields(self):
        value = LobbyLoginPayload(('',) * 5 + ('explicit-metadata-fixture',), (2, 0, 17, 0), 0)
        data = SdkSignInData('sdk-token-fixture', 'player-fixture', 'fixture-region', 'HK', None)
        result = bind_lobby_sdk_fields(value, sdk_data=data, netmarble_id='nid-fixture',
            nm_device_key='nm-fixture', joined_country_code='HK')
        self.assertEqual(result.strings, ('player-fixture', 'sdk-token-fixture', 'nm-fixture', 'HK',
            'nid-fixture', 'explicit-metadata-fixture'))
        self.assertEqual(result.integers, value.integers)
        self.assertEqual(result.raw_80, value.raw_80)
        self.assertEqual(value.strings[:5], ('',) * 5)
        with self.assertRaises(ValueError):
            bind_lobby_sdk_fields(result, sdk_data=data, netmarble_id='other-nid', nm_device_key='nm-fixture', joined_country_code='HK')
        with self.assertRaises(ValueError):
            bind_lobby_sdk_fields(value, sdk_data=data, netmarble_id='nid-fixture', nm_device_key='nm-fixture', joined_country_code='')
        with self.assertRaises(TypeError):
            bind_lobby_sdk_fields(LoginPayload(('',) * 15, (0,) * 4, (0,) * 5, 0),
                sdk_data=data, netmarble_id='nid-fixture', nm_device_key='nm-fixture', joined_country_code='HK')

    def test_compiled_nid_keys_country_offset_and_sdk_player_source_reproduce(self):
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-nid-input-index.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location('test_lobby_nid_input_index',
            HERE / 'resource-tools/vampir/build-lobby-nid-input-index.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), report)
        keys = [r['key'] for r in report['collector_keys']]
        self.assertEqual(len(keys), 27)
        self.assertEqual(keys.count('I_World'), 2)
        self.assertTrue({'I_JoinedCountryCode', 'I_NMDeviceKey', 'I_NMNID', 'I_NMCPU', 'I_NMRAM', 'I_NMVGA'} <= set(keys))
        self.assertEqual(report['country_field']['object_offset'], 0x170)
        self.assertEqual(report['country_field']['key_literal']['text'], 'I_JoinedCountryCode')
        self.assertTrue(any('UNMServiceSettings::GetPlayerId' in r['text'] for r in report['literals']))

    def test_all_whole_native_writer_vectors_reproduce_and_match(self):
        report = json.loads(Path('F:/PhoneExit Resources/Vampir/code-clues/lobby-login-writer-replay.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location('test_lobby_login_writer_native',
            HERE / 'resource-tools/vampir/replay-lobby-login-writer.py')
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        self.assertEqual(tool.build(), report)
        self.assertEqual(len(report['cases']), 24)
        for case in report['cases']:
            value = LobbyLoginPayload(tuple(case['strings']), tuple(case['integers']), case['raw_80'])
            body = bytes.fromhex(case['payload_hex'])
            self.assertEqual(value.encode(max_payload_size=len(body)), body)
            self.assertEqual(case['returned'], 1)
            if any(case['strings']):
                with self.assertRaises(BufferError): value.encode(max_payload_size=len(body) - 1)

    def test_bounded_immutable_explicit_inputs_and_redaction(self):
        value = LobbyLoginPayload(('sensitive-fixture',) * 6, (2, 0, 0, 0), 0)
        self.assertNotIn('sensitive-fixture', repr(value))
        self.assertEqual(len(LobbyLoginPayload(('',) * 6, (0,) * 4, 0).encode(max_payload_size=29)), 29)
        for strings in ([''] * 6, ('',) * 5, ('\0',) * 6, ('\ud800',) * 6, ('é' * 32768,) * 6):
            with self.assertRaises(ValueError): LobbyLoginPayload(strings, (0,) * 4, 0)
        for integers in ((0,) * 3, (True, 0, 0, 0), (0, -1, 0, 0), (0, 0, 0, 0x100000000)):
            with self.assertRaises(ValueError): LobbyLoginPayload(('',) * 6, integers, 0)
        for flag in (True, -1, 256):
            with self.assertRaises(ValueError): LobbyLoginPayload(('',) * 6, (0,) * 4, flag)
        for budget in (True, 28, 0x1000000):
            with self.assertRaises(ValueError): value.encode(max_payload_size=budget)


if __name__ == '__main__': unittest.main()
