"""Current raw metadata survives binding and cannot enter the legacy binder."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.lobby_current import CurrentWindowsLobbyLoginBinding, make_current_windows_lobby_login
from vampir_core.lobby_packets import (CURRENT_LOBBY_VERSION_SOURCE as SOURCE,
    CurrentLobbyVersionResultBody, LobbyVersionResultBody, decode_current_lobby_version_result,
    make_windows_lobby_login)
from vampir_core.login_context import bind_lobby_sdk_fields
from vampir_core.sdk_sign_in_response import SdkSignInData


class CurrentLobbyBindingTests(unittest.TestCase):
    def result(self, **changes):
        return replace(CurrentLobbyVersionResultBody(0, False, (0xffffffffffffffff, 0x8000000000000000),
            65535, 'Europe/Київ', 0xffffffff, 0x80000000), **changes)

    def bind(self, result=None, **changes):
        values = dict(version_result=self.result() if result is None else result,
            kind=2, selected_server_id=0xffffffff, metadata='caller-metadata', source_sha256=SOURCE)
        values.update(changes)
        return make_current_windows_lobby_login(**values)

    def test_current_result_is_retained_without_metadata_application(self):
        result = self.result()
        binding = self.bind(result)
        self.assertIs(binding.version_result, result)
        self.assertEqual((binding.version_result.raw_40, binding.version_result.raw_50, binding.version_result.raw_54),
                         ('Europe/Київ', 0xffffffff, 0x80000000))
        self.assertEqual(binding.login.integers, (2, 2, 0xffffffff, 0))
        self.assertEqual(binding.login.strings, ('',) * 5 + ('caller-metadata',))
        self.assertEqual(binding.login.raw_80, 7)
        self.assertIs(binding.metadata_applied, False)
        with self.assertRaises(FrozenInstanceError):
            binding.version_result = self.result(raw_40='')
        with self.assertRaises((ValueError, TypeError)):
            replace(binding, metadata_applied=True)

    def test_all_raw_values_survive_wire_decoder_to_binding(self):
        for text in ('', 'GMT+03:00', 'Ж♥猫'):
            data = text.encode('utf-8')
            body = struct.pack('<IBQQHH', 0, 0, 0xffffffffffffffff, 0x8000000000000000, 65535, len(data)) + data + struct.pack('<II', 0xffffffff, 0x80000000)
            decoded = decode_current_lobby_version_result(body, source_sha256=SOURCE)
            binding = self.bind(decoded)
            self.assertEqual(binding.version_result, replace(self.result(), raw_40=text))

    def test_rejected_flagged_or_other_source_cannot_construct_current_login(self):
        with self.assertRaises(ValueError): self.bind(source_sha256='0' * 64)
        with self.assertRaises(ValueError): self.bind(self.result(result_code=58))
        with self.assertRaises(NotImplementedError): self.bind(self.result(flag_14=True))
        with self.assertRaises(TypeError): self.bind(LobbyVersionResultBody(0, False, (1, 2), 3))
        with self.assertRaises(TypeError):
            make_windows_lobby_login(version_result=self.result(), kind=2, selected_server_id=1, metadata='')

    def test_numeric_limits_and_immutable_sdk_replacement(self):
        binding = self.bind(kind=0, selected_server_id=0)
        self.assertEqual(binding.login.integers, (2, 0, 0, 0))
        for name, value in (('kind', -1), ('kind', True), ('selected_server_id', 1 << 32)):
            with self.assertRaises(ValueError): self.bind(**{name: value})
        # Current wrapper remains the owner's object while a normal immutable
        # SDK binding fills only the five already proven outgoing identity slots.
        sdk = SdkSignInData('bounded-token', 'bounded-player', '', '', 0)
        login = bind_lobby_sdk_fields(binding.login, sdk_data=sdk, netmarble_id='bounded-nid',
            nm_device_key='bounded-device', joined_country_code='EU')
        updated = replace(binding, login=login)
        self.assertIs(updated.version_result, binding.version_result)
        self.assertFalse(updated.metadata_applied)
        self.assertEqual(updated.login.strings[5], 'caller-metadata')
        self.assertEqual(updated.login.integers, binding.login.integers)


if __name__ == '__main__': unittest.main()
