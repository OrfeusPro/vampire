import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import Mock
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'vampir-shared'))
from vampir_core.socks_route import socks_game_address_context
from vampir_core.version_cpu import VersionCpuInput
from vampir_core.windows_version import WindowsVersion

HERE = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


class ConnectedLocalAddressTests(unittest.TestCase):
    def test_native_getter_callback_and_version_reproduce(self):
        tool = load('local_address_native_test', HERE / 'resource-tools/vampir/replay-connected-local-address.py')
        saved = json.loads((tool.native.ROOT / 'code-clues/connected-local-address-replay.json').read_text('utf-8'))
        self.assertEqual(tool.build(), saved)
        self.assertEqual(len(saved['cases']), 5)
        for case in saved['cases']:
            value = case['packet']['strings']['0x58']
            f = case['fixture']
            self.assertEqual(value, f['endpoint_ip'] if f['sockname_return'] == 0 else '')
        self.assertEqual(saved['cases'][-1]['packet']['strings']['0x58'], '')

    def test_socks_metadata_never_reads_proxy_hop_as_game_address(self):
        for endpoint, expected in [(('0.0.0.0', 0), None), (('127.0.0.1', 1234), None),
                (('169.254.1.2', 1234), None), (('224.0.0.1', 1234), None),
                (('203.0.113.8', 0), None), (('10.20.30.40', 23456), '10.20.30.40'),
                (('203.0.113.8', 23456), '203.0.113.8')]:
            connection = Mock()
            connection.get_proxy_sockname.return_value = endpoint
            connection.getsockname.side_effect = AssertionError('Proxy hop is not game context')
            result = socks_game_address_context(connection)
            self.assertEqual(result.address, expected)
            self.assertEqual(result.source, 'socks_bound_unavailable' if expected is None else 'socks_bound_ipv4')
            if expected: self.assertNotIn(expected, repr(result))

    def test_invalid_metadata_cannot_supply_arbitrary_text_or_dns(self):
        for endpoint in (None, ('private-text', 1), ('::1', 1), ('1.2.3.4', -1), ('1.2.3.4', True), ('1.2.3.4', 65536)):
            connection = Mock()
            connection.get_proxy_sockname.return_value = endpoint
            with self.assertRaises(ValueError) as error: socks_game_address_context(connection)
            self.assertNotIn('private-text', str(error.exception))
            connection.getsockname.assert_not_called()

    def test_unavailable_address_is_empty_in_version_without_changing_other_fields(self):
        tool = load('local_address_version_test', HERE / 'vampir-headless/probe-game-version.py')
        kwargs = dict(app_version='1.12.14', nm_device_key='nm-fixture',
            cpu=VersionCpuInput('GenuineIntel', 'Fixture CPU'), windows_version=WindowsVersion(10, 0, 26200, 1, 256))
        known = tool.prepare_version(local_address='10.20.30.40', **kwargs)
        missing = tool.prepare_version(local_address=None, **kwargs)
        self.assertEqual(missing.strings[4], '')
        self.assertEqual(missing.strings[:4] + missing.strings[5:], known.strings[:4] + known.strings[5:])
        self.assertEqual(missing.integers, known.integers)
