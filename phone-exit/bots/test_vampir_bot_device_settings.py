from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, MagicMock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core.bot_device_settings import validate, new_identity, connection_presets, apply_binding, apply_system, metadata_values
from vampir_core.account_store import AccountStore
from vampir_core.device_registry import DeviceBinding
from test_vampir_account_console import FixtureVault


def load(file):
    spec = importlib.util.spec_from_file_location(file.replace('-', '_'), HERE / 'vampir-headless' / (file + '.py'))
    tool = importlib.util.module_from_spec(spec); sys.modules[spec.name] = tool; spec.loader.exec_module(tool)
    return tool


class BotDeviceSettingsTests(unittest.TestCase):
    def test_presets_are_combined_and_default_does_not_change_device_or_route(self):
        presets = connection_presets()
        self.assertEqual(presets[0], dict(id='default', name='По умолчанию · текущий ПК / прямой выход',
            device_profile='current-pc', device_settings={}, socks_port=None))
        for preset in presets:
            settings = AccountStore.assignment(dict(device_profile=preset['device_profile'],
                device_settings=preset['device_settings'], socks_port=preset['socks_port']))
            validate(settings['device_settings'])
        self.assertEqual({p['socks_port'] for p in presets}, {None, 1080, 1081})

    def test_distinct_persistent_identities_can_share_network_and_survive_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.sqlite3'; store = AccountStore(path, FixtureVault())
            first, second = new_identity(), new_identity()
            self.assertEqual(len(set(first.values()) | set(second.values())), 6)
            for i, identity in enumerate((first, second)):
                store.save(str(i) + '@unit.invalid', password='fixture', assignment=dict(
                    device_profile='custom', device_settings=dict(identity=identity), socks_port=1080))
            restored = AccountStore(path, FixtureVault()).accounts()
            self.assertEqual([a['device_settings']['identity'] for a in restored], [first, second])
            identifier = restored[0]['id']; store.registration_status(identifier, 'sdk_created')
            store.save(restored[0]['email'], assignment={k: v for k, v in restored[0].items()
                if k in AccountStore.assignment({})})
            self.assertEqual(store.accounts()[0]['registration_status'], 'sdk_created')
            store.save(restored[0]['email'], assignment=dict(device_profile='custom',
                device_settings=dict(identity=new_identity()), socks_port=1080))
            self.assertEqual(store.accounts()[0]['registration_status'], 'nid_verified')

    def test_saved_template_survives_restart_without_copying_private_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.sqlite3'; store = AccountStore(path, FixtureVault())
            preset = connection_presets()[2]
            settings = dict(device_profile='custom', device_settings=dict(preset['device_settings'], identity=new_identity()), socks_port=1080)
            identifier = store.save_connection_preset('Рабочий пресет', settings)
            saved = AccountStore(path, FixtureVault()).connection_presets()
            self.assertEqual(saved[0]['id'], identifier)
            self.assertEqual(saved[0]['socks_port'], 1080)
            self.assertNotIn('identity', saved[0]['device_settings'])
            self.assertIn('identity', settings['device_settings'])
            with self.assertRaises(ValueError): store.save_connection_preset('Рабочий пресет', settings)

    def test_binding_replacement_preserves_original_and_confirmation_gate(self):
        binding = DeviceBinding('fixture@unit.invalid', 'fixture', 'real', False, 'originalsdk', 'originalnm',
            'fixture-source', 'confirmed', 'fixture-confirmation', 'originalnid', 'fixture-nid')
        identity = new_identity(); alternate = apply_binding(binding, dict(identity=identity))
        self.assertEqual((alternate.device_key, alternate.nm_device_key, alternate.nid_device_key),
            tuple(identity[k] for k in ('device_key', 'nm_device_key', 'nid_device_key')))
        self.assertEqual(alternate.confirmation, 'unknown'); self.assertEqual(binding.confirmation, 'confirmed')
        with self.assertRaises(PermissionError): apply_binding(replace(binding, confirmation='required'), dict(identity=identity))

    def test_system_values_and_metadata_are_consistent_but_cannot_override_network_or_tokens(self):
        settings = connection_presets()[1]['device_settings']
        cpu, windows = apply_system(None, None, settings)
        metadata = metadata_values(settings)
        self.assertEqual(metadata['I_NMCPU'], cpu.text())
        self.assertEqual(metadata['I_DeviceOSVersion'], windows.suffix())
        for field in ('I_ConnectIP', 'I_CountryCD', 'I_JoinedCountryCode', 'I_PID', 'I_OS', 'I_NMDeviceKey'):
            with self.assertRaises(ValueError): validate(dict(metadata={field: 'fixture'}))
        for invalid in ({'identity': {'device_key': 'onlyone'}}, {'metadata': {'I_DeviceModel': 'bad"value'}},
                        {'cpu': {'vendor': 'x'}}, {'windows': {'major': 10}}, {'unexpected': 'fixture'}):
            with self.assertRaises(ValueError): validate(invalid)
        for invalid in (0, -1, True, '1080', 65536):
            with self.assertRaises(ValueError): AccountStore.assignment({'socks_port': invalid})

    def test_worker_propagates_same_device_and_route_to_config_and_lobby(self):
        tool = load('account-worker')
        device = dict(identity=new_identity(), **connection_presets()[1]['device_settings'])
        store, registry, cdn, lobby = MagicMock(), MagicMock(), MagicMock(), MagicMock()
        store.credential.return_value = ('fixture@unit.invalid', 'fixture-password', dict(
            enabled=True, region='JP', server_id=None, auth_flow='launcher', device_settings=device, socks_port=1081))
        cdn.profile.return_value = dict(url='https://fixture.invalid'); cdn.fetch.return_value = (b'fixture', {})
        cdn.save.return_value = (Path('fixture-manifest'), None)
        lobby.run.return_value.server_list_response.result_code = 0
        def modules(name, path):
            return cdn if path.name == 'fetch-public-cdn-config.py' else lobby
        with patch.object(tool, 'AccountStore', return_value=store), patch.object(tool, 'DeviceRegistry', return_value=registry), \
             patch.object(tool, 'load', side_effect=modules), patch.object(tool, 'build_account_catalog', return_value={}), patch.object(tool, 'emit'):
            tool.run(SimpleNamespace(store=Path('fixture.sqlite3'), account='fixture', operation='servers', manual_sign_in=False))
        self.assertEqual(cdn.fetch.call_args.kwargs['route'].port, 1081)
        self.assertEqual(lobby.run.call_args.kwargs['socks_port'], 1081)
        self.assertEqual(lobby.run.call_args.kwargs['device_settings'], device)


if __name__ == '__main__': unittest.main()
